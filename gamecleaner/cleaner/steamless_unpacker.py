"""
Steamless CLI Unpacker for SteamStub DRM (.bind section removal).
Safely orchestrates atom0s's Steamless CLI to unpack encrypted entrypoints,
backs up the original .bind-wrapped binary into .gamecleaner_backup/,
swaps the unpacked executable into place, and validates PE section integrity.
"""
from dataclasses import dataclass
from datetime import datetime
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time
from typing import Dict, List, Optional, Union

try:
    import pefile
except ImportError:
    pefile = None

from gamecleaner.analyzer.steam_stub import SteamStubDetector


@dataclass
class SteamlessResult:
    """Represents the outcome of a Steamless CLI unpack operation."""

    original_path: str
    unpacked_path: Optional[str] = None
    success: bool = False
    error_message: Optional[str] = None
    backup_created: Optional[str] = None


class SteamlessUnpacker:
    """Orchestrates Steamless CLI to automatically unpack SteamStub DRM and swap executables."""

    CLI_BINARY_NAMES = (
        "Steamless.CLI.exe",
        "Steamless.CLI",
        "steamless.exe",
        "steamless",
    )

    def __init__(
        self,
        steamless_path: Optional[Union[str, Path]] = None,
        tools_dir: Optional[Union[str, Path]] = None,
        timeout_seconds: int = 120,
    ) -> None:
        """Initializes the Steamless unpacker.

        Args:
            steamless_path: Explicit path to Steamless.CLI.exe (optional).
            tools_dir: Custom tools directory to search for Steamless (optional).
            timeout_seconds: Maximum seconds to wait for Steamless CLI execution.
        """
        self.custom_steamless_path = Path(steamless_path).resolve() if steamless_path else None
        self.custom_tools_dir = Path(tools_dir).resolve() if tools_dir else None
        self.timeout_seconds = timeout_seconds

    def _candidate_paths(self) -> List[Path]:
        """Returns candidate paths where Steamless.CLI.exe might reside."""
        candidates: List[Path] = []

        # 1. Custom tools dir if supplied
        if self.custom_tools_dir:
            for name in self.CLI_BINARY_NAMES:
                candidates.append(self.custom_tools_dir / name)
                candidates.append(self.custom_tools_dir / "steamless" / name)

        # 2. Local project tools/ directory (relative to cwd and relative to package root)
        cwd = Path.cwd()
        for name in self.CLI_BINARY_NAMES:
            candidates.append(cwd / "tools" / "steamless" / name)
            candidates.append(cwd / "tools" / name)

        # Package root resolution (e.g. repo root)
        try:
            repo_root = Path(__file__).resolve().parent.parent.parent
            for name in self.CLI_BINARY_NAMES:
                candidates.append(repo_root / "tools" / "steamless" / name)
                candidates.append(repo_root / "tools" / name)
        except Exception:
            pass

        # 3. User home directory ~/.gamecleaner/tools/
        home_cleaner = Path.home() / ".gamecleaner"
        for name in self.CLI_BINARY_NAMES:
            candidates.append(home_cleaner / "tools" / "steamless" / name)
            candidates.append(home_cleaner / "tools" / name)
            candidates.append(home_cleaner / "bin" / name)

        return candidates

    def get_steamless_path(self) -> Optional[Path]:
        """Resolves the absolute path to Steamless.CLI.exe across candidate directories and PATH."""
        if self.custom_steamless_path and self.custom_steamless_path.is_file():
            return self.custom_steamless_path

        # Check candidate locations on filesystem
        for candidate in self._candidate_paths():
            if candidate.is_file():
                return candidate.resolve()

        # Check system PATH
        for binary_name in self.CLI_BINARY_NAMES:
            which_path = shutil.which(binary_name)
            if which_path:
                resolved = Path(which_path).resolve()
                if resolved.is_file():
                    return resolved

        return None

    def is_available(self) -> bool:
        """Checks if Steamless CLI executable is present and accessible."""
        return self.get_steamless_path() is not None

    def has_bind_section(self, exe_path: Union[str, Path]) -> bool:
        """Inspects PE section table to verify whether any .bind or SteamStub sections exist.

        Args:
            exe_path: Path to executable to inspect.

        Returns:
            True if .bind or SteamStub sections/signatures are detected, False otherwise.
        """
        path = Path(exe_path).resolve()
        if not path.is_file():
            return False

        # 1. Check with pefile if available and file has valid PE structure
        if pefile is not None:
            try:
                pe = pefile.PE(str(path), fast_load=True)
                found_bind = False
                for section in pe.sections:
                    sec_name = (
                        section.Name.decode("utf-8", errors="ignore")
                        .rstrip("\x00")
                        .strip()
                        .lower()
                    )
                    if sec_name in (".bind", ".stub", ".steam"):
                        found_bind = True
                        break
                pe.close()
                return found_bind
            except Exception:
                # If PE parsing fails (e.g. mock test binary or non-PE header), continue to fallback
                pass

        # 2. Fallback check using SteamStubDetector
        try:
            detector = SteamStubDetector(path)
            res = detector.scan()
            if res.is_wrapped:
                return True
        except Exception:
            pass

        # 3. Raw byte check fallback
        try:
            content = path.read_bytes()
            return b".bind" in content or b"SteamDrmPfn" in content
        except Exception:
            return False

    def _find_unpacked_binary(self, exe_path: Path) -> Optional[Path]:
        """Identifies the unpacked executable produced by Steamless."""
        parent = exe_path.parent
        stem = exe_path.stem
        name = exe_path.name

        # Standard naming patterns generated by Steamless CLI
        candidates = [
            parent / f"{name}.unpacked.exe",
            parent / f"{stem}.unpacked.exe",
            parent / f"{stem}.unpacked",
            parent / f"{name}.unpacked",
        ]
        for cand in candidates:
            if cand.is_file():
                return cand.resolve()

        # Dynamic search for any newly generated *.unpacked* file in the same directory
        for cand in parent.glob(f"*{stem}*unpacked*"):
            if cand.is_file() and cand.suffix.lower() in (".exe", ""):
                return cand.resolve()

        return None

    def _backup_binary(self, exe_path: Path) -> Path:
        """Safely backs up original binary to .gamecleaner_backup/ with timestamp and manifest entry."""
        backup_dir = exe_path.parent / ".gamecleaner_backup"
        backup_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = backup_dir / f"{exe_path.name}_{timestamp}.bak"
        shutil.copy2(str(exe_path), str(backup_file))

        # Update backup manifest
        manifest_file = backup_dir / "backup_manifest.json"
        manifest: Dict[str, dict] = {}
        if manifest_file.exists():
            try:
                manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
            except Exception:
                manifest = {}

        manifest[backup_file.name] = {
            "original_path": str(exe_path),
            "relative_path": exe_path.name,
            "backup_file": backup_file.name,
            "timestamp": datetime.now().isoformat(),
            "type": "steamless_steamstub_backup",
        }

        try:
            manifest_file.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        except Exception:
            pass

        return backup_file

    def _swap_binary(self, unpacked_path: Path, target_path: Path) -> None:
        """Safely swaps unpacked binary into target path with NTFS locked file evasion."""
        # Strip read-only flag if target exists
        if target_path.exists():
            try:
                os.chmod(target_path, stat.S_IWRITE | stat.S_IREAD)
            except Exception:
                pass

        try:
            # Atomic replace
            os.replace(str(unpacked_path), str(target_path))
        except (PermissionError, OSError):
            # Locked file evasion: rename locked executable first
            temp_old = target_path.with_name(
                f"{target_path.name}.{int(time.time() * 1000)}.gc_old"
            )
            try:
                os.replace(str(target_path), str(temp_old))
            except Exception:
                shutil.move(str(target_path), str(temp_old))

            try:
                os.replace(str(unpacked_path), str(target_path))
            except Exception:
                shutil.move(str(unpacked_path), str(target_path))

    def unpack_binary(self, exe_path: Union[str, Path], backup: bool = True) -> SteamlessResult:
        """Invokes Steamless CLI against exe_path, backs up original, swaps unpacked binary into place,

        and verifies removal of the .bind section.

        Args:
            exe_path: Path to target Windows executable.
            backup: Whether to store backup of original executable in .gamecleaner_backup/.

        Returns:
            SteamlessResult with status, paths, and details.
        """
        target = Path(exe_path).resolve()

        if not target.is_file():
            return SteamlessResult(
                original_path=str(target),
                unpacked_path=None,
                success=False,
                error_message=f"Target executable does not exist or is not a file: {target}",
                backup_created=None,
            )

        steamless_cli = self.get_steamless_path()
        if not steamless_cli:
            return SteamlessResult(
                original_path=str(target),
                unpacked_path=None,
                success=False,
                error_message=(
                    "Steamless.CLI.exe not found. Place it in tools/steamless/, "
                    "~/.gamecleaner/tools/, or add to system PATH."
                ),
                backup_created=None,
            )

        # 1. Invoke Steamless CLI
        try:
            proc = subprocess.run(
                [str(steamless_cli), str(target)],
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return SteamlessResult(
                original_path=str(target),
                unpacked_path=None,
                success=False,
                error_message=f"Steamless CLI timed out after {self.timeout_seconds} seconds.",
                backup_created=None,
            )
        except Exception as e:
            return SteamlessResult(
                original_path=str(target),
                unpacked_path=None,
                success=False,
                error_message=f"Failed to execute Steamless CLI: {e}",
                backup_created=None,
            )

        # 2. Detect resulting .unpacked.exe file
        unpacked_file = self._find_unpacked_binary(target)
        if not unpacked_file or not unpacked_file.is_file():
            output_snippet = (proc.stderr or proc.stdout or "").strip()
            if len(output_snippet) > 200:
                output_snippet = output_snippet[:200] + "..."
            return SteamlessResult(
                original_path=str(target),
                unpacked_path=None,
                success=False,
                error_message=(
                    f"Steamless CLI completed without generating an unpacked file. "
                    f"CLI output: {output_snippet or 'None'}"
                ),
                backup_created=None,
            )

        # 3. Back up original .bind-wrapped binary
        backup_created: Optional[str] = None
        if backup:
            try:
                bak_path = self._backup_binary(target)
                backup_created = str(bak_path)
            except Exception as e:
                # If backup fails, do not proceed with overwriting the original file
                return SteamlessResult(
                    original_path=str(target),
                    unpacked_path=str(unpacked_file),
                    success=False,
                    error_message=f"Failed to create safe backup in .gamecleaner_backup: {e}",
                    backup_created=None,
                )

        # 4. Swap unpacked binary into place
        try:
            self._swap_binary(unpacked_file, target)
        except Exception as e:
            return SteamlessResult(
                original_path=str(target),
                unpacked_path=str(unpacked_file),
                success=False,
                error_message=f"Failed to swap unpacked binary into place: {e}",
                backup_created=backup_created,
            )

        # 5. Validate that .bind section is gone
        if self.has_bind_section(target):
            return SteamlessResult(
                original_path=str(target),
                unpacked_path=str(target),
                success=False,
                error_message="Integrity check failed: .bind section is still detected in unpacked binary.",
                backup_created=backup_created,
            )

        return SteamlessResult(
            original_path=str(target),
            unpacked_path=str(target),
            success=True,
            error_message=None,
            backup_created=backup_created,
        )
