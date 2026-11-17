"""
Quarantine manager: Safely isolates and neutralizes malicious binaries.
"""
import ctypes
from dataclasses import asdict, dataclass
from datetime import datetime
import json
import os
from pathlib import Path
import shutil
import stat
from typing import Dict, List, Optional

MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004


def remove_readonly(path: Path):
    """Strips read-only and system attributes so files can be deleted or moved."""
    try:
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
    except Exception:
        pass


def to_win32_long_path(path: Path) -> Path:
    """Prepends \\?\\ to absolute paths on Windows to bypass MAX_PATH 260 character limits."""
    if os.name != "nt":
        return path
    p_str = str(path.resolve())
    if not p_str.startswith("\\\\?\\") and not p_str.startswith("\\\\.\\"):
        if p_str.startswith("\\\\"):
            return Path("\\\\?\\UNC\\" + p_str[2:])
        return Path("\\\\?\\" + p_str)
    return path



@dataclass
class QuarantineRecord:
    original_rel_path: str
    quarantined_filename: str
    sha256: str
    reason: str
    timestamp: str


class QuarantineManager:
    """Manages moving suspected malicious binaries to an isolated vault."""

    def __init__(self, target_dir: Path):
        self.target_dir = Path(target_dir).resolve()
        self.quarantine_dir = self.target_dir / ".gamecleaner_quarantine"
        self.manifest_file = self.quarantine_dir / "quarantine_manifest.json"

    def _ensure_dir(self):
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        # Create an explanatory README inside the quarantine directory
        readme_file = self.quarantine_dir / "README_QUARANTINE.txt"
        if not readme_file.exists():
            readme_file.write_text(
                "This folder contains isolated files moved by GameCleaner.\n"
                "Files have been renamed with .quarantined suffix to prevent execution.\n"
                "DO NOT rename or execute files in this folder unless you have verified them.\n"
            )

    def _load_manifest(self) -> Dict[str, dict]:
        if not self.manifest_file.exists():
            return {}
        try:
            with open(self.manifest_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save_manifest(self, manifest: Dict[str, dict]):
        with open(self.manifest_file, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

    def quarantine_file(self, file_path: Path, reason: str, sha256: str) -> Optional[Path]:
        """Moves a suspicious file into the quarantine vault."""
        file_path = Path(file_path).resolve()
        if not file_path.exists():
            return None

        self._ensure_dir()
        manifest = self._load_manifest()

        # Compute relative path to target_dir
        try:
            rel_path = str(file_path.relative_to(self.target_dir))
        except ValueError:
            rel_path = file_path.name

        # Timestamped quarantine filename
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        quarantined_name = f"{file_path.name}_{timestamp_str}.quarantined"
        dest_path = self.quarantine_dir / quarantined_name

        remove_readonly(file_path)

        # Attempt 1: Standard atomic move
        try:
            shutil.move(str(file_path), str(dest_path))
        except (PermissionError, OSError):
            # Attempt 2: If locked by a running process, try to kill the locking process
            try:
                import psutil
                for proc in psutil.process_iter(["pid", "name", "exe"]):
                    try:
                        exe_path = proc.info.get("exe")
                        if exe_path and Path(exe_path).resolve() == file_path:
                            proc.kill()
                            proc.wait(timeout=2)
                            break
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            except Exception:
                pass

            # Try moving again after killing process
            try:
                shutil.move(str(file_path), str(dest_path))
            except Exception:
                pass

        # Attempt 3: Rename-first evasion (works on NTFS even when binary is mapped in memory)
        if file_path.exists() and not dest_path.exists():
            try:
                temp_renamed = file_path.with_name(f"{file_path.name}.gc_locked")
                remove_readonly(file_path)
                os.replace(file_path, temp_renamed)
                shutil.move(str(temp_renamed), str(dest_path))
            except Exception:
                pass

        # Attempt 4: Copy to quarantine and unlink source
        if file_path.exists() and not dest_path.exists():
            try:
                shutil.copy2(str(file_path), str(dest_path))
                remove_readonly(file_path)
                file_path.unlink()
            except Exception:
                pass

        # Attempt 5: If still locked on disk, schedule deletion upon Windows restart
        if file_path.exists() and os.name == "nt":
            try:
                ctypes.windll.kernel32.MoveFileExW(str(file_path), None, MOVEFILE_DELAY_UNTIL_REBOOT)
            except Exception:
                pass

        # Only update manifest if destination actually exists in quarantine
        if dest_path.exists():
            manifest[quarantined_name] = asdict(QuarantineRecord(
                original_rel_path=rel_path,
                quarantined_filename=quarantined_name,
                sha256=sha256,
                reason=reason,
                timestamp=datetime.now().isoformat(),
            ))
            self._save_manifest(manifest)
            return dest_path

        return None

    def restore_file(self, quarantined_name: str) -> bool:
        """Restores a quarantined file back to its original path."""
        manifest = self._load_manifest()
        if quarantined_name not in manifest:
            return False

        record = manifest[quarantined_name]
        src_file = self.quarantine_dir / quarantined_name
        dest_file = self.target_dir / record["original_rel_path"]

        if not src_file.exists():
            return False

        dest_file.parent.mkdir(parents=True, exist_ok=True)
        remove_readonly(src_file)
        if dest_file.exists():
            remove_readonly(dest_file)
            try:
                dest_file.unlink()
            except Exception:
                pass
        shutil.move(str(src_file), str(dest_file))

        del manifest[quarantined_name]
        self._save_manifest(manifest)
        return True

    def list_quarantined(self) -> List[QuarantineRecord]:
        """Returns list of currently quarantined files."""
        manifest = self._load_manifest()
        records = []
        for item in manifest.values():
            records.append(QuarantineRecord(**item))
        return records
