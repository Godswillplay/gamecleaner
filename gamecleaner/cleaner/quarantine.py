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
from typing import Dict, List, Optional, Union

MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004


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


def remove_readonly(path: Path):
    """Strips read-only, hidden, and system attributes so files can be deleted, moved, or restored."""
    p_str = str(to_win32_long_path(path))
    if os.name == "nt":
        try:
            # 0x80 = FILE_ATTRIBUTE_NORMAL (clears READONLY, HIDDEN, SYSTEM)
            ctypes.windll.kernel32.SetFileAttributesW(p_str, 0x80)
        except Exception:
            pass
    try:
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
    except Exception:
        pass



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
        """Saves the quarantine manifest atomically to prevent corruption."""
        tmp_manifest = self.manifest_file.with_name(f"{self.manifest_file.name}.tmp")
        try:
            with open(tmp_manifest, "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=2)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except Exception:
                    pass
            os.replace(tmp_manifest, self.manifest_file)
        except Exception:
            with open(self.manifest_file, "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=2)

    def quarantine_file(self, file_path: Path, reason: str, sha256: str) -> Optional[Path]:
        """Moves a suspicious file into the quarantine vault with long path and lock evasion."""
        import time

        file_path = Path(file_path).resolve()
        if not file_path.exists():
            return None

        self._ensure_dir()
        manifest = self._load_manifest()

        # If sha256 not provided, automatically compute hash
        if not sha256:
            try:
                import hashlib
                sha256 = hashlib.sha256(file_path.read_bytes()).hexdigest()
            except Exception:
                sha256 = ""

        # Compute relative path to target_dir
        try:
            rel_path = str(file_path.relative_to(self.target_dir))
        except ValueError:
            rel_path = file_path.name

        # Timestamped quarantine filename (microsecond resolution avoids collision)
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        quarantined_name = f"{file_path.name}_{timestamp_str}.quarantined"
        dest_path = self.quarantine_dir / quarantined_name

        remove_readonly(file_path)

        long_src = to_win32_long_path(file_path)
        long_dst = to_win32_long_path(dest_path)

        # Attempt 1: Standard atomic move
        try:
            shutil.move(str(long_src), str(long_dst))
        except (PermissionError, OSError):
            # Attempt 2: If locked by a running process, try to kill the locking process
            try:
                import psutil
                file_resolved = file_path.resolve()
                timeout_err = getattr(psutil, "TimeoutExpired", OSError)
                for proc in psutil.process_iter(["pid", "name", "exe"]):
                    try:
                        exe_path = proc.info.get("exe")
                        if exe_path and Path(exe_path).resolve() == file_resolved:
                            proc.kill()
                            proc.wait(timeout=2)
                            continue
                        try:
                            for of in proc.open_files():
                                if Path(of.path).resolve() == file_resolved:
                                    proc.kill()
                                    proc.wait(timeout=2)
                                    break
                        except (psutil.AccessDenied, psutil.NoSuchProcess, timeout_err):
                            pass
                    except (psutil.NoSuchProcess, psutil.AccessDenied, timeout_err, OSError):
                        continue
            except Exception:
                pass

            # Try moving again after killing process
            try:
                shutil.move(str(long_src), str(long_dst))
            except Exception:
                pass

        # Attempt 3: Rename-first evasion (works on NTFS even when binary is mapped in memory)
        if file_path.exists() and not dest_path.exists():
            try:
                temp_renamed = file_path.with_name(f"{file_path.name}.{int(time.time()*1000)}.gc_locked")
                remove_readonly(file_path)
                os.replace(long_src, to_win32_long_path(temp_renamed))
                remove_readonly(temp_renamed)
                shutil.move(str(to_win32_long_path(temp_renamed)), str(long_dst))
            except Exception:
                pass

        # Attempt 4: Copy to quarantine and neutralize source
        if file_path.exists() and not dest_path.exists():
            try:
                shutil.copy2(str(long_src), str(long_dst))
                remove_readonly(file_path)
                try:
                    file_path.unlink()
                except Exception:
                    # If file is locked and cannot be deleted, overwrite/zero out payload bytes
                    try:
                        with open(long_src, "wb") as f_zero:
                            f_zero.write(b"")
                    except Exception:
                        pass
                    # If still on disk, rename away from original executable name
                    try:
                        quar_locked = file_path.with_name(f"{file_path.name}.{int(time.time()*1000)}.gc_quar_locked")
                        os.replace(long_src, to_win32_long_path(quar_locked))
                    except Exception:
                        pass
            except Exception:
                pass

        # Attempt 5: If still locked on disk, schedule deletion upon Windows restart
        if file_path.exists() and os.name == "nt":
            try:
                ctypes.windll.kernel32.MoveFileExW(str(long_src), None, MOVEFILE_DELAY_UNTIL_REBOOT)
            except Exception:
                pass

        # Strip execute permissions on quarantined file to neutralize it
        if dest_path.exists():
            try:
                os.chmod(dest_path, stat.S_IREAD)
            except Exception:
                pass

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

    def restore_file(self, quarantined_name: Union[str, Path]) -> bool:
        """Restores a quarantined file back to its original path, validating traversal safety."""
        q_name = Path(str(quarantined_name)).name
        manifest = self._load_manifest()
        if q_name not in manifest:
            return False

        record = manifest[q_name]
        src_file = self.quarantine_dir / q_name

        # Prevent directory traversal in stored original path
        orig_rel = record.get("original_rel_path", q_name)
        cleaned_rel = Path(orig_rel).as_posix().lstrip("/\\")
        dest_file = (self.target_dir / cleaned_rel).resolve()
        try:
            dest_file.relative_to(self.target_dir)
        except ValueError:
            dest_file = self.target_dir / Path(orig_rel).name

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

        long_src = to_win32_long_path(src_file)
        long_dst = to_win32_long_path(dest_file)
        shutil.move(str(long_src), str(long_dst))
        remove_readonly(dest_file)

        del manifest[q_name]
        self._save_manifest(manifest)
        return True

    def list_quarantined(self) -> List[QuarantineRecord]:
        """Returns list of currently quarantined files safely without crashing on corrupted manifests."""
        manifest = self._load_manifest()
        records = []
        allowed = {"original_rel_path", "quarantined_filename", "sha256", "reason", "timestamp"}
        for item in manifest.values():
            if isinstance(item, dict):
                filtered = {k: v for k, v in item.items() if k in allowed}
                for req in allowed:
                    filtered.setdefault(req, "")
                records.append(QuarantineRecord(**filtered))
        return records
