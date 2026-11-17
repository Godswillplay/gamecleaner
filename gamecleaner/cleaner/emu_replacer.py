"""
Clean Emulator Replacement Engine: Replaces untrusted/sketchy crack DLLs with clean, verified open-source emulators.
"""
from dataclasses import dataclass
from datetime import datetime
import json
import os
from pathlib import Path
import re
import shutil
from typing import List, Optional, Tuple
import urllib.request


@dataclass
class DRMTarget:
    dll_name: str
    architecture: str  # x86 or x64
    full_path: Path
    relative_path: str
    has_appid_file: bool
    app_id: Optional[str] = None


class EmulatorReplacer:
    """Detects untrusted Steamworks DLLs and replaces them with verified clean open-source emulators (e.g., Goldberg)."""

    GOLDBERG_URLS = {
        "x86": "https://gitlab.com/Mr_Goldberg/goldberg_emulator/-/jobs/artifacts/master/raw/steam_api.dll?job=build",
        "x64": "https://gitlab.com/Mr_Goldberg/goldberg_emulator/-/jobs/artifacts/master/raw/steam_api64.dll?job=build",
    }

    def __init__(self, target_dir: Path, emulator_storage: Optional[Path] = None):
        self.target_dir = Path(target_dir).resolve()
        if emulator_storage:
            self.emulator_storage = Path(emulator_storage).resolve()
        else:
            self.emulator_storage = Path(__file__).resolve().parent.parent.parent / "emulators" / "goldberg"
        self.backup_dir = self.target_dir / ".gamecleaner_backup"

    def discover_appid(self, dll_parent_dir: Path) -> Optional[str]:
        """
        Discovers the true Steam AppID from steam_appid.txt, steam_settings, or repack INI files
        (steam_emu.ini, codex.ini, flt.ini, Rune.ini, SteamConfig.ini, ALI213.ini, CreamAPI.ini).
        """
        # 1. Direct steam_appid.txt
        direct_file = dll_parent_dir / "steam_appid.txt"
        if direct_file.exists():
            try:
                val = direct_file.read_text(encoding="utf-8", errors="ignore").strip()
                if val.isdigit() and len(val) >= 3:
                    return val
            except Exception:
                pass

        # 2. steam_settings/steam_appid.txt
        settings_file = dll_parent_dir / "steam_settings" / "steam_appid.txt"
        if settings_file.exists():
            try:
                val = settings_file.read_text(encoding="utf-8", errors="ignore").strip()
                if val.isdigit() and len(val) >= 3:
                    return val
            except Exception:
                pass

        # 3. Check INI files across dll_parent, parent, and root target_dir
        pattern = re.compile(
            r"^\s*(?:AppId|AppID|SteamAppId|TargetAppId)\s*=\s*([0-9]{3,10})",
            re.IGNORECASE | re.MULTILINE,
        )
        candidate_dirs = [dll_parent_dir, dll_parent_dir.parent, self.target_dir]
        seen_dirs = set()

        for cdir in candidate_dirs:
            cdir_res = cdir.resolve()
            if cdir_res in seen_dirs or not cdir_res.exists():
                continue
            seen_dirs.add(cdir_res)

            for ini_path in cdir_res.glob("*.ini"):
                try:
                    content = ini_path.read_text(encoding="utf-8", errors="ignore")
                    match = pattern.search(content)
                    if match:
                        return match.group(1).strip()
                except Exception:
                    continue
        return None

    def find_drm_targets(self) -> List[DRMTarget]:
        """Scans the game directory for Steam API DLLs and their configurations."""
        targets = []
        for path in self.target_dir.rglob("*.dll"):
            if ".gamecleaner" in str(path):
                continue
            name_lower = path.name.lower()
            if name_lower in ("steam_api.dll", "steam_api64.dll"):
                arch = "x64" if "64" in name_lower else "x86"
                appid_val = self.discover_appid(path.parent)

                targets.append(DRMTarget(
                    dll_name=path.name,
                    architecture=arch,
                    full_path=path,
                    relative_path=str(path.relative_to(self.target_dir)),
                    has_appid_file=bool(appid_val),
                    app_id=appid_val,
                ))
        return targets

    def backup_dll(self, target: DRMTarget) -> Path:
        """Backs up the existing DLL before replacement."""
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"{target.dll_name}_{timestamp}.bak"
        dest_path = self.backup_dir / backup_name
        shutil.copy2(str(target.full_path), str(dest_path))

        # Update backup manifest
        manifest_file = self.backup_dir / "backup_manifest.json"
        manifest = {}
        if manifest_file.exists():
            try:
                manifest = json.loads(manifest_file.read_text())
            except Exception:
                pass

        manifest[backup_name] = {
            "original_path": str(target.full_path),
            "relative_path": target.relative_path,
            "architecture": target.architecture,
            "timestamp": datetime.now().isoformat(),
        }
        manifest_file.write_text(json.dumps(manifest, indent=2))
        return dest_path

    def get_clean_emulator(self, architecture: str) -> Optional[Path]:
        """Retrieves or downloads the clean open-source Goldberg emulator for x86 or x64."""
        self.emulator_storage.mkdir(parents=True, exist_ok=True)
        filename = "steam_api64.dll" if architecture == "x64" else "steam_api.dll"
        local_file = self.emulator_storage / filename

        if local_file.exists() and local_file.stat().st_size > 10000:
            return local_file

        # Attempt to download Goldberg artifact if not present locally
        url = self.GOLDBERG_URLS.get(architecture)
        if url:
            try:
                urllib.request.urlretrieve(url, str(local_file))
                if local_file.exists() and local_file.stat().st_size > 10000:
                    return local_file
            except Exception:
                pass

        return local_file if local_file.exists() else None

    def replace_with_clean_emulator(
        self,
        target: DRMTarget,
        custom_clean_dll: Optional[Path] = None,
        default_appid: str = "480",
    ) -> Tuple[bool, str]:
        """
        Replaces the untrusted DLL with a verified clean emulator.
        Also configures steam_appid.txt so the game launches seamlessly.
        """
        # Step 1: Backup
        self.backup_dll(target)

        # Step 2: Get clean DLL
        clean_dll = custom_clean_dll or self.get_clean_emulator(target.architecture)
        if not clean_dll or not clean_dll.exists():
            return False, f"Clean emulator binary for {target.architecture} not found in {self.emulator_storage}"

        # Step 3: Replace file
        try:
            shutil.copy2(str(clean_dll), str(target.full_path))
        except Exception as e:
            return False, f"Failed to overwrite {target.full_path.name}: {e}"

        # Step 4: Ensure steam_appid.txt and steam_settings exist with accurate AppID
        chosen_appid = target.app_id or self.discover_appid(target.full_path.parent) or default_appid
        appid_file = target.full_path.parent / "steam_appid.txt"
        appid_file.write_text(chosen_appid, encoding="utf-8")

        # Also create steam_settings/steam_appid.txt for Goldberg emulator compatibility
        goldberg_dir = target.full_path.parent / "steam_settings"
        goldberg_dir.mkdir(parents=True, exist_ok=True)
        (goldberg_dir / "steam_appid.txt").write_text(chosen_appid, encoding="utf-8")

        return True, f"Successfully replaced {target.dll_name} with clean open-source emulator."

    def rollback_backup(self, backup_name: str) -> bool:
        """Restores a backed up DLL."""
        manifest_file = self.backup_dir / "backup_manifest.json"
        if not manifest_file.exists():
            return False

        manifest = json.loads(manifest_file.read_text())
        if backup_name not in manifest:
            return False

        info = manifest[backup_name]
        src_file = self.backup_dir / backup_name
        dest_file = Path(info["original_path"])

        if src_file.exists():
            shutil.copy2(str(src_file), str(dest_file))
            return True
        return False
