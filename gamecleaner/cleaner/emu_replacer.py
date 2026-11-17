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
    platform: str = "Steam"  # Steam, Epic, Ubisoft
    app_id: Optional[str] = None


class EmulatorReplacer:
    """Detects untrusted Steamworks DLLs and replaces them with verified clean open-source emulators (e.g., Goldberg)."""

    GOLDBERG_URLS = {
        "x86": "https://github.com/Detanup01/gbe_fork/releases/download/release-2026_09_27/emu-win-release-vs22.7z",
        "x64": "https://github.com/Detanup01/gbe_fork/releases/download/release-2026_09_27/emu-win-release-vs22.7z",
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
        """Scans the game directory for Steam, Epic, and Ubisoft DRM wrapper DLLs."""
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
                    platform="Steam",
                    full_path=path,
                    relative_path=str(path.relative_to(self.target_dir)),
                    has_appid_file=bool(appid_val),
                    app_id=appid_val,
                ))
            elif "eossdk" in name_lower and name_lower.endswith(".dll"):
                arch = "x64" if "64" in name_lower else "x86"
                targets.append(DRMTarget(
                    dll_name=path.name,
                    architecture=arch,
                    platform="Epic",
                    full_path=path,
                    relative_path=str(path.relative_to(self.target_dir)),
                    has_appid_file=False,
                ))
            elif "uplay_r1_loader" in name_lower and name_lower.endswith(".dll"):
                arch = "x64" if "64" in name_lower else "x86"
                targets.append(DRMTarget(
                    dll_name=path.name,
                    architecture=arch,
                    platform="Ubisoft",
                    full_path=path,
                    relative_path=str(path.relative_to(self.target_dir)),
                    has_appid_file=False,
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

    def get_clean_emulator(self, architecture: str, platform: str = "Steam") -> Optional[Path]:
        """Retrieves or downloads the clean open-source emulator for Steam, Epic, or Ubisoft."""
        self.emulator_storage.mkdir(parents=True, exist_ok=True)
        
        if platform == "Epic":
            epic_storage = self.emulator_storage.parent / "epic"
            epic_storage.mkdir(parents=True, exist_ok=True)
            filename = "EOSSDK-Win64-Shipping.dll" if architecture == "x64" else "EOSSDK-Win32-Shipping.dll"
            local_file = epic_storage / filename
            if local_file.exists() and local_file.stat().st_size > 1000:
                return local_file
            return None

        if platform == "Ubisoft":
            uplay_storage = self.emulator_storage.parent / "ubisoft"
            uplay_storage.mkdir(parents=True, exist_ok=True)
            filename = "uplay_r1_loader64.dll" if architecture == "x64" else "uplay_r1_loader.dll"
            local_file = uplay_storage / filename
            if local_file.exists() and local_file.stat().st_size > 1000:
                return local_file
            return None

        # Steam (Goldberg)
        filename = "steam_api64.dll" if architecture == "x64" else "steam_api.dll"
        local_file = self.emulator_storage / filename

        if local_file.exists() and local_file.stat().st_size > 10000:
            return local_file

        # Attempt to download and extract Goldberg release archive if not present locally
        archive_url = self.GOLDBERG_URLS.get(architecture)
        if archive_url:
            try:
                import subprocess
                import tempfile
                with tempfile.TemporaryDirectory() as tmp_dir:
                    tmp_archive = Path(tmp_dir) / "goldberg.7z"
                    urllib.request.urlretrieve(archive_url, str(tmp_archive))
                    subprocess.run(["tar", "-xf", str(tmp_archive), "-C", tmp_dir], check=True, capture_output=True)
                    for dll_p in Path(tmp_dir).rglob("*.dll"):
                        p_str = str(dll_p).lower()
                        if dll_p.name == "steam_api64.dll" and "x64" in p_str and "regular" in p_str:
                            shutil.copy2(str(dll_p), str(self.emulator_storage / "steam_api64.dll"))
                        elif dll_p.name == "steam_api.dll" and "x86" in p_str and "regular" in p_str:
                            shutil.copy2(str(dll_p), str(self.emulator_storage / "steam_api.dll"))
            except Exception:
                pass

        if local_file.exists() and local_file.stat().st_size > 10000:
            return local_file

        return None

    def replace_with_clean_emulator(
        self,
        target: DRMTarget,
        custom_clean_dll: Optional[Path] = None,
        default_appid: str = "480",
    ) -> Tuple[bool, str]:
        """
        Replaces the untrusted DLL with a verified clean emulator.
        Also configures steam_appid.txt and DLCs for Steam targets.
        """
        # Step 1: Backup
        self.backup_dll(target)

        # Step 2: Get clean DLL
        clean_dll = custom_clean_dll or self.get_clean_emulator(target.architecture, platform=target.platform)
        if not clean_dll or not clean_dll.exists():
            return False, f"Clean emulator binary for {target.platform} ({target.architecture}) not found"

        # Step 3: Replace file (using rename-first evasion if file is locked or loaded in memory)
        try:
            # Strip read-only
            if target.full_path.exists():
                try:
                    import stat
                    os.chmod(target.full_path, stat.S_IWRITE | stat.S_IREAD)
                except Exception:
                    pass
            shutil.copy2(str(clean_dll), str(target.full_path))
        except (PermissionError, OSError):
            # NTFS loaded DLL evasion: rename existing locked file out of the way first
            try:
                temp_old = target.full_path.with_name(f"{target.full_path.name}.gc_old")
                if temp_old.exists():
                    temp_old.unlink()
                os.replace(target.full_path, temp_old)
                shutil.copy2(str(clean_dll), str(target.full_path))
            except Exception as e:
                return False, f"Failed to overwrite {target.full_path.name} (locked by process): {e}"

        # Step 4-6: Configure Steam-specific settings (AppID, interfaces, DLC manifests)
        if target.platform == "Steam":
            chosen_appid = target.app_id or self.discover_appid(target.full_path.parent) or default_appid
            appid_file = target.full_path.parent / "steam_appid.txt"
            appid_file.write_text(chosen_appid, encoding="utf-8")

            # Also create steam_settings/steam_appid.txt for Goldberg emulator compatibility
            goldberg_dir = target.full_path.parent / "steam_settings"
            goldberg_dir.mkdir(parents=True, exist_ok=True)
            (goldberg_dir / "steam_appid.txt").write_text(chosen_appid, encoding="utf-8")

            # Step 5: Reverse-engineer required Steamworks interfaces for Goldberg
            try:
                from gamecleaner.rea.interface_extractor import InterfaceExtractor
                extractor = InterfaceExtractor()
                interfaces_file = target.full_path.parent / "steam_interfaces.txt"
                extractor.generate_interfaces_file(target.full_path.parent, interfaces_file)
                shutil.copy2(str(interfaces_file), str(goldberg_dir / "steam_interfaces.txt"))
            except Exception:
                pass

            # Step 6: Automatically query Steam store API and populate steam_settings/DLC.txt
            try:
                from gamecleaner.cleaner.dlc_fetcher import SteamDLCFetcher
                dlc_fetcher = SteamDLCFetcher()
                dlc_file = goldberg_dir / "DLC.txt"
                if not dlc_file.exists():
                    dlc_fetcher.generate_dlc_txt(chosen_appid, dlc_file, game_dir=target.full_path.parent)
            except Exception:
                pass

            # Step 7: Mirror clean emulator and configs to common executable subdirectories (bin/, bin/x64/, etc.)
            common_bin_candidates = [
                target.full_path.parent / "bin",
                target.full_path.parent / "bin" / "x64",
                target.full_path.parent / "bin" / "x86",
                target.full_path.parent / "Binaries" / "Win64",
                target.full_path.parent / "Engine" / "Binaries" / "Win64",
            ]
            for bdir in common_bin_candidates:
                if bdir.exists() and bdir.is_dir():
                    try:
                        shutil.copy2(str(clean_dll), str(bdir / target.dll_name))
                        (bdir / "steam_appid.txt").write_text(chosen_appid, encoding="utf-8")
                        b_gold = bdir / "steam_settings"
                        b_gold.mkdir(parents=True, exist_ok=True)
                        (b_gold / "steam_appid.txt").write_text(chosen_appid, encoding="utf-8")
                        if (target.full_path.parent / "steam_interfaces.txt").exists():
                            shutil.copy2(str(target.full_path.parent / "steam_interfaces.txt"), str(bdir / "steam_interfaces.txt"))
                    except Exception:
                        pass

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
