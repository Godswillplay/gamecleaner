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
        candidate_dirs = [dll_parent_dir, dll_parent_dir.parent, self.target_dir]
        seen_dirs = set()

        # 1. Direct steam_appid.txt or steam_settings/steam_appid.txt across all candidate locations
        for cdir in candidate_dirs:
            cdir_res = cdir.resolve()
            if cdir_res in seen_dirs or not cdir_res.exists():
                continue
            seen_dirs.add(cdir_res)

            for probe_path in (cdir_res / "steam_appid.txt", cdir_res / "steam_settings" / "steam_appid.txt"):
                if probe_path.exists():
                    try:
                        val = probe_path.read_text(encoding="utf-8", errors="ignore").strip().strip('"').strip("'")
                        if val.isdigit() and len(val) >= 3 and val != "480" and val != "0":
                            return val
                    except Exception:
                        pass

        # 2. Check INI files across candidate directories (allowing quoted AppIDs)
        pattern = re.compile(
            r"""^\s*(?:AppId|AppID|SteamAppId|TargetAppId)\s*=\s*["']?([0-9]{3,10})["']?""",
            re.IGNORECASE | re.MULTILINE,
        )

        for cdir_res in seen_dirs:
            for ini_path in cdir_res.glob("*.ini"):
                try:
                    content = ini_path.read_text(encoding="utf-8", errors="ignore")
                    match = pattern.search(content)
                    if match:
                        found_id = match.group(1).strip()
                        if found_id != "0":
                            return found_id
                except Exception:
                    continue

        # 3. Fallback check for any 480 placeholder if nothing else was found
        for cdir_res in seen_dirs:
            for probe_path in (cdir_res / "steam_appid.txt", cdir_res / "steam_settings" / "steam_appid.txt"):
                if probe_path.exists():
                    try:
                        val = probe_path.read_text(encoding="utf-8", errors="ignore").strip().strip('"').strip("'")
                        if val.isdigit() and len(val) >= 3:
                            return val
                    except Exception:
                        pass

        return None

    def _detect_pe_arch(self, path: Path) -> str:
        """Reads PE header machine type directly for 100% accurate architecture identification."""
        try:
            with open(path, "rb") as f:
                mz = f.read(2)
                if mz == b"MZ":
                    f.seek(0x3C)
                    pe_offset = int.from_bytes(f.read(4), "little")
                    f.seek(pe_offset + 4)
                    machine = int.from_bytes(f.read(2), "little")
                    if machine == 0x8664:
                        return "x64"
                    elif machine == 0x014C:
                        return "x86"
        except Exception:
            pass
        return "x64" if "64" in path.name.lower() else "x86"

    def find_drm_targets(self) -> List[DRMTarget]:
        """Scans the game directory for Steam, Epic, and Ubisoft DRM wrapper DLLs."""
        targets = []
        for path in self.target_dir.rglob("*.dll"):
            if ".gamecleaner" in str(path):
                continue
            name_lower = path.name.lower()
            if name_lower in ("steam_api.dll", "steam_api64.dll"):
                arch = self._detect_pe_arch(path)
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
                arch = self._detect_pe_arch(path)
                targets.append(DRMTarget(
                    dll_name=path.name,
                    architecture=arch,
                    platform="Epic",
                    full_path=path,
                    relative_path=str(path.relative_to(self.target_dir)),
                    has_appid_file=False,
                ))
            elif any(tag in name_lower for tag in ("uplay_r1_loader", "uplay_r2_loader")) and name_lower.endswith(".dll"):
                arch = self._detect_pe_arch(path)
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
        home_emu = Path.home() / ".gamecleaner" / "emulators"
        
        if platform == "Epic":
            filename = "EOSSDK-Win64-Shipping.dll" if architecture == "x64" else "EOSSDK-Win32-Shipping.dll"
            search_paths = [
                self.emulator_storage / "epic" / filename,
                self.emulator_storage.parent / "epic" / filename,
                home_emu / "epic" / filename,
                self.emulator_storage / filename,
            ]
            for p in search_paths:
                if p.exists() and p.stat().st_size > 1000:
                    return p
            return None

        if platform == "Ubisoft":
            filename = "uplay_r1_loader64.dll" if architecture == "x64" else "uplay_r1_loader.dll"
            search_paths = [
                self.emulator_storage / "ubisoft" / filename,
                self.emulator_storage.parent / "ubisoft" / filename,
                home_emu / "ubisoft" / filename,
                self.emulator_storage / filename,
            ]
            for p in search_paths:
                if p.exists() and p.stat().st_size > 1000:
                    return p
            return None

        # Steam (Goldberg)
        filename = "steam_api64.dll" if architecture == "x64" else "steam_api.dll"
        steam_search_paths = [
            self.emulator_storage / filename,
            self.emulator_storage / "goldberg" / filename,
            self.emulator_storage.parent / "goldberg" / filename,
            home_emu / "goldberg" / filename,
        ]
        for p in steam_search_paths:
            if p.exists() and p.stat().st_size > 10000:
                return p

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

        for p in steam_search_paths:
            if p.exists() and p.stat().st_size > 10000:
                return p

        return None

    def replace_with_clean_emulator(
        self,
        target: DRMTarget,
        custom_clean_dll: Optional[Path] = None,
        default_appid: str = "480",
    ) -> Tuple[bool, str]:
        """
        Replaces the untrusted DLL with a verified clean emulator.
        Also configures steam_appid.txt, interfaces, and DLCs for Steam targets across all executable locations.
        """
        import time

        # Step 1: Validate clean emulator exists BEFORE creating backups
        clean_dll = Path(custom_clean_dll) if custom_clean_dll else self.get_clean_emulator(target.architecture, platform=target.platform)
        if not clean_dll or not clean_dll.exists():
            return False, f"Clean emulator binary for {target.platform} ({target.architecture}) not found"

        # Step 2: Backup once clean replacement binary is confirmed
        if target.full_path.exists():
            self.backup_dll(target)

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
                temp_old = target.full_path.with_name(f"{target.full_path.name}.{int(time.time()*1000)}.gc_old")
                if temp_old.exists():
                    try:
                        temp_old.unlink()
                    except Exception:
                        pass
                os.replace(target.full_path, temp_old)
                shutil.copy2(str(clean_dll), str(target.full_path))
            except Exception as e:
                return False, f"Failed to overwrite {target.full_path.name} (locked by process): {e}"

        def _safe_write(p: Path, text: str):
            try:
                p.parent.mkdir(parents=True, exist_ok=True)
                if p.exists():
                    try:
                        import stat
                        os.chmod(p, stat.S_IWRITE | stat.S_IREAD)
                    except Exception:
                        pass
                p.write_text(text, encoding="utf-8")
            except Exception:
                pass

        def _safe_copy(src_p: Path, dst_p: Path):
            try:
                dst_p.parent.mkdir(parents=True, exist_ok=True)
                if dst_p.exists():
                    try:
                        import stat
                        os.chmod(dst_p, stat.S_IWRITE | stat.S_IREAD)
                    except Exception:
                        pass
                shutil.copy2(str(src_p), str(dst_p))
            except Exception:
                pass

        # Step 4-6: Configure Steam-specific settings (AppID, interfaces, DLC manifests)
        if target.platform == "Steam":
            chosen_appid = target.app_id or self.discover_appid(target.full_path.parent) or default_appid
            appid_file = target.full_path.parent / "steam_appid.txt"
            _safe_write(appid_file, chosen_appid)

            # Also create steam_settings/steam_appid.txt for Goldberg emulator compatibility
            goldberg_dir = target.full_path.parent / "steam_settings"
            goldberg_dir.mkdir(parents=True, exist_ok=True)
            _safe_write(goldberg_dir / "steam_appid.txt", chosen_appid)

            # Step 5: Reverse-engineer required Steamworks interfaces for Goldberg
            try:
                from gamecleaner.rea.interface_extractor import InterfaceExtractor
                extractor = InterfaceExtractor()
                interfaces_file = target.full_path.parent / "steam_interfaces.txt"
                extractor.generate_interfaces_file(target.full_path.parent, interfaces_file)
                if interfaces_file.exists():
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

            # Step 7: Mirror clean emulator, DLC.txt, steam_interfaces.txt, and configs to candidate executable directories
            candidate_dirs = set()
            # If target DLL was already located in bin/ or bin/x64/, include game root target_dir
            if target.full_path.parent != self.target_dir:
                candidate_dirs.add(self.target_dir)

            # Common binary subdirectories relative to self.target_dir
            for sub in [
                "bin",
                "bin/x64",
                "bin/x86",
                "bin/Win64",
                "bin/Win32",
                "Binaries/Win64",
                "Binaries/Win32",
                "Engine/Binaries/Win64",
                "Engine/Binaries/Win32",
            ]:
                cand = (self.target_dir / sub).resolve()
                if cand.exists() and cand.is_dir() and cand != target.full_path.parent:
                    candidate_dirs.add(cand)

            # Also check subdirectories relative to target.full_path.parent
            for sub in ["bin", "bin/x64", "bin/x86", "Binaries/Win64"]:
                cand = (target.full_path.parent / sub).resolve()
                if cand.exists() and cand.is_dir() and cand != target.full_path.parent:
                    candidate_dirs.add(cand)

            # Also include any directories containing .exe files under target_dir
            for exe_path in self.target_dir.rglob("*.exe"):
                if ".gamecleaner" in str(exe_path):
                    continue
                exe_dir = exe_path.parent.resolve()
                if exe_dir != target.full_path.parent and exe_dir.exists() and exe_dir.is_dir():
                    candidate_dirs.add(exe_dir)

            # Mirror to all discovered candidate directories
            for bdir in candidate_dirs:
                try:
                    _safe_copy(clean_dll, bdir / target.dll_name)
                    _safe_write(bdir / "steam_appid.txt", chosen_appid)
                    b_gold = bdir / "steam_settings"
                    b_gold.mkdir(parents=True, exist_ok=True)
                    _safe_write(b_gold / "steam_appid.txt", chosen_appid)

                    # Mirror DLC.txt to steam_settings/DLC.txt and root
                    src_dlc = goldberg_dir / "DLC.txt"
                    if src_dlc.exists():
                        _safe_copy(src_dlc, b_gold / "DLC.txt")
                        _safe_copy(src_dlc, bdir / "DLC.txt")

                    # Mirror steam_interfaces.txt to steam_settings and root
                    src_iface = goldberg_dir / "steam_interfaces.txt"
                    if not src_iface.exists() and (target.full_path.parent / "steam_interfaces.txt").exists():
                        src_iface = target.full_path.parent / "steam_interfaces.txt"
                    if src_iface.exists():
                        _safe_copy(src_iface, b_gold / "steam_interfaces.txt")
                        _safe_copy(src_iface, bdir / "steam_interfaces.txt")

                    # Mirror persona / identity configs if present
                    for id_file in ("account_name.txt", "user_steam_id.txt", "listen_port.txt"):
                        if (goldberg_dir / id_file).exists():
                            _safe_copy(goldberg_dir / id_file, b_gold / id_file)
                except Exception:
                    pass
        elif target.platform in ("Epic", "Ubisoft"):
            # Mirror clean Epic/Ubisoft DLL to any candidate bin directories
            candidate_dirs = set()
            if target.full_path.parent != self.target_dir:
                candidate_dirs.add(self.target_dir)
            for sub in ["bin", "bin/x64", "Binaries/Win64", "Engine/Binaries/Win64"]:
                cand = (self.target_dir / sub).resolve()
                if cand.exists() and cand.is_dir() and cand != target.full_path.parent:
                    candidate_dirs.add(cand)

            for bdir in candidate_dirs:
                try:
                    if (bdir / target.dll_name).exists() or any(bdir.glob("*.exe")):
                        shutil.copy2(str(clean_dll), str(bdir / target.dll_name))
                except Exception:
                    pass

        return True, f"Successfully replaced {target.dll_name} with clean open-source emulator."

    def list_backups(self) -> List[dict]:
        """Returns list of all available emulator backups in .gamecleaner_backup."""
        manifest_file = self.backup_dir / "backup_manifest.json"
        if not manifest_file.exists():
            return []
        try:
            manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
            backups = []
            for b_name, data in manifest.items():
                data_copy = dict(data)
                data_copy["backup_file"] = b_name
                backups.append(data_copy)
            return backups
        except Exception:
            return []

    def rollback_all(self) -> List[Tuple[str, bool]]:
        """Restores all backed up DLLs."""
        backups = self.list_backups()
        results = []
        for b in backups:
            name = b["backup_file"]
            ok = self.rollback_backup(name)
            results.append((name, ok))
        return results

    def rollback_backup(self, backup_name: str) -> bool:
        """Restores a backed up DLL."""
        manifest_file = self.backup_dir / "backup_manifest.json"
        if not manifest_file.exists():
            return False

        try:
            manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        except Exception:
            return False

        if backup_name not in manifest:
            return False

        info = manifest[backup_name]
        src_file = self.backup_dir / backup_name
        dest_file = Path(info["original_path"])

        if src_file.exists():
            dest_file.parent.mkdir(parents=True, exist_ok=True)
            if dest_file.exists():
                try:
                    import stat
                    os.chmod(dest_file, stat.S_IWRITE | stat.S_IREAD)
                except Exception:
                    pass
            shutil.copy2(str(src_file), str(dest_file))
            try:
                src_file.unlink()
                del manifest[backup_name]
                manifest_file.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
            except Exception:
                pass
            return True
        return False
