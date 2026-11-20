"""
Save Game and Steam ID Migrator.
Preserves user save games and Steam profile identity when switching from scene cracks (CODEX, RUNE, FLT, etc.)
to clean Goldberg Steam emulator.
"""
from dataclasses import dataclass, field
import os
from pathlib import Path
import re
import shutil
from typing import Dict, List, Optional


@dataclass
class SaveMigrationResult:
    app_id: Optional[str]
    account_name: Optional[str]
    steam_id: Optional[str]
    config_source: Optional[str]
    goldberg_settings_configured: bool
    saves_found_at: Optional[str]
    saves_migrated_to: Optional[str]
    migrated_files: List[str] = field(default_factory=list)


class SaveGameMigrator:
    """Detects scene crack configurations, configures Goldberg identity, and migrates save games."""

    SCENE_CONFIG_NAMES = [
        "steam_emu.ini",
        "codex.ini",
        "rune.ini",
        "flt.ini",
        "tenoke.ini",
        "tinyiso.ini",
        "doge.ini",
        "chronos.ini",
        "darksiders.ini",
        "valve.ini",
        "creamapi.ini",
        "saves.ini",
        "empress.ini",
        "skidrow.ini",
        "cpy.ini",
        "ali213.ini",
        "plaza.ini",
        "hoodlum.ini",
        "hlm.ini",
        "razor1911.ini",
        "rzr.ini",
        "steamconfig.ini",
        "smartsteamemu.ini",
        "goldberg_emulator.ini",
    ]

    def __init__(self, game_dir: Path):
        self.game_dir = Path(game_dir).resolve()
        self.appdata = Path(os.environ.get("APPDATA", "C:\\Users\\Default\\AppData\\Roaming"))
        self.localappdata = Path(os.environ.get("LOCALAPPDATA", "C:\\Users\\Default\\AppData\\Local"))
        self.public_docs = Path(os.environ.get("PUBLIC", "C:\\Users\\Public")) / "Documents"
        # Support OneDrive protected/redirected Documents folder if active
        onedrive_docs = Path.home() / "OneDrive" / "Documents"
        self.user_docs = onedrive_docs if onedrive_docs.exists() else (Path.home() / "Documents")

    def detect_scene_config(self) -> Dict[str, Optional[str]]:
        """Searches game directory for scene INI files and extracts AppId, PersonaName, and SteamId."""
        info: Dict[str, Optional[str]] = {
            "app_id": None,
            "account_name": None,
            "steam_id": None,
            "source_file": None,
        }

        # Check steam_appid.txt first
        appid_txt = self.game_dir / "steam_appid.txt"
        if appid_txt.exists():
            try:
                content = appid_txt.read_text(encoding="utf-8", errors="ignore").strip().strip('"').strip("'")
                if content.isdigit() and content not in ("480", "0"):
                    info["app_id"] = content
            except Exception:
                pass

        # Scan for scene INIs in game root and subdirectories
        for root, _, files in os.walk(self.game_dir):
            for file in files:
                if file.lower() in self.SCENE_CONFIG_NAMES:
                    ini_path = Path(root) / file
                    try:
                        content = ini_path.read_text(encoding="utf-8", errors="ignore")
                        info["source_file"] = str(ini_path)

                        # Extract AppId (allow quoted or unquoted)
                        if not info["app_id"] or info["app_id"] in ("480", "0"):
                            m = re.search(r"""^\s*(?:AppId|appid|TargetAppId|SteamAppId)\s*=\s*["']?(\d+)["']?""", content, re.MULTILINE | re.IGNORECASE)
                            if m:
                                found_id = m.group(1).strip()
                                if found_id != "0":
                                    info["app_id"] = found_id

                        # Extract Account Name / PersonaName
                        if not info["account_name"]:
                            m = re.search(r"^\s*(?:PersonaName|AccountIdName|UserName|AccountName|PlayerName)\s*=\s*(.+)", content, re.MULTILINE | re.IGNORECASE)
                            if m:
                                raw_name = m.group(1).strip().strip('"').strip("'")
                                raw_name = raw_name.split(";")[0].split("#")[0].strip()
                                if raw_name:
                                    info["account_name"] = raw_name

                        # Extract SteamId64 / AccountId
                        if not info["steam_id"]:
                            m = re.search(r"^\s*(?:AccountId|SteamId|SteamId64|TargetSteamId)\s*=\s*(\d+)", content, re.MULTILINE | re.IGNORECASE)
                            if m:
                                info["steam_id"] = m.group(1).strip()

                        if info["app_id"] and info["account_name"]:
                            return info
                    except Exception:
                        continue

        return info

    def configure_goldberg_identity(
        self,
        app_id: Optional[str] = None,
        account_name: Optional[str] = None,
        steam_id: Optional[str] = None,
    ) -> bool:
        """Configures Goldberg Steam emulator identity files in steam_settings directory and mirrors to bin dirs."""
        steam_settings = self.game_dir / "steam_settings"
        try:
            steam_settings.mkdir(parents=True, exist_ok=True)

            if account_name:
                (steam_settings / "account_name.txt").write_text(account_name, encoding="utf-8")

            if steam_id:
                (steam_settings / "user_steam_id.txt").write_text(steam_id, encoding="utf-8")

            if app_id:
                (self.game_dir / "steam_appid.txt").write_text(app_id, encoding="utf-8")
                (steam_settings / "steam_appid.txt").write_text(app_id, encoding="utf-8")

            # Mirror identity to common executable / bin subdirectories if they exist
            common_subdirs = [
                self.game_dir / "bin",
                self.game_dir / "bin" / "x64",
                self.game_dir / "bin" / "x86",
                self.game_dir / "Binaries" / "Win64",
                self.game_dir / "Binaries" / "Win32",
                self.game_dir / "Engine" / "Binaries" / "Win64",
            ]
            for sdir in common_subdirs:
                if sdir.exists() and sdir.is_dir():
                    try:
                        s_gold = sdir / "steam_settings"
                        s_gold.mkdir(parents=True, exist_ok=True)
                        if account_name:
                            (s_gold / "account_name.txt").write_text(account_name, encoding="utf-8")
                        if steam_id:
                            (s_gold / "user_steam_id.txt").write_text(steam_id, encoding="utf-8")
                        if app_id:
                            (sdir / "steam_appid.txt").write_text(app_id, encoding="utf-8")
                            (s_gold / "steam_appid.txt").write_text(app_id, encoding="utf-8")
                    except Exception:
                        pass

            return True
        except Exception:
            return False

    def find_scene_save_directory(self, app_id: str) -> Optional[Path]:
        """Locates scene save files across all major scene groups and Steam Cloud."""
        if not app_id:
            return None

        candidates: List[Path] = [
            # CODEX in AppData Roaming and Public Documents
            self.appdata / "Steam" / "CODEX" / app_id,
            self.appdata / "Roaming" / "Steam" / "CODEX" / app_id,
            self.public_docs / "Steam" / "CODEX" / app_id,
            # RUNE in LocalAppData and Public Documents
            self.localappdata / "Rabinoviche" / "Rune" / app_id,
            self.public_docs / "Steam" / "RUNE" / app_id,
            # TENOKE in LocalAppData, AppData, and My Games
            self.localappdata / "TENOKE" / app_id,
            self.appdata / "TENOKE" / app_id,
            self.user_docs / "My Games" / f"TENOKE_{app_id}",
            # TiNYiSO in AppData
            self.appdata / "TiNYiSO" / app_id,
            # DOGE in AppData
            self.appdata / "DOGE" / app_id,
            # CHRONOS in AppData and LocalAppData
            self.appdata / "Chronos" / app_id,
            self.localappdata / "Chronos" / app_id,
            # DARKSIDERS in AppData
            self.appdata / "DARKSIDERS" / app_id,
            # FLT in AppData and LocalAppData
            self.appdata / "FLT" / app_id,
            self.localappdata / "FLT" / app_id,
            # EMPRESS in AppData, Public Documents, and LocalAppData
            self.appdata / "EMPRESS" / app_id,
            self.public_docs / "EMPRESS" / app_id,
            self.localappdata / "EMPRESS" / app_id,
            # SKIDROW in LocalAppData and AppData
            self.localappdata / "SKIDROW" / app_id,
            self.appdata / "SKIDROW" / app_id,
            # PLAZA in Public Documents and AppData
            self.public_docs / "Steam" / "PLAZA" / app_id,
            self.appdata / "Steam" / "PLAZA" / app_id,
            # HOODLUM in AppData, LocalAppData, and User Documents
            self.appdata / "HOODLUM" / app_id,
            self.localappdata / "HOODLUM" / app_id,
            self.user_docs / "HOODLUM" / app_id,
            # RAZOR1911 in AppData, LocalAppData, and User Documents
            self.appdata / "Razor1911" / app_id,
            self.localappdata / "Razor1911" / app_id,
            self.user_docs / "Razor1911" / app_id,
            # ALI213 in Game Directory, AppData, and LocalAppData
            self.game_dir / "Profile" / "ALI213" / "Saves" / app_id,
            self.game_dir / "Profile" / "ALI213" / "Saves",
            self.game_dir / "ALI213" / "Saves",
            self.game_dir / "Profile" / "Saves",
            self.appdata / "ALI213" / app_id,
            self.localappdata / "ALI213" / app_id,
            # SmartSteamEmu in Game Directory
            self.game_dir / "SmartSteamEmu" / app_id,
            self.game_dir / "SmartSteamEmu",
        ]

        # CPY in Documents/CPY_SAVES (often structured as CPY_SAVES/<Player>/<appid> or CPY_SAVES/<appid>)
        cpy_docs = [self.user_docs / "CPY_SAVES", self.public_docs / "CPY_SAVES", self.public_docs / "Steam" / "CPY"]
        for cpy_base in cpy_docs:
            if cpy_base.exists() and cpy_base.is_dir():
                candidates.append(cpy_base / app_id)
                try:
                    for sub in cpy_base.iterdir():
                        if sub.is_dir():
                            candidates.append(sub / app_id)
                except Exception:
                    pass

        # Real Steam Cloud / userdata saves
        steam_userdata_roots = [
            Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")) / "Steam" / "userdata",
            Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "Steam" / "userdata",
        ]
        try:
            import winreg
            for hkey, subkey in [
                (winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Valve\Steam"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Valve\Steam"),
            ]:
                try:
                    with winreg.OpenKey(hkey, subkey) as k:
                        val, _ = winreg.QueryValueEx(k, "SteamPath")
                        if val:
                            steam_userdata_roots.append(Path(val) / "userdata")
                except Exception:
                    pass
        except Exception:
            pass

        for s_root in steam_userdata_roots:
            if s_root.exists() and s_root.is_dir():
                try:
                    for udir in s_root.iterdir():
                        if udir.is_dir() and udir.name.isdigit():
                            candidates.append(udir / app_id / "remote")
                            candidates.append(udir / app_id)
                except Exception:
                    pass

        # Prioritize candidates that exist and contain actual files
        fallback_cand = None
        for cand in candidates:
            if cand.exists() and cand.is_dir():
                try:
                    # Check if directory has at least one file (recursively)
                    has_files = any(f.is_file() for f in cand.rglob("*"))
                    if has_files:
                        return cand
                    if fallback_cand is None:
                        fallback_cand = cand
                except Exception:
                    if fallback_cand is None:
                        fallback_cand = cand

        return fallback_cand

    def migrate_saves(self, app_id: Optional[str] = None, copy_files: bool = True) -> SaveMigrationResult:
        """Finds scene saves, configures Goldberg identity, and copies save files without double-nesting."""
        config_info = self.detect_scene_config()
        detected_appid = app_id or config_info.get("app_id")
        account_name = config_info.get("account_name") or "Player"
        steam_id = config_info.get("steam_id")

        configured = self.configure_goldberg_identity(
            app_id=detected_appid,
            account_name=account_name,
            steam_id=steam_id,
        )

        migrated_files = []
        source_save_dir = None
        target_save_dir = None

        if detected_appid:
            source_save_dir = self.find_scene_save_directory(detected_appid)
            if source_save_dir and copy_files:
                target_base_dir = self.appdata / "Goldberg SteamEmu Saves" / detected_appid
                target_save_dir = target_base_dir / "remote"

                # Guard against SameFileError if source is already Goldberg target
                try:
                    s_res = source_save_dir.resolve()
                    if s_res in (target_base_dir.resolve(), target_save_dir.resolve()) or target_save_dir.resolve() in s_res.parents:
                        existing = [f.name for f in target_save_dir.glob("*") if f.is_file()] if target_save_dir.exists() else []
                        return SaveMigrationResult(
                            app_id=detected_appid,
                            account_name=account_name,
                            steam_id=steam_id,
                            config_source=config_info.get("source_file"),
                            goldberg_settings_configured=configured,
                            saves_found_at=str(source_save_dir),
                            saves_migrated_to=str(target_save_dir),
                            migrated_files=existing,
                        )
                except Exception:
                    pass

                try:
                    target_save_dir.mkdir(parents=True, exist_ok=True)

                    remote_sub = source_save_dir / "remote"
                    has_remote_sub = remote_sub.exists() and remote_sub.is_dir()
                    source_is_remote = source_save_dir.name.lower() == "remote"

                    # Recursively copy all save files, preventing nested remote/remote
                    for root, _, files in os.walk(source_save_dir):
                        for file in files:
                            src_file = Path(root) / file

                            if source_is_remote:
                                rel_path = src_file.relative_to(source_save_dir)
                                dst_file = target_save_dir / rel_path
                            elif has_remote_sub:
                                try:
                                    # If the file is inside the "remote" folder, map directly into target remote/
                                    rel_path = src_file.relative_to(remote_sub)
                                    dst_file = target_save_dir / rel_path
                                except ValueError:
                                    # File is outside "remote" folder (e.g. achievements or stats in appid root)
                                    rel_path = src_file.relative_to(source_save_dir)
                                    dst_file = target_base_dir / rel_path
                            else:
                                rel_path = src_file.relative_to(source_save_dir)
                                dst_file = target_save_dir / rel_path

                            dst_file.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copy2(src_file, dst_file)
                            migrated_files.append(str(rel_path))

                    # Self-healing: if an older buggy migration created target_save_dir/remote, un-nest it
                    buggy_nested = target_save_dir / "remote"
                    if buggy_nested.is_dir():
                        try:
                            for root, _, n_files in os.walk(buggy_nested):
                                for n_file in n_files:
                                    nested_src = Path(root) / n_file
                                    rel = nested_src.relative_to(buggy_nested)
                                    healed_dest = target_save_dir / rel
                                    healed_dest.parent.mkdir(parents=True, exist_ok=True)
                                    if not healed_dest.exists():
                                        shutil.move(str(nested_src), str(healed_dest))
                            shutil.rmtree(buggy_nested, ignore_errors=True)
                        except Exception:
                            pass
                except Exception:
                    pass

        return SaveMigrationResult(
            app_id=detected_appid,
            account_name=account_name,
            steam_id=steam_id,
            config_source=config_info.get("source_file"),
            goldberg_settings_configured=configured,
            saves_found_at=str(source_save_dir) if source_save_dir else None,
            saves_migrated_to=str(target_save_dir) if target_save_dir and migrated_files else None,
            migrated_files=migrated_files,
        )
