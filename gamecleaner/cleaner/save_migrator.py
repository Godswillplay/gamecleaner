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
        "valve.ini",
        "creamapi.ini",
        "saves.ini",
    ]

    def __init__(self, game_dir: Path):
        self.game_dir = Path(game_dir).resolve()
        self.appdata = Path(os.environ.get("APPDATA", "C:\\Users\\Default\\AppData\\Roaming"))
        self.localappdata = Path(os.environ.get("LOCALAPPDATA", "C:\\Users\\Default\\AppData\\Local"))
        self.public_docs = Path(os.environ.get("PUBLIC", "C:\\Users\\Public")) / "Documents"

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
                content = appid_txt.read_text(encoding="utf-8", errors="ignore").strip()
                if content.isdigit():
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

                        # Extract AppId
                        if not info["app_id"]:
                            m = re.search(r"^\s*(?:AppId|appid|TargetAppId)\s*=\s*(\d+)", content, re.MULTILINE | re.IGNORECASE)
                            if m:
                                info["app_id"] = m.group(1).strip()

                        # Extract Account Name / PersonaName
                        if not info["account_name"]:
                            m = re.search(r"^\s*(?:PersonaName|AccountIdName|UserName|AccountName)\s*=\s*(.+)", content, re.MULTILINE | re.IGNORECASE)
                            if m:
                                info["account_name"] = m.group(1).strip()

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
        """Configures Goldberg Steam emulator identity files in steam_settings directory."""
        steam_settings = self.game_dir / "steam_settings"
        try:
            steam_settings.mkdir(parents=True, exist_ok=True)

            if account_name:
                (steam_settings / "account_name.txt").write_text(account_name, encoding="utf-8")

            if steam_id:
                (steam_settings / "user_steam_id.txt").write_text(steam_id, encoding="utf-8")

            if app_id:
                (self.game_dir / "steam_appid.txt").write_text(app_id, encoding="utf-8")

            return True
        except Exception:
            return False

    def find_scene_save_directory(self, app_id: str) -> Optional[Path]:
        """Locates scene save files in standard Windows locations."""
        if not app_id:
            return None

        candidates = [
            # CODEX in AppData Roaming
            self.appdata / "Steam" / "CODEX" / app_id,
            self.appdata / "Roaming" / "Steam" / "CODEX" / app_id,
            # CODEX in Public Documents
            self.public_docs / "Steam" / "CODEX" / app_id,
            # RUNE in LocalAppData
            self.localappdata / "Rabinoviche" / "Rune" / app_id,
            # RUNE in Public Documents
            self.public_docs / "Steam" / "RUNE" / app_id,
            # FLT in AppData
            self.appdata / "FLT" / app_id,
        ]

        for cand in candidates:
            if cand.exists() and cand.is_dir():
                return cand

        return None

    def migrate_saves(self, app_id: Optional[str] = None, copy_files: bool = True) -> SaveMigrationResult:
        """Finds scene saves, configures Goldberg identity, and copies save files to Goldberg directory."""
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
                target_save_dir = self.appdata / "Goldberg SteamEmu Saves" / detected_appid / "remote"
                try:
                    target_save_dir.mkdir(parents=True, exist_ok=True)
                    # Recursively copy all save files
                    for root, _, files in os.walk(source_save_dir):
                        for file in files:
                            src_file = Path(root) / file
                            rel_path = src_file.relative_to(source_save_dir)
                            dst_file = target_save_dir / rel_path
                            dst_file.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copy2(src_file, dst_file)
                            migrated_files.append(str(rel_path))
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
