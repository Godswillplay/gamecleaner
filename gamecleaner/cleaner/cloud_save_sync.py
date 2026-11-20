"""
GameCleaner Universal Cloud Save Exporter & Importer.
Enables cross-platform save synchronization between Goldberg emulators, official Steam userdata,
scene cracks, and portable tools (Ludusavi, GameSave Manager, Steam Deck Proton compatdata).
Tracks sync state via standardized `.gc_save_meta.json` manifests.
"""
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import zipfile

# SteamID64 base offset for individual accounts in public universe (0x0110000100000000)
STEAM_ID64_BASE = 76561197960265728

# Standard metadata manifest filename
METADATA_FILENAME = ".gc_save_meta.json"


def steamid64_to_account_id(steamid64: Union[int, str]) -> int:
    """
    Converts a 64-bit SteamID64 into a 32-bit Steam AccountID.
    Example: 76561197972611406 -> 12345678
    """
    sid = int(str(steamid64).strip())
    if sid >= STEAM_ID64_BASE:
        return sid - STEAM_ID64_BASE
    return sid & 0xFFFFFFFF


def account_id_to_steamid64(account_id: Union[int, str]) -> int:
    """
    Converts a 32-bit Steam AccountID into a 64-bit SteamID64.
    Example: 12345678 -> 76561197972611406
    """
    aid = int(str(account_id).strip())
    if aid < STEAM_ID64_BASE:
        return aid + STEAM_ID64_BASE
    return aid


def calculate_file_hash(path: Path) -> str:
    """Calculates SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class CloudSaveMetadata:
    """Metadata recorded in .gc_save_meta.json tracking cloud save state."""

    appid: str
    game_title: str
    save_timestamp: str
    source_emulator: str
    account_id: Optional[str] = None
    steam_id64: Optional[str] = None
    file_count: int = 0
    total_size_bytes: int = 0
    files: List[Dict[str, Any]] = field(default_factory=list)
    target_compatdata_path: Optional[str] = None
    format_version: str = "1.0"
    created_by: str = "GameCleaner CloudSaveSync"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CloudSaveMetadata":
        return cls(
            appid=str(data.get("appid", "")),
            game_title=str(data.get("game_title", "Unknown Game")),
            save_timestamp=str(data.get("save_timestamp", "")),
            source_emulator=str(data.get("source_emulator", "Unknown")),
            account_id=str(data["account_id"]) if data.get("account_id") is not None else None,
            steam_id64=str(data["steam_id64"]) if data.get("steam_id64") is not None else None,
            file_count=int(data.get("file_count", 0)),
            total_size_bytes=int(data.get("total_size_bytes", 0)),
            files=data.get("files", []),
            target_compatdata_path=data.get("target_compatdata_path"),
            format_version=str(data.get("format_version", "1.0")),
            created_by=str(data.get("created_by", "GameCleaner CloudSaveSync")),
        )

    @classmethod
    def from_file(cls, path: Union[str, Path]) -> "CloudSaveMetadata":
        with open(path, "r", encoding="utf-8") as f:
            return cls.from_dict(json.load(f))

    def save_to_file(self, path: Union[str, Path]) -> None:
        p = Path(path).resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(self.to_json())


@dataclass
class ExportResult:
    """Result of a save export operation."""

    success: bool
    archive_path: Optional[str] = None
    format: str = "universal"
    file_count: int = 0
    total_size_bytes: int = 0
    metadata: Optional[CloudSaveMetadata] = None
    error_message: Optional[str] = None


@dataclass
class ImportResult:
    """Result of a save import operation."""

    success: bool
    source_path: str
    target_save_dir: str
    files_imported: List[str] = field(default_factory=list)
    appid: Optional[str] = None
    account_id: Optional[str] = None
    steam_id64: Optional[str] = None
    goldberg_configured: bool = False
    metadata: Optional[CloudSaveMetadata] = None
    error_message: Optional[str] = None


class CloudSaveSync:
    """
    Universal Save Game Exporter & Importer for Goldberg emulators,
    official Steam userdata, Ludusavi, GameSave Manager, and Steam Deck.
    """

    def __init__(
        self,
        appdata_dir: Optional[Union[str, Path]] = None,
        steam_userdata_dir: Optional[Union[str, Path]] = None,
    ) -> None:
        # Base AppData for Goldberg
        if appdata_dir:
            self.appdata = Path(appdata_dir).resolve()
        else:
            env_appdata = os.environ.get("APPDATA")
            if env_appdata:
                self.appdata = Path(env_appdata).resolve()
            else:
                self.appdata = (Path.home() / "AppData" / "Roaming").resolve()

        self.goldberg_saves_dir = self.appdata / "Goldberg SteamEmu Saves"

        # Steam userdata directory
        if steam_userdata_dir:
            self.steam_userdata = Path(steam_userdata_dir).resolve()
        else:
            self.steam_userdata = self._detect_steam_userdata()

    def _detect_steam_userdata(self) -> Path:
        """Detects the default Steam userdata path across standard Windows locations."""
        prog_files_x86 = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
        default_userdata = prog_files_x86 / "Steam" / "userdata"
        if default_userdata.exists():
            return default_userdata

        prog_files = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
        alt_userdata = prog_files / "Steam" / "userdata"
        if alt_userdata.exists():
            return alt_userdata

        return default_userdata

    def resolve_goldberg_save_dir(self, appid: str) -> Path:
        """Returns the standard Goldberg emulator save directory for an AppID."""
        return self.goldberg_saves_dir / str(appid).strip() / "remote"

    def export_save(
        self,
        source_save_dir: Union[str, Path],
        output_archive_path: Union[str, Path],
        appid: str,
        game_title: str = "Unknown Game",
        source_emulator: str = "Goldberg",
        export_format: str = "universal",
        account_id: Optional[Union[str, int]] = None,
        steam_id64: Optional[Union[str, int]] = None,
    ) -> ExportResult:
        """
        Exports save files to a standardized portable archive.

        Formats supported:
        - 'universal' / 'all': Multi-format archive compatible with Steam Deck, Ludusavi, and GSM.
        - 'steam_deck': Compatdata structure ready for Steam Deck (~/.local/share/Steam/steamapps/compatdata/...)
        - 'ludusavi': Ludusavi backup mapping structure.
        - 'gamesave_manager': GameSave Manager (.gsba / .zip) format.
        """
        src = Path(source_save_dir).resolve()
        if not src.exists():
            return ExportResult(
                success=False,
                error_message=f"Source save directory does not exist: {src}",
            )

        appid_str = str(appid).strip()
        out_archive = Path(output_archive_path).resolve()
        out_archive.parent.mkdir(parents=True, exist_ok=True)

        # Normalize AccountID and SteamID64
        acc_id_str: Optional[str] = None
        sid64_str: Optional[str] = None
        if account_id is not None:
            acc_id_str = str(account_id).strip()
            sid64_str = str(account_id_to_steamid64(acc_id_str))
        elif steam_id64 is not None:
            sid64_str = str(steam_id64).strip()
            acc_id_str = str(steamid64_to_account_id(sid64_str))

        # Collect save files
        save_files: List[Tuple[Path, str]] = []  # (absolute_file_path, relative_save_path)
        if src.is_file():
            save_files.append((src, src.name))
        else:
            # If src has a 'remote' subfolder, use remote as relative base if files reside in remote
            remote_sub = src / "remote"
            base_dir = remote_sub if (remote_sub.exists() and remote_sub.is_dir() and any(remote_sub.iterdir())) else src

            for root, _, files in os.walk(base_dir):
                for f in files:
                    # Skip metadata files from being re-archived as raw save data
                    if f == METADATA_FILENAME or f.endswith(".tmp"):
                        continue
                    full_p = Path(root) / f
                    rel_p = str(full_p.relative_to(base_dir)).replace("\\", "/")
                    save_files.append((full_p, rel_p))

        if not save_files:
            return ExportResult(
                success=False,
                error_message=f"No save files found in source directory: {src}",
            )

        # Build file manifest records and calculate total size
        manifest_records: List[Dict[str, Any]] = []
        total_size = 0
        timestamp = datetime.now(timezone.utc).isoformat()

        for full_p, rel_p in save_files:
            sz = full_p.stat().st_size
            total_size += sz
            sha = calculate_file_hash(full_p)
            manifest_records.append({
                "relative_path": rel_p,
                "size_bytes": sz,
                "sha256": sha,
            })

        deck_proton_path = f"compatdata/{appid_str}/pfx/drive_c/users/steamuser/AppData/Roaming/Goldberg SteamEmu Saves/{appid_str}/remote"

        metadata = CloudSaveMetadata(
            appid=appid_str,
            game_title=game_title,
            save_timestamp=timestamp,
            source_emulator=source_emulator,
            account_id=acc_id_str,
            steam_id64=sid64_str,
            file_count=len(save_files),
            total_size_bytes=total_size,
            files=manifest_records,
            target_compatdata_path=deck_proton_path,
        )

        fmt = export_format.lower()

        # Build portable ZIP archive
        try:
            with zipfile.ZipFile(out_archive, "w", zipfile.ZIP_DEFLATED) as zf:
                # 1. Always write .gc_save_meta.json at archive root
                zf.writestr(METADATA_FILENAME, metadata.to_json())

                # 2. Universal / standard save files
                for full_p, rel_p in save_files:
                    # Standard root saves path
                    zf.write(full_p, arcname=f"remote/{rel_p}")
                    zf.write(full_p, arcname=f"saves/{rel_p}")

                # 3. Steam Deck direct transfer compatdata structure
                if fmt in ("universal", "all", "steam_deck"):
                    for full_p, rel_p in save_files:
                        deck_arcname = f"{deck_proton_path}/{rel_p}"
                        zf.write(full_p, arcname=deck_arcname)

                    # Include automated POSIX deploy helper script
                    deploy_script = self._generate_deck_deploy_script(appid_str, metadata)
                    zf.writestr("deploy_to_deck.sh", deploy_script)

                # 4. Ludusavi format compatibility
                if fmt in ("universal", "all", "ludusavi"):
                    ludusavi_manifest = {
                        "game": game_title,
                        "appid": appid_str,
                        "backup_timestamp": timestamp,
                        "files": {
                            rec["relative_path"]: {
                                "hash": rec["sha256"],
                                "size": rec["size_bytes"],
                            }
                            for rec in manifest_records
                        },
                    }
                    zf.writestr("ludusavi_manifest.json", json.dumps(ludusavi_manifest, indent=2))
                    for full_p, rel_p in save_files:
                        zf.write(full_p, arcname=f"{game_title}/saves/{rel_p}")

                # 5. GameSave Manager format compatibility
                if fmt in ("universal", "all", "gamesave_manager"):
                    gsm_info = (
                        f"[GameSave Manager]\n"
                        f"GameTitle={game_title}\n"
                        f"AppID={appid_str}\n"
                        f"Timestamp={timestamp}\n"
                        f"TargetDirectory=%APPDATA%\\Goldberg SteamEmu Saves\\{appid_str}\\remote\n"
                    )
                    zf.writestr("gsm_info.txt", gsm_info)

            # Also write metadata into source directory if it's a directory
            if src.is_dir():
                try:
                    meta_out = src / METADATA_FILENAME
                    metadata.save_to_file(meta_out)
                except Exception:
                    pass

            return ExportResult(
                success=True,
                archive_path=str(out_archive),
                format=fmt,
                file_count=len(save_files),
                total_size_bytes=total_size,
                metadata=metadata,
            )
        except Exception as e:
            return ExportResult(
                success=False,
                error_message=f"Failed to create save archive: {e}",
            )

    def export_to_steam_deck_archive(
        self,
        source_save_dir: Union[str, Path],
        output_archive_path: Union[str, Path],
        appid: str,
        game_title: str = "Unknown Game",
        account_id: Optional[Union[str, int]] = None,
        steam_id64: Optional[Union[str, int]] = None,
    ) -> ExportResult:
        """Convenience method for direct Steam Deck compatdata export."""
        return self.export_save(
            source_save_dir=source_save_dir,
            output_archive_path=output_archive_path,
            appid=appid,
            game_title=game_title,
            export_format="steam_deck",
            account_id=account_id,
            steam_id64=steam_id64,
        )

    def export_to_ludusavi_archive(
        self,
        source_save_dir: Union[str, Path],
        output_archive_path: Union[str, Path],
        appid: str,
        game_title: str = "Unknown Game",
    ) -> ExportResult:
        """Convenience method for Ludusavi portable export."""
        return self.export_save(
            source_save_dir=source_save_dir,
            output_archive_path=output_archive_path,
            appid=appid,
            game_title=game_title,
            export_format="ludusavi",
        )

    def export_to_gamesave_manager_archive(
        self,
        source_save_dir: Union[str, Path],
        output_archive_path: Union[str, Path],
        appid: str,
        game_title: str = "Unknown Game",
    ) -> ExportResult:
        """Convenience method for GameSave Manager (.gsba) portable export."""
        return self.export_save(
            source_save_dir=source_save_dir,
            output_archive_path=output_archive_path,
            appid=appid,
            game_title=game_title,
            export_format="gamesave_manager",
        )

    def export_game(
        self,
        game_dir: Union[str, Path],
        output_archive_path: Optional[Union[str, Path]] = None,
        appid: Optional[str] = None,
    ) -> ExportResult:
        """Convenience method to export saves for a game directory."""
        gdir = Path(game_dir).resolve()
        appid_str = str(appid).strip() if appid else None
        if not appid_str:
            appid_p = gdir / "steam_appid.txt"
            if appid_p.exists():
                try:
                    appid_str = appid_p.read_text(encoding="utf-8").strip().splitlines()[0].strip()
                except Exception:
                    pass
        if not appid_str:
            appid_str = "480"

        goldberg_root = Path(os.environ.get("APPDATA", "")) / "Goldberg SteamEmu Saves" / appid_str
        save_dir = goldberg_root if goldberg_root.exists() else gdir

        if not output_archive_path:
            output_archive_path = gdir / f"{gdir.name}_saves_{appid_str}.zip"

        return self.export_save(
            source_save_dir=save_dir,
            output_archive_path=output_archive_path,
            appid=appid_str,
            game_title=gdir.name,
        )

    def import_steam_save(
        self,
        steam_userdata_path: Union[str, Path],
        appid: Optional[str] = None,
        target_goldberg_base: Optional[Union[str, Path]] = None,
        game_dir: Optional[Union[str, Path]] = None,
        custom_account_id: Optional[Union[str, int]] = None,
        custom_game_title: str = "Official Steam Import",
    ) -> ImportResult:
        """
        Imports official Steam save files (userdata/<AccountID>/<AppID>) into
        Goldberg local emulator format, mapping SteamID64 to Goldberg account structure.
        """
        src = Path(steam_userdata_path).resolve()
        if not src.exists():
            return ImportResult(
                success=False,
                source_path=str(src),
                target_save_dir="",
                error_message=f"Steam userdata path does not exist: {src}",
            )

        # Infer AccountID and AppID from directory path if not explicitly provided
        # Pattern: userdata/<AccountID>/<AppID> or userdata/<AccountID>/<AppID>/remote
        norm_path = str(src).replace("\\", "/")
        detected_account_id = str(custom_account_id) if custom_account_id else None
        detected_appid = str(appid).strip() if appid else None

        m = re.search(r"userdata/(\d+)/(\d+)", norm_path, re.IGNORECASE)
        if m:
            if not detected_account_id:
                detected_account_id = m.group(1)
            if not detected_appid:
                detected_appid = m.group(2)

        if not detected_appid:
            # Check if directory name is numerical AppID
            if src.name.isdigit():
                detected_appid = src.name
            elif src.parent.name.isdigit() and src.name.lower() == "remote":
                detected_appid = src.parent.name

        if not detected_appid:
            return ImportResult(
                success=False,
                source_path=str(src),
                target_save_dir="",
                error_message="Could not resolve Steam AppID from userdata path or arguments.",
            )

        # Convert AccountID to SteamID64
        steam_id64_val: Optional[int] = None
        if detected_account_id:
            steam_id64_val = account_id_to_steamid64(detected_account_id)
        else:
            # Default fallback SteamID64 if account id could not be deduced
            steam_id64_val = STEAM_ID64_BASE + 1

        # Locate save files in source
        remote_dir = src / "remote"
        effective_src = remote_dir if (remote_dir.exists() and remote_dir.is_dir()) else src

        source_files: List[Tuple[Path, str]] = []
        for root, _, files in os.walk(effective_src):
            for f in files:
                if f.lower() in ("remotecache.vdf", METADATA_FILENAME):
                    continue
                fp = Path(root) / f
                rel_p = str(fp.relative_to(effective_src)).replace("\\", "/")
                source_files.append((fp, rel_p))

        if not source_files:
            return ImportResult(
                success=False,
                source_path=str(src),
                target_save_dir="",
                appid=detected_appid,
                account_id=detected_account_id,
                error_message=f"No save game files discovered inside {src}",
            )

        # Determine Goldberg target save folder
        if target_goldberg_base:
            base_gb = Path(target_goldberg_base).resolve()
        else:
            base_gb = self.goldberg_saves_dir

        target_remote_dir = base_gb / detected_appid / "remote"
        target_remote_dir.mkdir(parents=True, exist_ok=True)

        imported_files: List[str] = []
        manifest_records: List[Dict[str, Any]] = []
        total_size = 0

        for full_p, rel_p in source_files:
            dest_file = target_remote_dir / Path(rel_p)
            dest_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(full_p, dest_file)
            imported_files.append(rel_p)

            sz = dest_file.stat().st_size
            total_size += sz
            sha = calculate_file_hash(dest_file)
            manifest_records.append({
                "relative_path": rel_p,
                "size_bytes": sz,
                "sha256": sha,
            })

        # Configure Goldberg Steam identity in game directory if game_dir is provided
        goldberg_configured = False
        if game_dir:
            try:
                g_dir = Path(game_dir).resolve()
                g_settings = g_dir / "steam_settings"
                g_settings.mkdir(parents=True, exist_ok=True)

                if steam_id64_val:
                    (g_settings / "user_steam_id.txt").write_text(str(steam_id64_val), encoding="utf-8")
                (g_settings / "steam_appid.txt").write_text(detected_appid, encoding="utf-8")
                (g_dir / "steam_appid.txt").write_text(detected_appid, encoding="utf-8")

                # Mirror identity to common game bin folders
                for bin_sub in ("bin", "bin/x64", "bin/x86", "Binaries/Win64"):
                    s_bin = g_dir / bin_sub
                    if s_bin.exists() and s_bin.is_dir():
                        s_sub = s_bin / "steam_settings"
                        s_sub.mkdir(parents=True, exist_ok=True)
                        if steam_id64_val:
                            (s_sub / "user_steam_id.txt").write_text(str(steam_id64_val), encoding="utf-8")
                        (s_sub / "steam_appid.txt").write_text(detected_appid, encoding="utf-8")
                        (s_bin / "steam_appid.txt").write_text(detected_appid, encoding="utf-8")

                goldberg_configured = True
            except Exception:
                goldberg_configured = False

        # Generate and save metadata manifest in Goldberg AppID root
        meta = CloudSaveMetadata(
            appid=detected_appid,
            game_title=custom_game_title,
            save_timestamp=datetime.now(timezone.utc).isoformat(),
            source_emulator="Official Steam",
            account_id=detected_account_id,
            steam_id64=str(steam_id64_val) if steam_id64_val else None,
            file_count=len(imported_files),
            total_size_bytes=total_size,
            files=manifest_records,
            target_compatdata_path=f"compatdata/{detected_appid}/pfx/drive_c/users/steamuser/AppData/Roaming/Goldberg SteamEmu Saves/{detected_appid}/remote",
        )

        meta_path = base_gb / detected_appid / METADATA_FILENAME
        try:
            meta.save_to_file(meta_path)
        except Exception:
            pass

        return ImportResult(
            success=True,
            source_path=str(src),
            target_save_dir=str(target_remote_dir),
            files_imported=imported_files,
            appid=detected_appid,
            account_id=detected_account_id,
            steam_id64=str(steam_id64_val) if steam_id64_val else None,
            goldberg_configured=goldberg_configured,
            metadata=meta,
        )

    def import_portable_archive(
        self,
        archive_path: Union[str, Path],
        target_goldberg_base: Optional[Union[str, Path]] = None,
        game_dir: Optional[Union[str, Path]] = None,
        override_appid: Optional[str] = None,
    ) -> ImportResult:
        """
        Imports save game files from a standardized portable archive (.zip)
        into the Goldberg emulator save structure.
        """
        arc = Path(archive_path).resolve()
        if not arc.exists() or not zipfile.is_zipfile(arc):
            return ImportResult(
                success=False,
                source_path=str(arc),
                target_save_dir="",
                error_message=f"Archive file does not exist or is not a valid zip: {arc}",
            )

        try:
            with zipfile.ZipFile(arc, "r") as zf:
                # 1. Read metadata manifest if present
                meta: Optional[CloudSaveMetadata] = None
                if METADATA_FILENAME in zf.namelist():
                    meta_raw = zf.read(METADATA_FILENAME).decode("utf-8")
                    meta = CloudSaveMetadata.from_dict(json.loads(meta_raw))

                appid = override_appid or (meta.appid if meta else None)
                if not appid:
                    # Look for AppID in file paths inside archive
                    for name in zf.namelist():
                        m = re.search(r"Goldberg SteamEmu Saves/(\d+)/", name)
                        if m:
                            appid = m.group(1)
                            break
                        m2 = re.search(r"compatdata/(\d+)/", name)
                        if m2:
                            appid = m2.group(1)
                            break

                if not appid:
                    return ImportResult(
                        success=False,
                        source_path=str(arc),
                        target_save_dir="",
                        error_message="Could not resolve Steam AppID from archive metadata.",
                    )

                base_gb = Path(target_goldberg_base).resolve() if target_goldberg_base else self.goldberg_saves_dir
                target_remote_dir = base_gb / appid / "remote"
                target_remote_dir.mkdir(parents=True, exist_ok=True)

                # Determine which prefix inside archive holds save files
                imported_files: List[str] = []
                names = zf.namelist()

                # Preference order for archive prefixes:
                # 1) remote/
                # 2) saves/
                # 3) compatdata/.../remote/
                # 4) root level files
                prefix_to_use = None
                if any(n.startswith("remote/") and not n.endswith("/") for n in names):
                    prefix_to_use = "remote/"
                elif any(n.startswith("saves/") and not n.endswith("/") for n in names):
                    prefix_to_use = "saves/"
                else:
                    for n in names:
                        if "Goldberg SteamEmu Saves" in n and "/remote/" in n and not n.endswith("/"):
                            prefix_to_use = n[: n.index("/remote/") + len("/remote/")]
                            break

                for n in names:
                    if n.endswith("/") or n == METADATA_FILENAME or n.endswith(".sh") or n.endswith(".txt") or n.endswith(".json"):
                        # If prefix is defined and this file is under prefix, process it
                        if not prefix_to_use or not n.startswith(prefix_to_use):
                            continue

                    if prefix_to_use and n.startswith(prefix_to_use):
                        rel_p = n[len(prefix_to_use):]
                    else:
                        if prefix_to_use:
                            continue
                        rel_p = n

                    if not rel_p:
                        continue

                    dest = target_remote_dir / Path(rel_p)
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(n) as src_f, open(dest, "wb") as dst_f:
                        shutil.copyfileobj(src_f, dst_f)
                    imported_files.append(rel_p)

                # Configure Goldberg identity in game_dir if requested
                goldberg_configured = False
                steam_id64_val = meta.steam_id64 if meta else None
                if game_dir:
                    try:
                        g_dir = Path(game_dir).resolve()
                        g_settings = g_dir / "steam_settings"
                        g_settings.mkdir(parents=True, exist_ok=True)
                        if steam_id64_val:
                            (g_settings / "user_steam_id.txt").write_text(str(steam_id64_val), encoding="utf-8")
                        (g_settings / "steam_appid.txt").write_text(appid, encoding="utf-8")
                        (g_dir / "steam_appid.txt").write_text(appid, encoding="utf-8")
                        goldberg_configured = True
                    except Exception:
                        goldberg_configured = False

                # Stamp metadata into destination folder
                if meta:
                    meta.save_to_file(base_gb / appid / METADATA_FILENAME)

                return ImportResult(
                    success=True,
                    source_path=str(arc),
                    target_save_dir=str(target_remote_dir),
                    files_imported=imported_files,
                    appid=appid,
                    account_id=meta.account_id if meta else None,
                    steam_id64=steam_id64_val,
                    goldberg_configured=goldberg_configured,
                    metadata=meta,
                )
        except Exception as e:
            return ImportResult(
                success=False,
                source_path=str(arc),
                target_save_dir="",
                error_message=f"Failed to extract portable archive: {e}",
            )

    def find_official_steam_saves(self, appid: Optional[str] = None) -> List[Dict[str, Any]]:
        """Discovers official Steam save folders in Steam/userdata."""
        results: List[Dict[str, Any]] = []
        if not self.steam_userdata.exists():
            return results

        appid_filter = str(appid).strip() if appid else None

        try:
            for account_dir in self.steam_userdata.iterdir():
                if not account_dir.is_dir() or not account_dir.name.isdigit():
                    continue

                account_id = account_dir.name
                sid64 = account_id_to_steamid64(account_id)

                for app_dir in account_dir.iterdir():
                    if not app_dir.is_dir() or not app_dir.name.isdigit():
                        continue

                    cur_appid = app_dir.name
                    if appid_filter and cur_appid != appid_filter:
                        continue

                    # Check for files in app_dir or app_dir/remote
                    file_count = 0
                    total_bytes = 0
                    for root, _, files in os.walk(app_dir):
                        for f in files:
                            if f.lower() != "remotecache.vdf":
                                file_count += 1
                                try:
                                    total_bytes += (Path(root) / f).stat().st_size
                                except Exception:
                                    pass

                    if file_count > 0:
                        results.append({
                            "appid": cur_appid,
                            "account_id": account_id,
                            "steam_id64": str(sid64),
                            "save_path": str(app_dir),
                            "remote_path": str(app_dir / "remote") if (app_dir / "remote").exists() else str(app_dir),
                            "file_count": file_count,
                            "size_bytes": total_bytes,
                        })
        except Exception:
            pass

        return results

    def find_goldberg_saves(self, appid: Optional[str] = None) -> List[Dict[str, Any]]:
        """Discovers active Goldberg emulator saves in %APPDATA%/Goldberg SteamEmu Saves."""
        results: List[Dict[str, Any]] = []
        if not self.goldberg_saves_dir.exists():
            return results

        appid_filter = str(appid).strip() if appid else None

        try:
            for item in self.goldberg_saves_dir.iterdir():
                if not item.is_dir() or not item.name.isdigit():
                    continue

                cur_appid = item.name
                if appid_filter and cur_appid != appid_filter:
                    continue

                # Check for files
                file_count = 0
                total_bytes = 0
                for root, _, files in os.walk(item):
                    for f in files:
                        if f != METADATA_FILENAME:
                            file_count += 1
                            try:
                                total_bytes += (Path(root) / f).stat().st_size
                            except Exception:
                                pass

                meta_path = item / METADATA_FILENAME
                meta_loaded = None
                if meta_path.exists():
                    try:
                        meta_loaded = CloudSaveMetadata.from_file(meta_path)
                    except Exception:
                        pass

                results.append({
                    "appid": cur_appid,
                    "save_dir": str(item / "remote" if (item / "remote").exists() else item),
                    "file_count": file_count,
                    "size_bytes": total_bytes,
                    "metadata": meta_loaded.to_dict() if meta_loaded else None,
                })
        except Exception:
            pass

        return results

    @staticmethod
    def _generate_deck_deploy_script(appid: str, metadata: CloudSaveMetadata) -> str:
        """Generates POSIX shell deployment script for Steam Deck users."""
        return f"""#!/usr/bin/env bash
# GameCleaner Steam Deck Save Importer
# AppID: {appid} - Title: {metadata.game_title}
# Deploys save files into the Steam Deck Proton compatdata prefix.

set -euo pipefail

APPID="{appid}"
STEAM_COMPAT_DIR="${{HOME}}/.local/share/Steam/steamapps/compatdata/${{APPID}}/pfx/drive_c/users/steamuser/AppData/Roaming/Goldberg SteamEmu Saves/${{APPID}}/remote"

echo "[*] Deploying Goldberg save games for AppID ${{APPID}}..."
mkdir -p "${{STEAM_COMPAT_DIR}}"

SCRIPT_DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"
SOURCE_SAVES="${{SCRIPT_DIR}}/remote"

if [ ! -d "${{SOURCE_SAVES}}" ]; then
    SOURCE_SAVES="${{SCRIPT_DIR}}/saves"
fi

if [ -d "${{SOURCE_SAVES}}" ]; then
    cp -r "${{SOURCE_SAVES}}/"* "${{STEAM_COMPAT_DIR}}/"
    echo "[+] Saves successfully copied to: ${{STEAM_COMPAT_DIR}}"
else
    echo "[!] Save directory not found in archive."
    exit 1
fi
"""
