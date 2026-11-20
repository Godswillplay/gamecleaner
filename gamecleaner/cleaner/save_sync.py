"""
Goldberg Steam Emulator Save Game State Preservation & Snapshot Manager.
Provides automated versioned point-in-time snapshots (.zip archives) of active save files
in %APPDATA%/Goldberg SteamEmu Saves/ before and after gameplay sessions, enabling
anti-corruption backups, state preservation, and safe rollbacks.
"""
from dataclasses import asdict, dataclass
from datetime import datetime
import json
import os
from pathlib import Path
import re
import shutil
from typing import Dict, List, Optional, Union
import zipfile


@dataclass
class SnapshotRecord:
    """Metadata record for a single game save snapshot."""

    snapshot_filename: str
    appid: str
    timestamp: str
    note: str
    file_count: int
    size_bytes: int
    full_path: str
    save_source_dir: Optional[str] = None
    created_at: Optional[str] = None


@dataclass
class SnapshotResult:
    """Result of a save snapshot creation operation."""

    success: bool
    snapshot_path: Optional[str] = None
    snapshot_record: Optional[SnapshotRecord] = None
    error_message: Optional[str] = None
    files_archived: int = 0
    size_bytes: int = 0


class SaveSyncManager:
    """Manages versioned save snapshots for Goldberg Steam Emulator saves."""

    MANIFEST_FILENAME = "manifest.json"
    SNAPSHOTS_DIR_NAME = ".gamecleaner_saves"

    def __init__(self, appdata_dir: Optional[Union[str, Path]] = None) -> None:
        """Initializes the save sync manager.

        Args:
            appdata_dir: Custom AppData directory (defaults to %APPDATA%).
        """
        if appdata_dir:
            self.appdata = Path(appdata_dir).resolve()
        else:
            env_appdata = os.environ.get("APPDATA")
            if env_appdata:
                self.appdata = Path(env_appdata).resolve()
            else:
                self.appdata = (Path.home() / "AppData" / "Roaming").resolve()

        self.goldberg_base_dir = self.appdata / "Goldberg SteamEmu Saves"

    def resolve_goldberg_save_path(self, appid: Optional[str] = None) -> Path:
        """Resolves the Goldberg save path.

        Checks:
        1. %APPDATA%/Goldberg SteamEmu Saves/<AppID>/
        2. %APPDATA%/Goldberg SteamEmu Saves/

        Args:
            appid: Steam AppID (optional).

        Returns:
            Resolved Path to Goldberg save folder.
        """
        if appid:
            appid_str = str(appid).strip()
            appid_dir = self.goldberg_base_dir / appid_str
            if appid_dir.exists():
                return appid_dir

        if self.goldberg_base_dir.exists():
            # Check if root contains save files or directories directly
            try:
                has_direct_files = any(f.is_file() for f in self.goldberg_base_dir.iterdir())
                if has_direct_files or not appid:
                    return self.goldberg_base_dir
            except Exception:
                pass

        # If AppID provided, return the AppID specific path
        if appid:
            return self.goldberg_base_dir / str(appid).strip()
        return self.goldberg_base_dir

    def _get_snapshots_dir(self, game_dir: Union[str, Path]) -> Path:
        """Returns the .gamecleaner_saves directory for a game."""
        return Path(game_dir).resolve() / self.SNAPSHOTS_DIR_NAME

    def _load_manifest(self, snapshots_dir: Path) -> List[Dict]:
        """Loads snapshot records from manifest.json."""
        manifest_file = snapshots_dir / self.MANIFEST_FILENAME
        if not manifest_file.exists():
            return []
        try:
            data = json.loads(manifest_file.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return data
            elif isinstance(data, dict) and "snapshots" in data:
                return data["snapshots"]
        except Exception:
            pass
        return []

    def _save_manifest(self, snapshots_dir: Path, records: List[Dict]) -> None:
        """Writes snapshot records to manifest.json."""
        snapshots_dir.mkdir(parents=True, exist_ok=True)
        manifest_file = snapshots_dir / self.MANIFEST_FILENAME
        payload = {
            "version": 1,
            "updated_at": datetime.now().isoformat(),
            "snapshots": records,
        }
        manifest_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def create_snapshot(
        self,
        game_dir: Union[str, Path],
        appid: str,
        note: str = "Pre-launch snapshot",
    ) -> SnapshotResult:
        """Compresses active Goldberg save files into a versioned timestamped .zip snapshot.

        Destination: <game_dir>/.gamecleaner_saves/save_snapshot_<appid>_<timestamp>.zip
        Metadata: <game_dir>/.gamecleaner_saves/manifest.json

        Args:
            game_dir: Path to game root directory.
            appid: Steam AppID for the game.
            note: Human-readable note or trigger (e.g. 'Pre-launch', 'Post-session').

        Returns:
            SnapshotResult with success status, path, and record.
        """
        if not appid:
            return SnapshotResult(
                success=False,
                error_message="Cannot create save snapshot: Steam AppID is required.",
            )

        g_dir = Path(game_dir).resolve()
        if not g_dir.exists():
            return SnapshotResult(
                success=False,
                error_message=f"Game directory does not exist: {g_dir}",
            )

        # 1. Locate active save files
        save_dir = self.resolve_goldberg_save_path(appid)
        if not save_dir.exists():
            # Check if saves are at root goldberg folder instead
            if self.goldberg_base_dir.exists() and any(self.goldberg_base_dir.rglob("*")):
                save_dir = self.goldberg_base_dir
            else:
                return SnapshotResult(
                    success=False,
                    error_message=f"Goldberg save directory does not exist for AppID {appid} at: {save_dir}",
                )

        save_files: List[Path] = [p for p in save_dir.rglob("*") if p.is_file()]
        if not save_files:
            return SnapshotResult(
                success=False,
                error_message=f"No save files found to snapshot in: {save_dir}",
            )

        # 2. Prepare snapshots directory
        snapshots_dir = self._get_snapshots_dir(g_dir)
        snapshots_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        zip_filename = f"save_snapshot_{appid}_{timestamp}.zip"
        zip_path = snapshots_dir / zip_filename

        # 3. Create zip archive
        try:
            with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                for sf in save_files:
                    arcname = str(sf.relative_to(save_dir))
                    zf.write(sf, arcname=arcname)
            size_bytes = zip_path.stat().st_size
        except Exception as e:
            if zip_path.exists():
                try:
                    zip_path.unlink()
                except Exception:
                    pass
            return SnapshotResult(
                success=False,
                error_message=f"Failed to compress save files into snapshot zip: {e}",
            )

        # 4. Create and save snapshot record
        record = SnapshotRecord(
            snapshot_filename=zip_filename,
            appid=str(appid),
            timestamp=timestamp,
            note=note,
            file_count=len(save_files),
            size_bytes=size_bytes,
            full_path=str(zip_path),
            save_source_dir=str(save_dir),
            created_at=datetime.now().isoformat(),
        )

        existing_manifest = self._load_manifest(snapshots_dir)
        # Prepend so newest is first
        existing_manifest.insert(0, asdict(record))
        try:
            self._save_manifest(snapshots_dir, existing_manifest)
        except Exception:
            pass

        return SnapshotResult(
            success=True,
            snapshot_path=str(zip_path),
            snapshot_record=record,
            files_archived=len(save_files),
            size_bytes=size_bytes,
        )

    def list_snapshots(self, game_dir: Union[str, Path]) -> List[SnapshotRecord]:
        """Lists all available save snapshots for a game, ordered from newest to oldest.

        Args:
            game_dir: Path to game root directory.

        Returns:
            List of SnapshotRecord instances.
        """
        snapshots_dir = self._get_snapshots_dir(game_dir)
        if not snapshots_dir.exists():
            return []

        manifest_entries = self._load_manifest(snapshots_dir)
        records: List[SnapshotRecord] = []
        known_filenames = set()

        # Parse records from manifest
        for item in manifest_entries:
            try:
                fn = item.get("snapshot_filename")
                if not fn:
                    continue
                full_path = snapshots_dir / fn
                if not full_path.is_file():
                    continue

                rec = SnapshotRecord(
                    snapshot_filename=fn,
                    appid=str(item.get("appid", "")),
                    timestamp=str(item.get("timestamp", "")),
                    note=str(item.get("note", "")),
                    file_count=int(item.get("file_count", 0)),
                    size_bytes=int(item.get("size_bytes", full_path.stat().st_size)),
                    full_path=str(full_path),
                    save_source_dir=item.get("save_source_dir"),
                    created_at=item.get("created_at"),
                )
                records.append(rec)
                known_filenames.add(fn)
            except Exception:
                continue

        # Reconcile any orphan zip files on disk not registered in manifest
        for zip_file in snapshots_dir.glob("save_snapshot_*.zip"):
            if zip_file.name not in known_filenames and zip_file.is_file():
                try:
                    appid_match = re.match(r"^save_snapshot_([^_]+)_(\d{8}_\d{6})\.zip$", zip_file.name)
                    appid = appid_match.group(1) if appid_match else "unknown"
                    ts = appid_match.group(2) if appid_match else ""

                    count = 0
                    with zipfile.ZipFile(zip_file, "r") as zf:
                        count = len([m for m in zf.infolist() if not m.is_dir()])

                    rec = SnapshotRecord(
                        snapshot_filename=zip_file.name,
                        appid=appid,
                        timestamp=ts,
                        note="Discovered snapshot",
                        file_count=count,
                        size_bytes=zip_file.stat().st_size,
                        full_path=str(zip_file),
                        save_source_dir=str(self.resolve_goldberg_save_path(appid)),
                        created_at=datetime.fromtimestamp(zip_file.stat().st_mtime).isoformat(),
                    )
                    records.append(rec)
                except Exception:
                    continue

        # Sort by timestamp descending
        records.sort(key=lambda r: r.timestamp or r.created_at or "", reverse=True)
        return records

    def restore_snapshot(
        self,
        game_dir: Union[str, Path],
        snapshot_filename: str,
    ) -> bool:
        """Safely restores the requested snapshot zip back into the Goldberg save location.

        Guards against zip-slip directory traversal vulnerabilities.

        Args:
            game_dir: Path to game root directory.
            snapshot_filename: Basename or path of snapshot .zip to restore.

        Returns:
            True if snapshot was restored successfully, False otherwise.
        """
        snapshots_dir = self._get_snapshots_dir(game_dir)

        # 1. Locate zip file
        target_zip: Optional[Path] = None
        cand_direct = Path(snapshot_filename)
        if cand_direct.is_file():
            target_zip = cand_direct.resolve()
        elif (snapshots_dir / snapshot_filename).is_file():
            target_zip = (snapshots_dir / snapshot_filename).resolve()
        elif (snapshots_dir / f"{snapshot_filename}.zip").is_file():
            target_zip = (snapshots_dir / f"{snapshot_filename}.zip").resolve()
        else:
            # Match by substring or filename
            for z in snapshots_dir.glob("*.zip"):
                if snapshot_filename.lower() in z.name.lower():
                    target_zip = z.resolve()
                    break

        if not target_zip or not target_zip.is_file():
            return False

        # 2. Determine target save location
        target_save_dir: Optional[Path] = None

        # Check manifest records first
        manifest_entries = self._load_manifest(snapshots_dir)
        matched_entry = None
        for item in manifest_entries:
            if item.get("snapshot_filename") == target_zip.name:
                matched_entry = item
                break

        if matched_entry and matched_entry.get("save_source_dir"):
            cand_save = Path(matched_entry["save_source_dir"])
            # If the source was under goldberg_base_dir, preserve relative target
            if self.goldberg_base_dir.name in cand_save.parts:
                target_save_dir = cand_save
            elif matched_entry.get("appid"):
                target_save_dir = self.resolve_goldberg_save_path(matched_entry["appid"])

        if target_save_dir is None:
            # Extract AppID from filename pattern
            m = re.match(r"^save_snapshot_([^_]+)_", target_zip.name)
            if m:
                appid = m.group(1)
                target_save_dir = self.resolve_goldberg_save_path(appid)
            else:
                target_save_dir = self.goldberg_base_dir

        target_save_dir = target_save_dir.resolve()
        target_save_dir.mkdir(parents=True, exist_ok=True)

        # 3. Safely extract files (zip-slip protection)
        try:
            with zipfile.ZipFile(target_zip, "r") as zf:
                for member in zf.infolist():
                    extracted_path = (target_save_dir / member.filename).resolve()
                    if not (
                        extracted_path == target_save_dir
                        or target_save_dir in extracted_path.parents
                    ):
                        raise ValueError(
                            f"Path traversal security violation in zip member: {member.filename}"
                        )

                    if member.is_dir():
                        extracted_path.mkdir(parents=True, exist_ok=True)
                    else:
                        extracted_path.parent.mkdir(parents=True, exist_ok=True)
                        with zf.open(member) as src, open(extracted_path, "wb") as dst:
                            shutil.copyfileobj(src, dst)
            return True
        except Exception:
            return False

    def get_latest_snapshot(
        self,
        game_dir: Union[str, Path],
        appid: Optional[str] = None,
    ) -> Optional[SnapshotRecord]:
        """Retrieves the most recent snapshot for the game (optionally filtered by AppID)."""
        snapshots = self.list_snapshots(game_dir)
        if appid:
            appid_str = str(appid).strip()
            snapshots = [s for s in snapshots if s.appid == appid_str]
        return snapshots[0] if snapshots else None

    def delete_snapshot(
        self,
        game_dir: Union[str, Path],
        snapshot_filename: str,
    ) -> bool:
        """Deletes a snapshot archive and updates manifest.json.

        Args:
            game_dir: Path to game root directory.
            snapshot_filename: Filename of snapshot to delete.

        Returns:
            True if deleted, False otherwise.
        """
        snapshots_dir = self._get_snapshots_dir(game_dir)
        zip_path = snapshots_dir / snapshot_filename
        if not zip_path.is_file():
            return False

        try:
            zip_path.unlink()
        except Exception:
            return False

        # Update manifest
        manifest = self._load_manifest(snapshots_dir)
        updated = [m for m in manifest if m.get("snapshot_filename") != snapshot_filename]
        try:
            self._save_manifest(snapshots_dir, updated)
        except Exception:
            pass
        return True
