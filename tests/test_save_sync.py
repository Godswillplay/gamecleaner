"""
Unit tests for SaveSyncManager defensive save preservation & snapshot module.
"""
from datetime import datetime
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
import zipfile

from gamecleaner.cleaner.save_sync import (
    SaveSyncManager,
    SnapshotRecord,
    SnapshotResult,
)


class TestSaveSyncManager(unittest.TestCase):
    """Test suite for versioned Goldberg save snapshots, compression, manifest indexing, and rollbacks."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.work_dir = Path(self.temp_dir.name).resolve()

        # Isolated AppData environment
        self.mock_appdata = self.work_dir / "AppData" / "Roaming"
        self.mock_appdata.mkdir(parents=True, exist_ok=True)

        self.mock_game_dir = self.work_dir / "Games" / "TestGame"
        self.mock_game_dir.mkdir(parents=True, exist_ok=True)

        self.sync_mgr = SaveSyncManager(appdata_dir=self.mock_appdata)
        self.goldberg_root = self.mock_appdata / "Goldberg SteamEmu Saves"

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_mock_saves(self, appid: str, files: dict) -> Path:
        """Helper to populate fake Goldberg save files."""
        save_dir = self.goldberg_root / appid
        save_dir.mkdir(parents=True, exist_ok=True)
        for rel_path, content in files.items():
            f_path = save_dir / rel_path
            f_path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, str):
                f_path.write_text(content, encoding="utf-8")
            else:
                f_path.write_bytes(content)
        return save_dir

    def test_resolve_goldberg_save_path_appid_exists(self):
        """Resolves %APPDATA%/Goldberg SteamEmu Saves/<AppID>/ when it exists."""
        appid = "227100"
        save_dir = self.goldberg_root / appid
        save_dir.mkdir(parents=True, exist_ok=True)

        resolved = self.sync_mgr.resolve_goldberg_save_path(appid)
        self.assertEqual(resolved, save_dir.resolve())

    def test_resolve_goldberg_save_path_root_fallback(self):
        """Falls back to %APPDATA%/Goldberg SteamEmu Saves/ if root contains saves directly."""
        self.goldberg_root.mkdir(parents=True, exist_ok=True)
        (self.goldberg_root / "global_save.dat").write_text("root save", encoding="utf-8")

        resolved = self.sync_mgr.resolve_goldberg_save_path(None)
        self.assertEqual(resolved, self.goldberg_root.resolve())

    def test_create_snapshot_missing_appid(self):
        """Creating a snapshot without AppID returns failure."""
        res = self.sync_mgr.create_snapshot(self.mock_game_dir, "")
        self.assertFalse(res.success)
        self.assertIn("AppID is required", res.error_message)

    def test_create_snapshot_no_saves_found(self):
        """Fails gracefully if no saves exist for the target AppID."""
        res = self.sync_mgr.create_snapshot(self.mock_game_dir, "999999")
        self.assertFalse(res.success)
        self.assertIn("does not exist", res.error_message)

    def test_create_snapshot_empty_save_dir(self):
        """Fails gracefully if the save directory exists but contains zero files."""
        empty_dir = self.goldberg_root / "12345"
        empty_dir.mkdir(parents=True, exist_ok=True)

        res = self.sync_mgr.create_snapshot(self.mock_game_dir, "12345")
        self.assertFalse(res.success)
        self.assertIn("No save files found", res.error_message)

    def test_create_snapshot_success(self):
        """Successfully creates a versioned .zip snapshot and records manifest."""
        appid = "227100"
        self._create_mock_saves(
            appid,
            {
                "remote/savegame.sav": "game save data 123",
                "remote/profile.dat": "player profile",
                "settings/account_name.txt": "GamerTag",
            },
        )

        res = self.sync_mgr.create_snapshot(
            self.mock_game_dir,
            appid=appid,
            note="Pre-launch backup",
        )

        self.assertTrue(res.success)
        self.assertIsNone(res.error_message)
        self.assertEqual(res.files_archived, 3)
        self.assertGreater(res.size_bytes, 0)
        self.assertTrue(Path(res.snapshot_path).is_file())

        # Verify zip archive contents
        with zipfile.ZipFile(res.snapshot_path, "r") as zf:
            names = zf.namelist()
            self.assertIn("remote/savegame.sav", [n.replace("\\", "/") for n in names])
            self.assertIn("remote/profile.dat", [n.replace("\\", "/") for n in names])
            self.assertIn("settings/account_name.txt", [n.replace("\\", "/") for n in names])

        # Verify manifest.json
        manifest_path = self.mock_game_dir / ".gamecleaner_saves" / "manifest.json"
        self.assertTrue(manifest_path.is_file())
        manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
        snapshots = manifest_data.get("snapshots", [])
        self.assertEqual(len(snapshots), 1)
        self.assertEqual(snapshots[0]["appid"], appid)
        self.assertEqual(snapshots[0]["note"], "Pre-launch backup")
        self.assertEqual(snapshots[0]["file_count"], 3)

    def test_list_snapshots_order_and_reconciliation(self):
        """Lists snapshots newest-first and recovers orphans on disk."""
        appid = "227100"
        self._create_mock_saves(appid, {"save.dat": "v1"})

        # Create two consecutive snapshots
        res1 = self.sync_mgr.create_snapshot(self.mock_game_dir, appid, note="Snapshot 1")
        self.assertTrue(res1.success)

        res2 = self.sync_mgr.create_snapshot(self.mock_game_dir, appid, note="Snapshot 2")
        self.assertTrue(res2.success)

        # Create an orphan zip manually in .gamecleaner_saves
        saves_dir = self.mock_game_dir / ".gamecleaner_saves"
        orphan_zip = saves_dir / "save_snapshot_55555_20000101_000000.zip"
        with zipfile.ZipFile(orphan_zip, "w") as zf:
            zf.writestr("test.dat", "orphan test")

        snapshots = self.sync_mgr.list_snapshots(self.mock_game_dir)
        self.assertEqual(len(snapshots), 3)
        # Verify newest is first
        self.assertEqual(snapshots[0].note, "Snapshot 2")
        self.assertEqual(snapshots[1].note, "Snapshot 1")
        # Check orphan was discovered
        orphan_rec = next(s for s in snapshots if s.appid == "55555")
        self.assertEqual(orphan_rec.note, "Discovered snapshot")
        self.assertEqual(orphan_rec.file_count, 1)

    def test_restore_snapshot_success(self):
        """Successfully restores a save snapshot back into the Goldberg save location."""
        appid = "227100"
        save_dir = self._create_mock_saves(
            appid,
            {
                "remote/savegame.sav": "state BEFORE corruption",
                "user.cfg": "config data",
            },
        )

        # Take snapshot of good state
        res = self.sync_mgr.create_snapshot(self.mock_game_dir, appid, note="Good State")
        self.assertTrue(res.success)
        snapshot_filename = res.snapshot_record.snapshot_filename

        # Simulate game corruption/overwriting save files
        (save_dir / "remote" / "savegame.sav").write_text("CORRUPTED BY CRASH", encoding="utf-8")
        self.assertEqual(
            (save_dir / "remote" / "savegame.sav").read_text(encoding="utf-8"),
            "CORRUPTED BY CRASH",
        )

        # Restore good snapshot
        ok = self.sync_mgr.restore_snapshot(self.mock_game_dir, snapshot_filename)
        self.assertTrue(ok)

        # Verify state is restored to pre-corruption
        restored_text = (save_dir / "remote" / "savegame.sav").read_text(encoding="utf-8")
        self.assertEqual(restored_text, "state BEFORE corruption")

    def test_restore_snapshot_not_found(self):
        """Returns False when attempting to restore non-existent snapshot."""
        ok = self.sync_mgr.restore_snapshot(self.mock_game_dir, "nonexistent.zip")
        self.assertFalse(ok)

    def test_restore_snapshot_zip_slip_prevention(self):
        """Blocks and rejects malicious zip archives with directory traversal paths."""
        saves_dir = self.mock_game_dir / ".gamecleaner_saves"
        saves_dir.mkdir(parents=True, exist_ok=True)

        malicious_zip = saves_dir / "save_snapshot_99999_20261120_120000.zip"
        with zipfile.ZipFile(malicious_zip, "w") as zf:
            # Attempt directory traversal outside of the save directory
            zf.writestr("../../pwned.txt", "malicious payload")

        ok = self.sync_mgr.restore_snapshot(self.mock_game_dir, malicious_zip.name)
        self.assertFalse(ok)

        # Ensure traversal file was NOT created
        escaped_file = self.work_dir / "pwned.txt"
        self.assertFalse(escaped_file.exists())

    def test_get_latest_snapshot(self):
        """Retrieves the most recent snapshot filtered by AppID."""
        appid1 = "111"
        appid2 = "222"
        self._create_mock_saves(appid1, {"save.dat": "app1"})
        self._create_mock_saves(appid2, {"save.dat": "app2"})

        self.sync_mgr.create_snapshot(self.mock_game_dir, appid1, note="App1 Snapshot")
        self.sync_mgr.create_snapshot(self.mock_game_dir, appid2, note="App2 Snapshot")

        latest_app1 = self.sync_mgr.get_latest_snapshot(self.mock_game_dir, appid="111")
        self.assertIsNotNone(latest_app1)
        self.assertEqual(latest_app1.appid, "111")
        self.assertEqual(latest_app1.note, "App1 Snapshot")

    def test_delete_snapshot(self):
        """Deletes a snapshot archive and removes it from manifest."""
        appid = "333"
        self._create_mock_saves(appid, {"save.dat": "app3"})
        res = self.sync_mgr.create_snapshot(self.mock_game_dir, appid, note="To Delete")
        self.assertTrue(res.success)
        filename = res.snapshot_record.snapshot_filename

        ok = self.sync_mgr.delete_snapshot(self.mock_game_dir, filename)
        self.assertTrue(ok)

        # Verify file is gone
        zip_file = self.mock_game_dir / ".gamecleaner_saves" / filename
        self.assertFalse(zip_file.exists())

        # Verify removed from manifest
        snapshots = self.sync_mgr.list_snapshots(self.mock_game_dir)
        self.assertEqual(len(snapshots), 0)


if __name__ == "__main__":
    unittest.main()
