"""
Unit and integration tests for gamecleaner.cleaner.cloud_save_sync.
Covers:
- SteamID64 and 32-bit AccountID conversion and round-tripping
- CloudSaveMetadata serialization, hashing, and persistence (.gc_save_meta.json)
- Universal save exporter:
  * Steam Deck Proton compatdata archive with automated deploy script
  * Ludusavi backup mapping format
  * GameSave Manager (.gsba / .zip) format
- Save importer:
  * Official Steam userdata saves (userdata/<AccountID>/<AppID>) into Goldberg emulator
  * Goldberg identity and steam_settings configuration (user_steam_id.txt mapping)
  * Portable ZIP archive restoration
- Save discovery in Steam userdata and Goldberg save directories
"""
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
import zipfile

from gamecleaner.cleaner.cloud_save_sync import (
    CloudSaveSync,
    CloudSaveMetadata,
    ExportResult,
    ImportResult,
    METADATA_FILENAME,
    STEAM_ID64_BASE,
    account_id_to_steamid64,
    calculate_file_hash,
    steamid64_to_account_id,
)


class TestSteamIdConversion(unittest.TestCase):
    """Tests conversion between 64-bit SteamID64 and 32-bit AccountID."""

    def test_steamid64_to_account_id(self):
        # Base offset (AccountID 0)
        self.assertEqual(steamid64_to_account_id(STEAM_ID64_BASE), 0)

        # Standard AccountID 12345678
        expected_sid64 = STEAM_ID64_BASE + 12345678
        self.assertEqual(steamid64_to_account_id(expected_sid64), 12345678)
        self.assertEqual(steamid64_to_account_id(str(expected_sid64)), 12345678)

        # Account ID already 32-bit (fallback bitwise AND)
        self.assertEqual(steamid64_to_account_id(999999), 999999)

    def test_account_id_to_steamid64(self):
        # AccountID 12345678
        sid64 = account_id_to_steamid64(12345678)
        self.assertEqual(sid64, 76561197972611406)
        self.assertEqual(account_id_to_steamid64("12345678"), 76561197972611406)

        # If already a SteamID64, return unchanged
        self.assertEqual(account_id_to_steamid64(76561197972611406), 76561197972611406)

    def test_round_trip_conversion(self):
        for aid in [1, 100, 12345678, 987654321]:
            sid = account_id_to_steamid64(aid)
            self.assertEqual(steamid64_to_account_id(sid), aid)


class TestCloudSaveMetadata(unittest.TestCase):
    """Tests CloudSaveMetadata data structure, serialization, and hash calculation."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name).resolve()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_metadata_dict_and_json(self):
        meta = CloudSaveMetadata(
            appid="227100",
            game_title="Sniper Elite Nazi Zombie Army",
            save_timestamp="2026-11-20T12:00:00Z",
            source_emulator="Goldberg",
            account_id="12345678",
            steam_id64="76561197972611406",
            file_count=2,
            total_size_bytes=4096,
            files=[
                {"relative_path": "save0.sav", "size_bytes": 2048, "sha256": "aaaa"},
                {"relative_path": "profile.bin", "size_bytes": 2048, "sha256": "bbbb"},
            ],
            target_compatdata_path="compatdata/227100/pfx/...",
        )

        d = meta.to_dict()
        self.assertEqual(d["appid"], "227100")
        self.assertEqual(d["account_id"], "12345678")

        json_str = meta.to_json()
        loaded = CloudSaveMetadata.from_dict(json.loads(json_str))
        self.assertEqual(loaded.appid, "227100")
        self.assertEqual(loaded.game_title, "Sniper Elite Nazi Zombie Army")
        self.assertEqual(loaded.file_count, 2)
        self.assertEqual(len(loaded.files), 2)

    def test_metadata_file_persistence(self):
        meta_file = self.temp_path / METADATA_FILENAME
        meta = CloudSaveMetadata(
            appid="480",
            game_title="Spacewar",
            save_timestamp="2026-11-20T12:30:00Z",
            source_emulator="Official Steam",
        )
        meta.save_to_file(meta_file)
        self.assertTrue(meta_file.exists())

        loaded = CloudSaveMetadata.from_file(meta_file)
        self.assertEqual(loaded.appid, "480")
        self.assertEqual(loaded.source_emulator, "Official Steam")

    def test_calculate_file_hash(self):
        dummy_file = self.temp_path / "dummy.dat"
        dummy_file.write_bytes(b"GameCleaner cloud save test bytes 12345")
        h = calculate_file_hash(dummy_file)
        self.assertIsInstance(h, str)
        self.assertEqual(len(h), 64)


class TestUniversalSaveExporter(unittest.TestCase):
    """Tests exporting save folders to universal, Steam Deck, Ludusavi, and GSM archives."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name).resolve()
        self.appdata_mock = self.temp_path / "AppData" / "Roaming"
        self.sync = CloudSaveSync(appdata_dir=self.appdata_mock)

        # Create dummy save directory
        self.save_dir = self.temp_path / "SampleSaves"
        self.save_dir.mkdir(parents=True, exist_ok=True)
        (self.save_dir / "slot1.sav").write_bytes(b"Slot 1 save data")
        (self.save_dir / "profile.dat").write_bytes(b"Player profile configuration")
        sub = self.save_dir / "subfolder"
        sub.mkdir(parents=True, exist_ok=True)
        (sub / "checkpoint.bin").write_bytes(b"Checkpoint state")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_export_universal_archive(self):
        out_zip = self.temp_path / "exports" / "universal_save.zip"
        res = self.sync.export_save(
            source_save_dir=self.save_dir,
            output_archive_path=out_zip,
            appid="227100",
            game_title="Sniper Elite Nazi Zombie Army",
            source_emulator="Goldberg",
            export_format="universal",
            account_id="12345678",
        )

        self.assertTrue(res.success)
        self.assertEqual(res.file_count, 3)
        self.assertTrue(out_zip.exists())
        self.assertIsNotNone(res.metadata)
        self.assertEqual(res.metadata.steam_id64, "76561197972611406")

        # Verify ZIP archive structure
        with zipfile.ZipFile(out_zip, "r") as zf:
            namelist = zf.namelist()
            # 1. Metadata manifest
            self.assertIn(METADATA_FILENAME, namelist)
            # 2. Universal saves/ and remote/
            self.assertTrue(any(n.startswith("remote/") for n in namelist))
            self.assertTrue(any(n.startswith("saves/") for n in namelist))
            # 3. Steam Deck compatdata structure
            self.assertTrue(any("compatdata/227100/pfx" in n for n in namelist))
            self.assertIn("deploy_to_deck.sh", namelist)
            # 4. Ludusavi manifest
            self.assertIn("ludusavi_manifest.json", namelist)
            # 5. GameSave Manager info
            self.assertIn("gsm_info.txt", namelist)

            # Check that deploy_to_deck.sh contains the appid
            deploy_script = zf.read("deploy_to_deck.sh").decode("utf-8")
            self.assertIn('APPID="227100"', deploy_script)

        # Check that source folder received stamped metadata
        self.assertTrue((self.save_dir / METADATA_FILENAME).exists())

    def test_export_steam_deck_format(self):
        out_zip = self.temp_path / "exports" / "steam_deck_save.zip"
        res = self.sync.export_to_steam_deck_archive(
            source_save_dir=self.save_dir,
            output_archive_path=out_zip,
            appid="550",
            game_title="Left 4 Dead 2",
            account_id="99999",
        )

        self.assertTrue(res.success)
        with zipfile.ZipFile(out_zip, "r") as zf:
            namelist = zf.namelist()
            self.assertIn(METADATA_FILENAME, namelist)
            self.assertIn("deploy_to_deck.sh", namelist)
            self.assertTrue(any("compatdata/550/pfx" in n for n in namelist))

    def test_export_ludusavi_format(self):
        out_zip = self.temp_path / "exports" / "ludusavi_save.zip"
        res = self.sync.export_to_ludusavi_archive(
            source_save_dir=self.save_dir,
            output_archive_path=out_zip,
            appid="105600",
            game_title="Terraria",
        )

        self.assertTrue(res.success)
        with zipfile.ZipFile(out_zip, "r") as zf:
            namelist = zf.namelist()
            self.assertIn("ludusavi_manifest.json", namelist)
            self.assertTrue(any("Terraria/saves" in n for n in namelist))

    def test_export_gamesave_manager_format(self):
        out_zip = self.temp_path / "exports" / "gsm_save.zip"
        res = self.sync.export_to_gamesave_manager_archive(
            source_save_dir=self.save_dir,
            output_archive_path=out_zip,
            appid="814380",
            game_title="Sekiro",
        )

        self.assertTrue(res.success)
        with zipfile.ZipFile(out_zip, "r") as zf:
            namelist = zf.namelist()
            self.assertIn("gsm_info.txt", namelist)

    def test_export_nonexistent_directory(self):
        res = self.sync.export_save(
            source_save_dir=self.temp_path / "NonExistentFolder",
            output_archive_path=self.temp_path / "fail.zip",
            appid="100",
        )
        self.assertFalse(res.success)
        self.assertIn("does not exist", res.error_message)

    def test_export_empty_directory(self):
        empty_dir = self.temp_path / "EmptyDir"
        empty_dir.mkdir(parents=True, exist_ok=True)
        res = self.sync.export_save(
            source_save_dir=empty_dir,
            output_archive_path=self.temp_path / "empty.zip",
            appid="100",
        )
        self.assertFalse(res.success)
        self.assertIn("No save files found", res.error_message)


class TestSaveImporter(unittest.TestCase):
    """Tests importing official Steam userdata saves and portable ZIP archives."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name).resolve()
        self.appdata_mock = self.temp_path / "AppData" / "Roaming"
        self.steam_userdata_mock = self.temp_path / "Steam" / "userdata"
        self.sync = CloudSaveSync(
            appdata_dir=self.appdata_mock,
            steam_userdata_dir=self.steam_userdata_mock,
        )

        # Create mock official Steam save directory
        # userdata/<AccountID>/<AppID>/remote/
        self.official_steam_save_dir = self.steam_userdata_mock / "12345678" / "227100" / "remote"
        self.official_steam_save_dir.mkdir(parents=True, exist_ok=True)
        (self.official_steam_save_dir / "official_save1.sav").write_bytes(b"Official Steam save progress")
        (self.official_steam_save_dir / "stats.bin").write_bytes(b"Achievements and stats")
        # remotecache.vdf in parent
        (self.official_steam_save_dir.parent / "remotecache.vdf").write_text('"227100" { "size" "1024" }', encoding="utf-8")

        # Create mock game directory with bin folder
        self.game_dir = self.temp_path / "GameInstallation"
        self.game_dir.mkdir(parents=True, exist_ok=True)
        (self.game_dir / "bin" / "x64").mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_import_official_steam_save(self):
        res = self.sync.import_steam_save(
            steam_userdata_path=self.official_steam_save_dir,
            game_dir=self.game_dir,
            custom_game_title="Sniper Elite Nazi Zombie Army",
        )

        self.assertTrue(res.success)
        self.assertEqual(res.appid, "227100")
        self.assertEqual(res.account_id, "12345678")
        self.assertEqual(res.steam_id64, "76561197972611406")
        self.assertEqual(len(res.files_imported), 2)
        self.assertTrue(res.goldberg_configured)

        # Verify save files were copied into Goldberg folder
        target_dir = Path(res.target_save_dir)
        self.assertTrue(target_dir.exists())
        self.assertTrue((target_dir / "official_save1.sav").exists())
        self.assertTrue((target_dir / "stats.bin").exists())
        # remotecache.vdf should NOT be copied into Goldberg save folder
        self.assertFalse((target_dir / "remotecache.vdf").exists())

        # Verify Goldberg identity configured in game directory
        steam_settings = self.game_dir / "steam_settings"
        self.assertTrue(steam_settings.exists())
        user_sid = (steam_settings / "user_steam_id.txt").read_text(encoding="utf-8").strip()
        self.assertEqual(user_sid, "76561197972611406")
        appid_txt = (steam_settings / "steam_appid.txt").read_text(encoding="utf-8").strip()
        self.assertEqual(appid_txt, "227100")

        # Verify mirrored to bin/x64/
        bin_settings = self.game_dir / "bin" / "x64" / "steam_settings"
        self.assertTrue((bin_settings / "user_steam_id.txt").exists())
        self.assertEqual((bin_settings / "user_steam_id.txt").read_text(encoding="utf-8").strip(), "76561197972611406")

        # Verify .gc_save_meta.json stamped in Goldberg AppID folder
        meta_file = target_dir.parent / METADATA_FILENAME
        self.assertTrue(meta_file.exists())
        meta = CloudSaveMetadata.from_file(meta_file)
        self.assertEqual(meta.source_emulator, "Official Steam")
        self.assertEqual(meta.steam_id64, "76561197972611406")

    def test_import_portable_archive(self):
        # 1. Export sample saves
        sample_dir = self.temp_path / "MySaves"
        sample_dir.mkdir(parents=True, exist_ok=True)
        (sample_dir / "quicksave.dat").write_bytes(b"Quicksave content 100%")

        out_zip = self.temp_path / "portable_backup.zip"
        self.sync.export_save(
            source_save_dir=sample_dir,
            output_archive_path=out_zip,
            appid="379720",
            game_title="DOOM",
            account_id="88888",
        )

        # 2. Import into a new Goldberg base
        fresh_goldberg_base = self.temp_path / "FreshGoldberg"
        import_res = self.sync.import_portable_archive(
            archive_path=out_zip,
            target_goldberg_base=fresh_goldberg_base,
            game_dir=self.game_dir,
        )

        self.assertTrue(import_res.success)
        self.assertEqual(import_res.appid, "379720")
        target_remote = Path(import_res.target_save_dir)
        self.assertTrue((target_remote / "quicksave.dat").exists())
        self.assertTrue(import_res.goldberg_configured)

        # Check metadata
        self.assertTrue((fresh_goldberg_base / "379720" / METADATA_FILENAME).exists())


class TestSaveDiscovery(unittest.TestCase):
    """Tests discovery of active saves in Steam userdata and Goldberg directories."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name).resolve()
        self.appdata_mock = self.temp_path / "AppData" / "Roaming"
        self.steam_userdata_mock = self.temp_path / "Steam" / "userdata"
        self.sync = CloudSaveSync(
            appdata_dir=self.appdata_mock,
            steam_userdata_dir=self.steam_userdata_mock,
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_find_official_steam_saves(self):
        # Create 2 mock game saves in userdata
        game1_dir = self.steam_userdata_mock / "11111111" / "100" / "remote"
        game1_dir.mkdir(parents=True, exist_ok=True)
        (game1_dir / "save.dat").write_bytes(b"data1")

        game2_dir = self.steam_userdata_mock / "11111111" / "200"
        game2_dir.mkdir(parents=True, exist_ok=True)
        (game2_dir / "profile.sav").write_bytes(b"data2")

        saves = self.sync.find_official_steam_saves()
        self.assertEqual(len(saves), 2)
        appids = [s["appid"] for s in saves]
        self.assertIn("100", appids)
        self.assertIn("200", appids)

        # Filter by AppID
        filtered = self.sync.find_official_steam_saves(appid="100")
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["appid"], "100")

    def test_find_goldberg_saves(self):
        gb_save = self.sync.goldberg_saves_dir / "227100" / "remote"
        gb_save.mkdir(parents=True, exist_ok=True)
        (gb_save / "save.bin").write_bytes(b"Goldberg save data")

        discovered = self.sync.find_goldberg_saves()
        self.assertEqual(len(discovered), 1)
        self.assertEqual(discovered[0]["appid"], "227100")
        self.assertEqual(discovered[0]["file_count"], 1)


if __name__ == "__main__":
    unittest.main()
