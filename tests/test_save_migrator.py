import tempfile
import unittest
from pathlib import Path

from gamecleaner.cleaner.save_migrator import SaveGameMigrator


class TestSaveGameMigrator(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.game_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_detect_scene_config(self):
        ini_content = """[Settings]
AppId=1091500
PersonaName=CyberGamer2077
AccountId=76561198000000000
"""
        (self.game_dir / "steam_emu.ini").write_text(ini_content, encoding="utf-8")

        migrator = SaveGameMigrator(self.game_dir)
        info = migrator.detect_scene_config()

        self.assertEqual(info["app_id"], "1091500")
        self.assertEqual(info["account_name"], "CyberGamer2077")
        self.assertEqual(info["steam_id"], "76561198000000000")

    def test_configure_goldberg_identity(self):
        migrator = SaveGameMigrator(self.game_dir)
        ok = migrator.configure_goldberg_identity(
            app_id="480",
            account_name="TestHero",
            steam_id="76561198123456789",
        )
        self.assertTrue(ok)

        settings_dir = self.game_dir / "steam_settings"
        self.assertTrue((settings_dir / "account_name.txt").exists())
        self.assertEqual((settings_dir / "account_name.txt").read_text(encoding="utf-8"), "TestHero")
        self.assertEqual((settings_dir / "user_steam_id.txt").read_text(encoding="utf-8"), "76561198123456789")
        self.assertEqual((self.game_dir / "steam_appid.txt").read_text(encoding="utf-8"), "480")

    def test_save_migration_avoids_remote_nesting(self):
        """Verify that when source save directory contains a 'remote' subfolder, saves are NOT nested into remote/remote."""
        migrator = SaveGameMigrator(self.game_dir)
        
        # Mock appdata and public_docs
        fake_appdata = self.game_dir / "mock_appdata"
        fake_public = self.game_dir / "mock_public"
        migrator.appdata = fake_appdata
        migrator.public_docs = fake_public

        # Simulate CODEX save directory in public_docs/Steam/CODEX/227100
        codex_save_dir = fake_public / "Steam" / "CODEX" / "227100"
        remote_dir = codex_save_dir / "remote"
        remote_dir.mkdir(parents=True, exist_ok=True)
        (remote_dir / "save001.sav").write_text("Saved Game Data Level 5", encoding="utf-8")
        (remote_dir / "profile.bin").write_bytes(b"\x01\x02\x03\x04")
        (codex_save_dir / "achievements.ini").write_text("[Achievements]\nAch1=1\n", encoding="utf-8")

        res = migrator.migrate_saves(app_id="227100", copy_files=True)
        self.assertIsNotNone(res.saves_migrated_to)

        target_remote = fake_appdata / "Goldberg SteamEmu Saves" / "227100" / "remote"
        self.assertTrue(target_remote.exists())

        # The crucial check: save001.sav MUST be directly under remote/, NOT remote/remote/
        self.assertTrue((target_remote / "save001.sav").exists())
        self.assertTrue((target_remote / "profile.bin").exists())
        self.assertFalse((target_remote / "remote").exists(), "Double nested remote/remote was created!")
        self.assertEqual((target_remote / "save001.sav").read_text(encoding="utf-8"), "Saved Game Data Level 5")

    def test_save_migration_self_heals_nested_remote(self):
        """Verify that pre-existing corrupted remote/remote directories are auto-healed."""
        migrator = SaveGameMigrator(self.game_dir)
        fake_appdata = self.game_dir / "mock_appdata"
        migrator.appdata = fake_appdata

        target_remote = fake_appdata / "Goldberg SteamEmu Saves" / "550" / "remote"
        buggy_nested = target_remote / "remote"
        buggy_nested.mkdir(parents=True, exist_ok=True)
        (buggy_nested / "corrupted_slot.sav").write_text("Old Corrupted Save", encoding="utf-8")

        # Empty source save dir
        fake_public = self.game_dir / "mock_public"
        migrator.public_docs = fake_public
        source_dir = fake_public / "Steam" / "CODEX" / "550"
        source_dir.mkdir(parents=True, exist_ok=True)
        (source_dir / "remote").mkdir(parents=True, exist_ok=True)

        migrator.migrate_saves(app_id="550", copy_files=True)

        # Buggy nested folder should be healed: moved to target_remote and deleted
        self.assertTrue((target_remote / "corrupted_slot.sav").exists())
        self.assertFalse(buggy_nested.exists())

    def test_expanded_scene_groups_detection(self):
        """Verify detection of various scene group configs (EMPRESS, SKIDROW, ALI213, Plaza, etc.)."""
        # Test EMPRESS
        empress_ini = self.game_dir / "empress.ini"
        empress_ini.write_text("[Settings]\nAppId=582010\nPlayerName=EmpressQueen\n", encoding="utf-8")

        migrator = SaveGameMigrator(self.game_dir)
        info = migrator.detect_scene_config()
        self.assertEqual(info["app_id"], "582010")
        self.assertEqual(info["account_name"], "EmpressQueen")

        # Test ALI213
        empress_ini.unlink()
        ali_ini = self.game_dir / "ali213.ini"
        ali_ini.write_text("[Settings]\nTargetAppId=271590\nUserName=AliPlayer\n", encoding="utf-8")
        info = migrator.detect_scene_config()
        self.assertEqual(info["app_id"], "271590")
        self.assertEqual(info["account_name"], "AliPlayer")

    def test_save_migration_flat_directory(self):
        """Verify that flat save files (not in a remote subfolder) are migrated cleanly into target remote/."""
        migrator = SaveGameMigrator(self.game_dir)
        fake_appdata = self.game_dir / "mock_appdata"
        fake_public = self.game_dir / "mock_public"
        migrator.appdata = fake_appdata
        migrator.public_docs = fake_public

        # Simulate FLT save directory without remote subfolder
        flt_save_dir = fake_appdata / "FLT" / "99999"
        flt_save_dir.mkdir(parents=True, exist_ok=True)
        (flt_save_dir / "flt_save.dat").write_text("FLT Game Save", encoding="utf-8")

        res = migrator.migrate_saves(app_id="99999", copy_files=True)
        self.assertIsNotNone(res.saves_migrated_to)

        target_remote = fake_appdata / "Goldberg SteamEmu Saves" / "99999" / "remote"
        self.assertTrue(target_remote.exists())
        self.assertTrue((target_remote / "flt_save.dat").exists())
        self.assertFalse((target_remote / "remote").exists())
        self.assertEqual((target_remote / "flt_save.dat").read_text(encoding="utf-8"), "FLT Game Save")


if __name__ == "__main__":
    unittest.main()
