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


if __name__ == "__main__":
    unittest.main()
