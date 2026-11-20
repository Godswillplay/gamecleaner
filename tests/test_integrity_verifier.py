import json
import tempfile
import unittest
from pathlib import Path

from gamecleaner.cleaner.integrity_verifier import (
    IntegrityVerifier,
    IntegrityReport,
    MANIFEST_FILENAME,
)


class TestIntegrityVerifier(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.game_dir = Path(self.temp_dir.name).resolve()

        # Create sample game files
        self.exe_file = self.game_dir / "Game.exe"
        self.exe_file.write_bytes(b"MZ" + b"\x00" * 100)

        self.dll_file = self.game_dir / "steam_api64.dll"
        self.dll_file.write_bytes(b"MZ" + b"\x00" * 200)

        self.cfg_file = self.game_dir / "steam_appid.txt"
        self.cfg_file.write_text("227100\n", encoding="utf-8")

        self.verifier = IntegrityVerifier(self.game_dir)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_create_manifest(self):
        manifest_p = self.verifier.create_manifest(appid="227100")
        self.assertTrue(manifest_p.exists())
        self.assertEqual(manifest_p.name, MANIFEST_FILENAME)

        data = json.loads(manifest_p.read_text(encoding="utf-8"))
        self.assertEqual(data.get("appid"), "227100")
        self.assertEqual(data.get("total_files"), 3)

        paths = [f["path"] for f in data["files"]]
        self.assertIn("Game.exe", paths)
        self.assertIn("steam_api64.dll", paths)
        self.assertIn("steam_appid.txt", paths)

    def test_verify_intact_files(self):
        self.verifier.create_manifest(appid="227100")
        report = self.verifier.verify()
        self.assertTrue(report.is_valid)
        self.assertEqual(report.total_verified, 3)
        self.assertEqual(len(report.missing_files), 0)
        self.assertEqual(len(report.modified_files), 0)
        self.assertEqual(len(report.untracked_binaries), 0)

    def test_detect_modified_file(self):
        self.verifier.create_manifest(appid="227100")

        # Tamper with executable
        self.exe_file.write_bytes(b"MZ" + b"\xFF" * 100)

        report = self.verifier.verify()
        self.assertFalse(report.is_valid)
        self.assertEqual(len(report.modified_files), 1)
        self.assertIn("Game.exe", report.modified_files)
        self.assertTrue(any("tampering" in a.lower() for a in report.tamper_alerts))

    def test_detect_missing_file(self):
        self.verifier.create_manifest(appid="227100")

        # Delete steam_api64.dll
        self.dll_file.unlink()

        report = self.verifier.verify()
        self.assertFalse(report.is_valid)
        self.assertEqual(len(report.missing_files), 1)
        self.assertIn("steam_api64.dll", report.missing_files)
        self.assertTrue(any("missing" in a.lower() for a in report.tamper_alerts))

    def test_detect_untracked_injected_binary(self):
        self.verifier.create_manifest(appid="227100")

        # Inject new untracked DLL into game directory
        injected = self.game_dir / "evil_miner.dll"
        injected.write_bytes(b"MZ" + b"\x55" * 100)

        report = self.verifier.verify()
        self.assertFalse(report.is_valid)
        self.assertEqual(len(report.untracked_binaries), 1)
        self.assertIn("evil_miner.dll", report.untracked_binaries)
        self.assertTrue(any("untracked" in a.lower() for a in report.tamper_alerts))


if __name__ == "__main__":
    unittest.main()
