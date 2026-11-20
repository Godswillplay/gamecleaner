import tempfile
import unittest
import zipfile
from pathlib import Path

from gamecleaner.cleaner.repack_unpacker import RepackUnpacker


class TestRepackUnpacker(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.work_dir = Path(self.temp_dir.name)
        self.out_dir = self.work_dir / "extracted_game"
        self.unpacker = RepackUnpacker(tools_dir=self.work_dir / "tools")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_unpack_zip_archive_with_autoclean(self):
        # Create a mock zip repack containing a game.exe and steam_api64.dll
        zip_path = self.work_dir / "setup_repack.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("game.exe", "MZMockBinaryData")
            zf.writestr("steam_api64.dll", "MZMockSteamDll")
            zf.writestr("steam_appid.txt", "480")

        res = self.unpacker.unpack(zip_path, self.out_dir, auto_clean=True)
        self.assertTrue(res.success)
        self.assertGreaterEqual(res.extracted_files_count, 3)
        self.assertTrue((self.out_dir / "game.exe").exists())
        self.assertTrue(res.cleaned_after_unpack)
        self.assertIsNotNone(res.pipeline_report)

    def test_is_inno_setup_detection(self):
        fake_inno = self.work_dir / "setup.exe"
        fake_inno.write_bytes(b"MZ" + b"\x00" * 50 + b"Inno Setup Setup Data (5.5.0)")
        self.assertTrue(self.unpacker.is_inno_setup(fake_inno))

        plain_exe = self.work_dir / "game.exe"
        plain_exe.write_bytes(b"MZ" + b"\x00" * 100)
        self.assertFalse(self.unpacker.is_inno_setup(plain_exe))

    def test_is_nsis_installer_detection(self):
        fake_nsis = self.work_dir / "nsis_setup.exe"
        fake_nsis.write_bytes(b"MZ" + b"\x00" * 100 + b"NullsoftInst" + b"\x00" * 50)
        self.assertTrue(self.unpacker.is_nsis_installer(fake_nsis))

        plain_exe = self.work_dir / "game_plain.exe"
        plain_exe.write_bytes(b"MZ" + b"\x00" * 100)
        self.assertFalse(self.unpacker.is_nsis_installer(plain_exe))

    def test_unpack_archive_with_spaces_in_path(self):
        # Create destination directory with spaces
        spaced_out = self.work_dir / "My Games Extracted Here"
        zip_path = self.work_dir / "game archive with spaces.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("test_file.txt", "Space safe extraction")

        res = self.unpacker.unpack(zip_path, spaced_out, auto_clean=False)
        self.assertTrue(res.success)
        self.assertIsNone(res.error_message)
        self.assertTrue((spaced_out / "test_file.txt").exists())

    def test_unpack_nonexistent_file(self):
        missing = self.work_dir / "nonexistent_installer.exe"
        res = self.unpacker.unpack(missing, self.out_dir, auto_clean=False)
        self.assertFalse(res.success)
        self.assertEqual(res.extractor_used, "none")
        self.assertIn("File not found", res.error_message)

    def test_unpack_fallback_7z(self):
        from unittest.mock import MagicMock, patch
        fake_archive = self.work_dir / "archive.7z"
        fake_archive.write_bytes(b"7zMockArchiveData")

        with patch.object(self.unpacker, "ensure_7z") as mock_7z, \
             patch("subprocess.run") as mock_subproc:
            mock_7z.return_value = Path("C:\\Tools\\7z.exe")
            mock_subproc.return_value = MagicMock(returncode=0, stdout="", stderr="")

            res = self.unpacker.unpack(fake_archive, self.out_dir, auto_clean=False)
            self.assertTrue(res.success)
            self.assertEqual(res.extractor_used, "7z")
            mock_subproc.assert_called_once()


if __name__ == "__main__":
    unittest.main()
