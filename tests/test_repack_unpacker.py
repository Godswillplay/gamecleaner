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


if __name__ == "__main__":
    unittest.main()
