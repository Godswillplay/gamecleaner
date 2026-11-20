import tempfile
import unittest
from pathlib import Path

from gamecleaner.analyzer.steam_stub import SteamStubDetector, SteamStubResult


class TestSteamStub(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.work_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_non_existent_file(self):
        detector = SteamStubDetector(self.work_dir / "does_not_exist.exe")
        res = detector.scan()
        self.assertFalse(res.is_wrapped)
        self.assertEqual(res.stub_version, "None")

    def test_non_pe_file(self):
        txt_file = self.work_dir / "readme.txt"
        txt_file.write_text("Hello World", encoding="utf-8")
        detector = SteamStubDetector(txt_file)
        res = detector.scan()
        self.assertFalse(res.is_wrapped)

    def test_clean_executable_no_steam_stub(self):
        exe_file = self.work_dir / "clean_game.exe"
        exe_file.write_bytes(b"MZ" + b"\x00" * 200)
        detector = SteamStubDetector(exe_file)
        res = detector.scan()
        self.assertFalse(res.is_wrapped)
        self.assertEqual(res.stub_version, "None")

    def test_steam_stub_signature_detection(self):
        stub_exe = self.work_dir / "stubbed_game.exe"
        # Binary containing Steam Stub DRM .bind signature marker
        stub_exe.write_bytes(b"MZ" + b"\x00" * 50 + b"SteamDrmPfn" + b"\x00" * 20 + b".bind" + b"\x00" * 100)
        detector = SteamStubDetector(stub_exe)
        res = detector.scan()
        self.assertTrue(res.is_wrapped)
        self.assertIn("Steam Stub", res.stub_version)
        self.assertIn("Steamless", res.guidance)

    def test_entropy_calculation(self):
        # High entropy data
        high_ent_data = bytes([i % 256 for i in range(1000)])
        ent = SteamStubDetector.calculate_entropy(high_ent_data)
        self.assertGreater(ent, 7.0)

        # Zero entropy data
        low_ent_data = b"\x00" * 1000
        ent_zero = SteamStubDetector.calculate_entropy(low_ent_data)
        self.assertEqual(ent_zero, 0.0)


if __name__ == "__main__":
    unittest.main()
