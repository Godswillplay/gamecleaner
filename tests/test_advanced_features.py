"""
Advanced feature tests: Steam DLC Fetcher, LNK Scanner, Persistence Auditor, and Multi-DRM detection.
"""
from pathlib import Path
import shutil
import tempfile
import unittest

from gamecleaner.analyzer import LnkScanner, PersistenceAuditor, ThreatSeverity
from gamecleaner.cleaner import EmulatorReplacer
from gamecleaner.cleaner.dlc_fetcher import SteamDLCFetcher


class TestAdvancedFeatures(unittest.TestCase):

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="adv_test_"))

    def tearDown(self):
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_multi_drm_target_detection(self):
        er = EmulatorReplacer(self.test_dir)

        # 1. Steam
        (self.test_dir / "steam_api64.dll").write_text("dummy steam")
        # 2. Epic Games Store
        (self.test_dir / "EOSSDK-Win64-Shipping.dll").write_text("dummy epic")
        # 3. Ubisoft
        (self.test_dir / "uplay_r1_loader64.dll").write_text("dummy uplay")

        targets = er.find_drm_targets()
        self.assertEqual(len(targets), 3)

        platforms = {t.platform: t for t in targets}
        self.assertIn("Steam", platforms)
        self.assertIn("Epic", platforms)
        self.assertIn("Ubisoft", platforms)
        self.assertEqual(platforms["Epic"].dll_name, "EOSSDK-Win64-Shipping.dll")
        self.assertEqual(platforms["Ubisoft"].dll_name, "uplay_r1_loader64.dll")

    def test_lnk_scanner_on_malicious_shortcut(self):
        scanner = LnkScanner()

        # Synthetic malicious LNK content
        fake_lnk = self.test_dir / "Play_Game.lnk"
        fake_lnk_content = (
            b"\x4c\x00\x00\x00" +
            b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46" +
            b"\x00" * 56 +
            b"C:\\Windows\\System32\\powershell.exe -w hidden -enc aQB3AHIAIA..." +
            b"\x00" * 50
        )
        fake_lnk.write_bytes(fake_lnk_content)

        res = scanner.scan_file(fake_lnk)
        self.assertEqual(res.overall_severity, ThreatSeverity.CRITICAL.value)
        self.assertEqual(res.recommended_action, "QUARANTINE")
        self.assertIn("powershell.exe", res.target_path.lower())

    def test_steam_dlc_fetcher_public_api(self):
        fetcher = SteamDLCFetcher()
        # AppID 1091500 (Cyberpunk 2077) has public DLCs
        dlcs = fetcher.fetch_dlc_list("1091500", fetch_names=False, timeout=5)
        if dlcs:
            self.assertGreaterEqual(len(dlcs), 1)
            out_dlc = self.test_dir / "DLC.txt"
            success = fetcher.generate_dlc_txt("1091500", out_dlc)
            self.assertTrue(success)
            self.assertTrue(out_dlc.exists())
            content = out_dlc.read_text(encoding="utf-8")
            self.assertIn("=", content)


if __name__ == "__main__":
    unittest.main()
