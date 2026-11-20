"""
Advanced feature tests: Steam DLC Fetcher, LNK Scanner, Persistence Auditor, and Multi-DRM detection.
"""
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from gamecleaner.analyzer import LnkScanner, PersistenceAuditor, ThreatSeverity
from gamecleaner.analyzer.persistence_auditor import PersistenceEntry
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
        # 3. Ubisoft (test both r1 and r2 loaders)
        (self.test_dir / "uplay_r1_loader64.dll").write_text("dummy uplay r1")
        (self.test_dir / "uplay_r2_loader64.dll").write_text("dummy uplay r2")

        targets = er.find_drm_targets()
        self.assertEqual(len(targets), 4)

        platforms = [t.platform for t in targets]
        self.assertIn("Steam", platforms)
        self.assertIn("Epic", platforms)
        self.assertEqual(platforms.count("Ubisoft"), 2)

    def test_emu_replacer_mirroring_with_nested_dll_and_dlc(self):
        """Verify that when target DLL is in bin/x64, mirroring works back to root and copies DLC.txt."""
        bin_x64 = self.test_dir / "bin" / "x64"
        bin_x64.mkdir(parents=True)
        target_dll = bin_x64 / "steam_api64.dll"
        target_dll.write_text("untrusted crack dll")

        # Create mock clean emulator
        fake_clean_dll = self.test_dir / "clean_steam_api64.dll"
        fake_clean_dll.write_text("verified clean goldberg emulator")

        # Create root exe to verify candidate discovery
        (self.test_dir / "Game.exe").write_text("Mock Executable")

        er = EmulatorReplacer(self.test_dir)
        targets = er.find_drm_targets()
        self.assertEqual(len(targets), 1)

        # Pre-seed a DLC.txt in target steam_settings
        gold_dir = bin_x64 / "steam_settings"
        gold_dir.mkdir(parents=True)
        (gold_dir / "DLC.txt").write_text("12345=Expansion Pack 1\n", encoding="utf-8")

        ok, msg = er.replace_with_clean_emulator(targets[0], custom_clean_dll=fake_clean_dll, default_appid="12340")
        self.assertTrue(ok)

        # Verify target was replaced
        self.assertEqual(target_dll.read_text(), "verified clean goldberg emulator")

        # Verify mirrored to root target_dir
        self.assertTrue((self.test_dir / "steam_api64.dll").exists())
        self.assertEqual((self.test_dir / "steam_api64.dll").read_text(), "verified clean goldberg emulator")
        self.assertTrue((self.test_dir / "steam_appid.txt").exists())
        self.assertEqual((self.test_dir / "steam_appid.txt").read_text(), "12340")

        # Verify DLC.txt was mirrored to root steam_settings/DLC.txt
        root_gold = self.test_dir / "steam_settings"
        self.assertTrue((root_gold / "DLC.txt").exists())
        self.assertEqual((root_gold / "DLC.txt").read_text(encoding="utf-8"), "12345=Expansion Pack 1\n")

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

    @patch("winreg.OpenKey")
    @patch("winreg.QueryInfoKey")
    @patch("winreg.EnumValue")
    def test_persistence_auditor_registry_runonce(self, mock_enum_val, mock_query_info, mock_open_key):
        mock_open_key.return_value.__enter__.return_value = MagicMock()
        mock_query_info.return_value = (0, 1, 0)
        mock_enum_val.return_value = ("MalwareRunOnce", f"{self.test_dir}\\dropper.exe", 1)

        auditor = PersistenceAuditor(self.test_dir)
        entries = auditor.audit_registry_runonce()
        self.assertGreaterEqual(len(entries), 1)
        self.assertEqual(entries[0].entry_type, "RegistryRunOnce")
        self.assertEqual(entries[0].name, "MalwareRunOnce")
        self.assertTrue(entries[0].is_malicious)

    def test_persistence_auditor_startup_folder(self):
        fake_appdata = self.test_dir / "AppData" / "Roaming"
        startup_dir = fake_appdata / r"Microsoft\Windows\Start Menu\Programs\Startup"
        startup_dir.mkdir(parents=True, exist_ok=True)

        # Place a malicious script pointing to game dir
        malicious_bat = startup_dir / "evil_autorun.bat"
        malicious_bat.write_text(f'@echo off\nstart "" "{self.test_dir}\\game.exe"\n', encoding="utf-8")

        with patch.dict(os.environ, {"APPDATA": str(fake_appdata), "PROGRAMDATA": str(self.test_dir / "empty")}):
            auditor = PersistenceAuditor(self.test_dir)
            entries = auditor.audit_startup_folder()
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0].entry_type, "StartupFolder")
            self.assertEqual(entries[0].name, "evil_autorun.bat")

            # Test removing startup persistence
            removed = auditor.remove_persistence(entries[0])
            self.assertTrue(removed)
            self.assertFalse(malicious_bat.exists())

    @patch("winreg.OpenKey")
    @patch("winreg.QueryInfoKey")
    @patch("winreg.EnumKey")
    @patch("winreg.QueryValueEx")
    def test_persistence_auditor_services(self, mock_query_val, mock_enum_key, mock_query_info, mock_open_key):
        mock_open_key.return_value.__enter__.return_value = MagicMock()
        mock_query_info.return_value = (1, 0, 0)
        mock_enum_key.return_value = "MaliciousGameService"
        mock_query_val.return_value = (f'"{self.test_dir}\\miner_service.exe" --run', 1)

        auditor = PersistenceAuditor(self.test_dir)
        entries = auditor.audit_services()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].entry_type, "Service")
        self.assertEqual(entries[0].name, "MaliciousGameService")
        self.assertTrue(entries[0].is_malicious)


if __name__ == "__main__":
    unittest.main()
