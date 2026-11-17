"""
Comprehensive test suite for GameCleaner modules.
"""
from pathlib import Path
import shutil
import tempfile
import unittest

from gamecleaner.analyzer import PEScanner, ThreatSeverity, calculate_entropy
from gamecleaner.cleaner import EmulatorReplacer, QuarantineManager
from gamecleaner.containment import FirewallManager, SandboxGenerator
from gamecleaner.pipeline import GameCleanerPipeline


class TestGameCleaner(unittest.TestCase):

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="gamecleaner_test_"))
        self.explorer_path = Path(r"C:\Windows\explorer.exe")

    def tearDown(self):
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_entropy_calculation(self):
        zero_data = b"\x00" * 1000
        self.assertEqual(calculate_entropy(zero_data), 0.0)

        # High entropy data
        import os
        random_data = os.urandom(2048)
        self.assertGreater(calculate_entropy(random_data), 7.0)

    def test_pe_scanner_on_real_binary(self):
        if not self.explorer_path.exists():
            self.skipTest("explorer.exe not found on system")

        scanner = PEScanner()
        result = scanner.scan_file(self.explorer_path)

        self.assertTrue(result.is_pe)
        self.assertIn(result.architecture, ("x64", "x86", "ARM64"))
        self.assertGreater(len(result.sha256), 20)
        self.assertGreater(len(result.sections), 0)
        # Windows system explorer.exe has an embedded Authenticode signature
        self.assertTrue(result.is_signed)
        self.assertEqual(result.overall_severity, ThreatSeverity.CLEAN.value)

    def test_quarantine_manager(self):
        qm = QuarantineManager(self.test_dir)
        dummy_file = self.test_dir / "suspicious_payload.exe"
        dummy_file.write_text("dummy payload content")

        # Quarantine file
        dest = qm.quarantine_file(dummy_file, reason="Test Infostealer", sha256="fake_sha256")
        self.assertIsNotNone(dest)
        self.assertFalse(dummy_file.exists())
        self.assertTrue(dest.exists())
        self.assertTrue(dest.name.endswith(".quarantined"))

        # Verify listing
        items = qm.list_quarantined()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].reason, "Test Infostealer")

        # Test restore
        success = qm.restore_file(dest.name)
        self.assertTrue(success)
        self.assertTrue(dummy_file.exists())
        self.assertEqual(len(qm.list_quarantined()), 0)

    def test_firewall_manager(self):
        fm = FirewallManager(self.test_dir)
        dummy_exe = self.test_dir / "game.exe"
        dummy_exe.write_text("dummy exe")

        block_ps1, unblock_ps1 = fm.generate_scripts()
        self.assertTrue(block_ps1.exists())
        self.assertTrue(unblock_ps1.exists())

        content = block_ps1.read_text(encoding="utf-8")
        self.assertIn("New-NetFirewallRule", content)
        self.assertIn("Outbound", content)
        self.assertIn("Block", content)
        self.assertIn("game.exe", content)

    def test_sandbox_generator(self):
        sg = SandboxGenerator(self.test_dir)
        wsb = sg.generate_wsb(read_only=True, v_gpu=True, allow_network=False)

        self.assertTrue(wsb.exists())
        xml_content = wsb.read_text(encoding="utf-8")
        self.assertIn("<Networking>Disable</Networking>", xml_content)
        self.assertIn("<VGpu>Enable</VGpu>", xml_content)
        self.assertIn("<ReadOnly>true</ReadOnly>", xml_content)
        self.assertIn(str(self.test_dir), xml_content)

    def test_emulator_replacer_detection(self):
        er = EmulatorReplacer(self.test_dir)
        dummy_dll = self.test_dir / "steam_api64.dll"
        dummy_dll.write_text("fake dll")
        appid_txt = self.test_dir / "steam_appid.txt"
        appid_txt.write_text("1091500")

        targets = er.find_drm_targets()
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].dll_name, "steam_api64.dll")
        self.assertEqual(targets[0].architecture, "x64")
        self.assertEqual(targets[0].app_id, "1091500")

        # Test backup
        backup_path = er.backup_dll(targets[0])
        self.assertTrue(backup_path.exists())


if __name__ == "__main__":
    unittest.main()
