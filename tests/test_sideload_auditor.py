import tempfile
import unittest
from pathlib import Path

from gamecleaner.analyzer.sideload_auditor import SideloadAuditor, SideloadFinding
from gamecleaner.analyzer.threat_rules import ThreatCategory, ThreatSeverity


class TestSideloadAuditor(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.game_dir = Path(self.temp_dir.name).resolve()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_clean_folder_no_sideloads(self):
        game_exe = self.game_dir / "Game.exe"
        game_exe.write_bytes(b"MZ" + b"\x00" * 100)
        clean_dll = self.game_dir / "GameEngine.dll"
        clean_dll.write_bytes(b"MZ" + b"\x00" * 100)

        auditor = SideloadAuditor(self.game_dir)
        findings = auditor.audit()
        self.assertEqual(len(findings), 0)

    def test_detect_sideloaded_system_dll(self):
        game_exe = self.game_dir / "Game.exe"
        game_exe.write_bytes(b"MZ" + b"\x00" * 100)
        # Sideloaded version.dll in game root
        sideload = self.game_dir / "version.dll"
        sideload.write_bytes(b"MZ" + b"\x00" * 200)

        auditor = SideloadAuditor(self.game_dir)
        findings = auditor.audit()
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.dll_name.lower(), "version.dll")
        self.assertEqual(f.target_exe, "Game.exe")
        self.assertFalse(f.is_legitimate_mod)
        self.assertEqual(f.severity, ThreatSeverity.MEDIUM)

    def test_detect_legitimate_reshade_mod(self):
        game_exe = self.game_dir / "Game.exe"
        game_exe.write_bytes(b"MZ" + b"\x00" * 100)
        # ReShade proxy dxgi.dll
        reshade_dll = self.game_dir / "dxgi.dll"
        reshade_dll.write_bytes(b"MZ" + b"\x00" * 50 + b"ReShade effectruntime crosire" + b"\x00" * 50)

        auditor = SideloadAuditor(self.game_dir)
        findings = auditor.audit()
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertTrue(f.is_legitimate_mod)
        self.assertEqual(f.mod_framework, "ReShade")
        self.assertEqual(f.severity, ThreatSeverity.LOW)
        self.assertEqual(f.threat_category, ThreatCategory.HACKTOOL_CRACK)

    def test_detect_legitimate_bepinex_mod(self):
        game_exe = self.game_dir / "Game.exe"
        game_exe.write_bytes(b"MZ" + b"\x00" * 100)
        # BepInEx doorstop winhttp.dll
        bepinex_dll = self.game_dir / "winhttp.dll"
        bepinex_dll.write_bytes(b"MZ" + b"\x00" * 50 + b"doorstop BepInEx mono-2.0" + b"\x00" * 50)

        auditor = SideloadAuditor(self.game_dir)
        findings = auditor.audit()
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertTrue(f.is_legitimate_mod)
        self.assertEqual(f.mod_framework, "BepInEx")


if __name__ == "__main__":
    unittest.main()
