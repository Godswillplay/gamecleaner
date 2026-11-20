from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from gamecleaner.analyzer.driver_auditor import (
    DriverAuditor,
    DriverFinding,
    KNOWN_BYOVD_DRIVERS,
    lookup_byovd,
)


class TestDriverAuditor(unittest.TestCase):
    """Unit tests for DriverAuditor (Kernel driver & BYOVD detection)."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.game_dir = Path(self.temp_dir.name).resolve()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_clean_folder_no_drivers(self):
        (self.game_dir / "Game.exe").write_bytes(b"MZ" + b"\x00" * 100)
        (self.game_dir / "readme.txt").write_text("Clean game folder")

        auditor = DriverAuditor(self.game_dir)
        findings = auditor.audit()
        self.assertEqual(len(findings), 0)

        summary = auditor.get_summary(findings)
        self.assertEqual(summary["total_findings"], 0)
        self.assertFalse(summary["has_threats"])

    def test_lookup_all_required_byovd_signatures(self):
        # All required BYOVD drivers specified in prompt:
        required_targets = [
            ("gdrv.sys", "gdrv"),
            ("mhyprot2.sys", "mhyprot2"),
            ("procexp.sys", "procexp"),
            ("procexp152.sys", "procexp152"),
            ("rtcore64.sys", "rtcore64"),
            ("rtcore32.sys", "rtcore32"),
            ("iqvw64e.sys", "iqvw64e"),
            ("asiodrv.sys", "asiodrv"),
            ("dbutil_2_3.sys", "dbutil_2_3"),
            ("ene.sys", "ene"),
        ]

        for with_ext, without_ext in required_targets:
            res_ext = lookup_byovd(with_ext)
            res_stem = lookup_byovd(without_ext)
            self.assertIsNotNone(res_ext, f"Failed lookup for {with_ext}")
            self.assertIsNotNone(res_stem, f"Failed lookup for {without_ext}")
            self.assertEqual(res_ext["canonical_name"], with_ext)
            self.assertIn(res_ext["severity"], ("CRITICAL", "HIGH"))

    @patch("gamecleaner.analyzer.driver_auditor.check_authenticode_signature", return_value="Valid")
    @patch("gamecleaner.analyzer.driver_auditor.check_is_microsoft_driver", return_value=False)
    def test_detect_byovd_binary_mhyprot2(self, mock_ms, mock_sig):
        driver_path = self.game_dir / "mhyprot2.sys"
        driver_path.write_bytes(b"MZ" + b"\x00" * 200)

        auditor = DriverAuditor(self.game_dir)
        findings = auditor.scan_drivers()

        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.driver_name, "mhyprot2.sys")
        self.assertTrue(f.is_known_vulnerable_byovd)
        self.assertEqual(f.severity, "CRITICAL")
        self.assertIn("HoYoverse", f.byovd_details)
        self.assertTrue(f.is_signed)
        self.assertFalse(f.is_microsoft)

    @patch("gamecleaner.analyzer.driver_auditor.check_authenticode_signature", return_value="Valid")
    @patch("gamecleaner.analyzer.driver_auditor.check_is_microsoft_driver", return_value=False)
    def test_detect_byovd_binary_gdrv(self, mock_ms, mock_sig):
        driver_path = self.game_dir / "gdrv.sys"
        driver_path.write_bytes(b"MZ" + b"\x00" * 200)

        auditor = DriverAuditor(self.game_dir)
        findings = auditor.scan_drivers()

        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.driver_name, "gdrv.sys")
        self.assertTrue(f.is_known_vulnerable_byovd)
        self.assertEqual(f.severity, "CRITICAL")
        self.assertIn("Gigabyte", f.byovd_details)

    @patch("gamecleaner.analyzer.driver_auditor.check_authenticode_signature", return_value="NotSigned")
    def test_detect_unsigned_kernel_driver(self, mock_sig):
        driver_path = self.game_dir / "unknown_custom.sys"
        driver_path.write_bytes(b"MZ" + b"\x00" * 200)

        auditor = DriverAuditor(self.game_dir)
        findings = auditor.scan_drivers()

        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.driver_name, "unknown_custom.sys")
        self.assertFalse(f.is_signed)
        self.assertFalse(f.is_microsoft)
        self.assertFalse(f.is_known_vulnerable_byovd)
        self.assertEqual(f.severity, "HIGH")
        self.assertIn("Unsigned kernel driver", f.description)

    @patch("gamecleaner.analyzer.driver_auditor.check_authenticode_signature", return_value="Valid")
    @patch("gamecleaner.analyzer.driver_auditor.check_is_microsoft_driver", return_value=True)
    def test_detect_signed_microsoft_driver(self, mock_ms, mock_sig):
        driver_path = self.game_dir / "ms_legit.sys"
        driver_path.write_bytes(b"MZ" + b"\x00" * 200)

        auditor = DriverAuditor(self.game_dir)
        findings = auditor.scan_drivers()

        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertTrue(f.is_signed)
        self.assertTrue(f.is_microsoft)
        self.assertFalse(f.is_known_vulnerable_byovd)
        self.assertEqual(f.severity, "LOW")

    @patch("gamecleaner.analyzer.driver_auditor.check_authenticode_signature", return_value="Valid")
    @patch("gamecleaner.analyzer.driver_auditor.check_is_microsoft_driver", return_value=False)
    def test_detect_signed_third_party_driver(self, mock_ms, mock_sig):
        driver_path = self.game_dir / "easyanticheat.sys"
        driver_path.write_bytes(b"MZ" + b"\x00" * 200)

        auditor = DriverAuditor(self.game_dir)
        findings = auditor.scan_drivers()

        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertTrue(f.is_signed)
        self.assertFalse(f.is_microsoft)
        self.assertFalse(f.is_known_vulnerable_byovd)
        self.assertEqual(f.severity, "MEDIUM")

    def test_detect_script_sc_create_mhyprot(self):
        script_path = self.game_dir / "install.bat"
        script_path.write_text(
            '@echo off\n'
            'sc create MhyProt binPath= "%~dp0mhyprot2.sys" type= kernel\n'
            'sc start MhyProt\n',
            encoding="utf-8",
        )

        auditor = DriverAuditor(self.game_dir)
        findings = auditor.scan_scripts()

        self.assertGreaterEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.driver_name, "mhyprot2.sys")
        self.assertTrue(f.is_known_vulnerable_byovd)
        self.assertEqual(f.severity, "CRITICAL")
        self.assertIn("install.bat", f.description)

    def test_detect_script_sc_start_gdrv(self):
        script_path = self.game_dir / "setup.cmd"
        script_path.write_text(
            '@echo off\n'
            'sc.exe start gdrv\n',
            encoding="utf-8",
        )

        auditor = DriverAuditor(self.game_dir)
        findings = auditor.scan_scripts()

        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.driver_name, "gdrv")
        self.assertTrue(f.is_known_vulnerable_byovd)
        self.assertEqual(f.severity, "CRITICAL")

    def test_detect_script_ps_new_service(self):
        script_path = self.game_dir / "install_driver.ps1"
        script_path.write_text(
            'New-Service -Name "RTCore" -BinaryPathName "$PSScriptRoot\\rtcore64.sys" -StartupType Manual\n',
            encoding="utf-8",
        )

        auditor = DriverAuditor(self.game_dir)
        findings = auditor.scan_scripts()

        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.driver_name, "rtcore64.sys")
        self.assertTrue(f.is_known_vulnerable_byovd)
        self.assertEqual(f.severity, "CRITICAL")

    def test_detect_script_unknown_driver_service(self):
        script_path = self.game_dir / "run.bat"
        script_path.write_text(
            'sc create CustomKernelService binPath= "%~dp0custom_payload.sys" type= kernel\n',
            encoding="utf-8",
        )

        auditor = DriverAuditor(self.game_dir)
        findings = auditor.scan_scripts()

        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.driver_name, "custom_payload.sys")
        self.assertFalse(f.is_known_vulnerable_byovd)
        self.assertEqual(f.severity, "HIGH")

    @patch("gamecleaner.analyzer.driver_auditor.check_authenticode_signature", return_value="NotSigned")
    def test_full_audit_combines_sys_and_scripts(self, mock_sig):
        # 1. Unsigned .sys binary
        (self.game_dir / "iqvw64e.sys").write_bytes(b"MZ" + b"\x00" * 150)

        # 2. Installer script
        (self.game_dir / "install.bat").write_text(
            'sc create IntelNet binPath= "%~dp0iqvw64e.sys" type= kernel\n',
            encoding="utf-8",
        )

        auditor = DriverAuditor(self.game_dir)
        findings = auditor.audit()

        self.assertGreaterEqual(len(findings), 2)
        byovd_findings = [f for f in findings if f.is_known_vulnerable_byovd]
        self.assertEqual(len(byovd_findings), 2)

        summary = auditor.get_summary(findings)
        self.assertGreaterEqual(summary["critical_count"], 2)
        self.assertTrue(summary["has_threats"])


if __name__ == "__main__":
    unittest.main()
