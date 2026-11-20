import os
from pathlib import Path
import tempfile
import unittest

from gamecleaner.analyzer.anticheat_detector import (
    AntiCheatDetector,
    AntiCheatFinding,
    AntiCheatScanReport,
    AntiCheatStatus,
    AntiCheatType,
)


class TestAntiCheatDetector(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.game_dir = Path(self.temp_dir.name)
        self.detector = AntiCheatDetector(self.game_dir)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_empty_game_folder(self):
        report = self.detector.scan()
        self.assertEqual(len(report.findings), 0)
        self.assertFalse(report.has_active_anticheat)
        self.assertFalse(report.has_byovd_risk)
        self.assertFalse(report.blocks_offline_emulator)
        self.assertIn("No third-party Anti-Cheat", report.summary)

    def test_easy_anti_cheat_active(self):
        # Create full EAC suite
        (self.game_dir / "EasyAntiCheat.sys").write_bytes(b"\x00" * 1024)
        (self.game_dir / "EasyAntiCheat_Setup.exe").write_bytes(b"MZ" + b"\x00" * 100)
        # Real client DLL > 50KB
        (self.game_dir / "EasyAntiCheat_x64.dll").write_bytes(b"MZ" + b"\x00" * (60 * 1024))

        report = self.detector.scan()
        eac_findings = [f for f in report.findings if f.anticheat_type == AntiCheatType.EASY_ANTI_CHEAT.value]
        self.assertEqual(len(eac_findings), 1)
        finding = eac_findings[0]
        self.assertEqual(finding.status, AntiCheatStatus.ACTIVE.value)
        self.assertTrue(finding.byovd_risk)
        self.assertTrue(finding.blocks_offline_play)
        self.assertTrue(report.has_byovd_risk)
        self.assertTrue(report.blocks_offline_emulator)

    def test_easy_anti_cheat_fake_bypassed(self):
        # Create EAC files with a dummy cracked DLL (< 35KB)
        (self.game_dir / "EasyAntiCheat.sys").write_bytes(b"\x00" * 1024)
        (self.game_dir / "EasyAntiCheat_x64.dll").write_bytes(b"MZ" + b"\x00" * (10 * 1024))

        report = self.detector.scan()
        eac_findings = [f for f in report.findings if f.anticheat_type == AntiCheatType.EASY_ANTI_CHEAT.value]
        self.assertEqual(len(eac_findings), 1)
        finding = eac_findings[0]
        self.assertEqual(finding.status, AntiCheatStatus.FAKE_BYPASSED.value)
        self.assertFalse(finding.blocks_offline_play)

    def test_battleye_active(self):
        (self.game_dir / "BEDaisy.sys").write_bytes(b"\x00" * 2048)
        (self.game_dir / "BEService.exe").write_bytes(b"MZ" + b"\x00" * 500)
        (self.game_dir / "BEClient_x64.dll").write_bytes(b"MZ" + b"\x00" * (80 * 1024))

        report = self.detector.scan()
        be_findings = [f for f in report.findings if f.anticheat_type == AntiCheatType.BATTLE_EYE.value]
        self.assertEqual(len(be_findings), 1)
        finding = be_findings[0]
        self.assertEqual(finding.status, AntiCheatStatus.ACTIVE.value)
        self.assertTrue(finding.byovd_risk)
        self.assertTrue(finding.blocks_offline_play)

    def test_battleye_bypassed(self):
        (self.game_dir / "BEDaisy.sys").write_bytes(b"\x00" * 2048)
        # Dummy BEClient DLL < 35KB
        (self.game_dir / "BEClient_x64.dll").write_bytes(b"MZ" + b"\x00" * (5 * 1024))

        report = self.detector.scan()
        be_findings = [f for f in report.findings if f.anticheat_type == AntiCheatType.BATTLE_EYE.value]
        self.assertEqual(len(be_findings), 1)
        finding = be_findings[0]
        self.assertEqual(finding.status, AntiCheatStatus.FAKE_BYPASSED.value)
        self.assertFalse(finding.blocks_offline_play)

    def test_denuvo_binary_scan_active(self):
        # Binary with Denuvo signature strings and .adata section marker
        game_exe = self.game_dir / "DenuvoProtectedGame.exe"
        header = b"MZ" + b"\x00" * 40 + b".adata\x00\x00" + b"\x00" * 50
        content = header + b"denuvo anti-tamper" + b"\x00" * 20 + b"Denuvo Ticket"
        game_exe.write_bytes(content)

        findings = self.detector.scan_binary(game_exe)
        denuvo = [f for f in findings if f.anticheat_type == AntiCheatType.DENUVO.value]
        self.assertEqual(len(denuvo), 1)
        self.assertEqual(denuvo[0].status, AntiCheatStatus.ACTIVE.value)
        self.assertTrue(denuvo[0].blocks_offline_play)

    def test_denuvo_binary_scan_bypassed_by_crack(self):
        # Binary with Denuvo signature, but game folder contains scene crack (EMP.dll)
        (self.game_dir / "emp.dll").write_bytes(b"MZ" + b"\x00" * 100)
        game_exe = self.game_dir / "CrackedDenuvoGame.exe"
        game_exe.write_bytes(b"MZ" + b"\x00" * 50 + b"denuvo.com" + b"\x00" * 50)

        findings = self.detector.scan_binary(game_exe)
        denuvo = [f for f in findings if f.anticheat_type == AntiCheatType.DENUVO.value]
        self.assertEqual(len(denuvo), 1)
        self.assertEqual(denuvo[0].status, AntiCheatStatus.FAKE_BYPASSED.value)
        self.assertFalse(denuvo[0].blocks_offline_play)

    def test_denuvo_anticheat_driver(self):
        (self.game_dir / "denuvo64.sys").write_bytes(b"\x00" * 1024)
        report = self.detector.scan()
        denuvo_drv = [f for f in report.findings if "Denuvo Anti-Cheat" in f.name]
        self.assertEqual(len(denuvo_drv), 1)
        self.assertTrue(denuvo_drv[0].byovd_risk)
        self.assertTrue(denuvo_drv[0].blocks_offline_play)

    def test_riot_vanguard_detection(self):
        (self.game_dir / "vgk.sys").write_bytes(b"\x00" * 2048)
        (self.game_dir / "vgk.dll").write_bytes(b"MZ" + b"\x00" * 100)

        report = self.detector.scan()
        vgk = [f for f in report.findings if f.anticheat_type == AntiCheatType.VANGUARD.value]
        self.assertEqual(len(vgk), 1)
        self.assertEqual(vgk[0].status, AntiCheatStatus.ACTIVE.value)
        self.assertTrue(vgk[0].byovd_risk)
        self.assertTrue(vgk[0].blocks_offline_play)
        self.assertEqual(vgk[0].severity, "CRITICAL")

    def test_vmprotect_binary_detection(self):
        vmp_exe = self.game_dir / "ProtectedVMP.exe"
        vmp_exe.write_bytes(b"MZ" + b"\x00" * 40 + b".vmp0\x00\x00\x00" + b"\x00" * 20 + b"VMProtect begin")

        findings = self.detector.scan_binary(vmp_exe)
        vmp = [f for f in findings if f.anticheat_type == AntiCheatType.VMPROTECT.value]
        self.assertEqual(len(vmp), 1)
        self.assertEqual(vmp[0].status, AntiCheatStatus.ACTIVE.value)
        self.assertFalse(vmp[0].byovd_risk)
        self.assertFalse(vmp[0].blocks_offline_play)

    def test_themida_binary_detection(self):
        themida_exe = self.game_dir / "ThemidaPacked.exe"
        themida_exe.write_bytes(b"MZ" + b"\x00" * 40 + b".themida\x00" + b"\x00" * 20 + b"Oreans Technologies")

        findings = self.detector.scan_binary(themida_exe)
        themida = [f for f in findings if f.anticheat_type == AntiCheatType.THEMIDA.value]
        self.assertEqual(len(themida), 1)
        self.assertEqual(themida[0].status, AntiCheatStatus.ACTIVE.value)
        self.assertFalse(themida[0].byovd_risk)

    def test_safedisc_vulnerable_driver(self):
        (self.game_dir / "SECDRV.SYS").write_bytes(b"\x00" * 4096)
        report = self.detector.scan()
        safedisc = [f for f in report.findings if f.anticheat_type == AntiCheatType.SAFEDISC.value]
        self.assertEqual(len(safedisc), 1)
        self.assertEqual(safedisc[0].status, AntiCheatStatus.VULNERABLE_DRIVER.value)
        self.assertTrue(safedisc[0].byovd_risk)
        self.assertTrue(safedisc[0].blocks_offline_play)
        self.assertEqual(safedisc[0].severity, "CRITICAL")

    def test_securom_detection(self):
        (self.game_dir / "paul.dll").write_bytes(b"MZ" + b"\x00" * 200)
        report = self.detector.scan()
        securom = [f for f in report.findings if f.anticheat_type == AntiCheatType.SECUROM.value]
        self.assertEqual(len(securom), 1)
        self.assertEqual(securom[0].status, AntiCheatStatus.ACTIVE.value)
        self.assertTrue(securom[0].blocks_offline_play)

    def test_entropy_calculation(self):
        # 1. Zero entropy
        zero_ent = AntiCheatDetector.calculate_entropy(b"\x00" * 1000)
        self.assertEqual(zero_ent, 0.0)

        # 2. High entropy
        high_ent_data = bytes([i % 256 for i in range(2000)])
        high_ent = AntiCheatDetector.calculate_entropy(high_ent_data)
        self.assertGreater(high_ent, 7.0)


if __name__ == "__main__":
    unittest.main()
