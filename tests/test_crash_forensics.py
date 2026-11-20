import os
from pathlib import Path
import tempfile
import unittest

from gamecleaner.analyzer.crash_forensics import (
    CrashForensics,
    CrashReport,
    FaultingModule,
    RemediationStep,
    CrashCauseCategory,
    normalize_exception_code,
)


class TestCrashForensics(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.work_dir = Path(self.temp_dir.name)
        self.forensics = CrashForensics(game_dir=self.work_dir)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_normalize_exception_code(self):
        # Hex string formats
        self.assertEqual(normalize_exception_code("0xc0000005"), "0xc0000005")
        self.assertEqual(normalize_exception_code("0xC0000005"), "0xc0000005")
        self.assertEqual(normalize_exception_code("c0000005"), "0xc0000005")

        # Signed integer format (-1073741819 is 0xc0000005)
        self.assertEqual(normalize_exception_code(-1073741819), "0xc0000005")
        self.assertEqual(normalize_exception_code("-1073741819"), "0xc0000005")

        # Unsigned integer
        self.assertEqual(normalize_exception_code(3221225477), "0xc0000005")

        # Other known exceptions
        self.assertEqual(normalize_exception_code("0xc0000139"), "0xc0000139")
        self.assertEqual(normalize_exception_code("0xc000007b"), "0xc000007b")
        self.assertEqual(normalize_exception_code("0xc000001d"), "0xc000001d")
        self.assertEqual(normalize_exception_code("0x80000003"), "0x80000003")
        self.assertEqual(normalize_exception_code("0xe06d7363"), "0xe06d7363")

    def test_faulting_module_classification(self):
        m_sys = FaultingModule.classify("ntdll.dll")
        self.assertTrue(m_sys.is_system_dll)
        self.assertFalse(m_sys.is_emulator)

        m_emu = FaultingModule.classify("steam_api64.dll")
        self.assertTrue(m_emu.is_emulator)
        self.assertFalse(m_emu.is_runtime)

        m_rt = FaultingModule.classify("vcruntime140.dll")
        self.assertTrue(m_rt.is_runtime)
        self.assertFalse(m_rt.is_proxy)

        m_proxy = FaultingModule.classify("dxgi.dll")
        self.assertTrue(m_proxy.is_proxy)

        m_game = FaultingModule.classify("SniperElite.exe", app_name="SniperElite.exe")
        self.assertTrue(m_game.is_game_binary)

    def test_parse_event_1000_message(self):
        msg = (
            "Faulting application name: SniperElite.exe, version: 1.0.0.0, time stamp: 0x50123456\r\n"
            "Faulting module name: steam_api64.dll, version: 0.0.0.0, time stamp: 0x51234567\r\n"
            "Exception code: 0xc0000005\r\n"
            "Fault offset: 0x000000000001a420\r\n"
            "Faulting process id: 0x1a2b\r\n"
            "Faulting application path: C:\\Games\\SniperElite\\bin\\SniperElite.exe\r\n"
            "Faulting module path: C:\\Games\\SniperElite\\bin\\steam_api64.dll\r\n"
            "Report Id: 11223344-5566-7788-99aa-bbccddeeff00\r\n"
        )
        report = self.forensics.parse_event_message(msg, timestamp="2026-11-20T10:00:00Z")
        self.assertIsNotNone(report)
        self.assertEqual(report.application_name, "SniperElite.exe")
        self.assertEqual(report.faulting_module.name, "steam_api64.dll")
        self.assertTrue(report.faulting_module.is_emulator)
        self.assertEqual(report.exception_code, "0xc0000005")
        self.assertEqual(report.exception_name, "STATUS_ACCESS_VIOLATION")
        self.assertEqual(report.fault_offset, "0x000000000001a420")
        self.assertEqual(report.process_id, 0x1a2b)
        self.assertEqual(report.root_cause_category, CrashCauseCategory.EMULATOR_INCOMPATIBILITY.value)
        self.assertGreater(len(report.remediation_steps), 0)

    def test_parse_event_1001_message(self):
        msg = (
            "Fault bucket 123456, type 5\r\n"
            "Event Name: APPCRASH\r\n"
            "Problem signature:\r\n"
            "P1: Borderlands2.exe\r\n"
            "P2: 1.8.4.0\r\n"
            "P3: 52000000\r\n"
            "P4: msvcp110.dll\r\n"
            "P5: 11.0.50727.1\r\n"
            "P6: 50112233\r\n"
            "P7: c0000005\r\n"
            "P8: 00012345\r\n"
        )
        report = self.forensics.parse_event_message(msg, event_id=1001)
        self.assertIsNotNone(report)
        self.assertEqual(report.application_name, "Borderlands2.exe")
        self.assertEqual(report.faulting_module.name, "msvcp110.dll")
        self.assertTrue(report.faulting_module.is_runtime)
        self.assertEqual(report.root_cause_category, CrashCauseCategory.MISSING_RUNTIME.value)

    def test_wer_file_parsing(self):
        wer_content = (
            "Version=1\r\n"
            "EventType=APPCRASH\r\n"
            "EventTime=132800000000000000\r\n"
            "ReportIdentifier=test-report-uuid\r\n"
            "Sig[0].Name=Application Name\r\n"
            "Sig[0].Value=GameLauncher.exe\r\n"
            "Sig[3].Name=Fault Module Name\r\n"
            "Sig[3].Value=dxgi.dll\r\n"
            "Sig[6].Name=Exception Code\r\n"
            "Sig[6].Value=c0000005\r\n"
            "Sig[7].Name=Fault Offset\r\n"
            "Sig[7].Value=00054321\r\n"
        )
        wer_path = self.work_dir / "Report.wer"
        # Write as UTF-16 LE
        wer_path.write_bytes(wer_content.encode("utf-16-le"))

        report = self.forensics.parse_wer_file(wer_path)
        self.assertIsNotNone(report)
        self.assertEqual(report.application_name, "GameLauncher.exe")
        self.assertEqual(report.faulting_module.name, "dxgi.dll")
        self.assertTrue(report.faulting_module.is_proxy)
        self.assertEqual(report.root_cause_category, CrashCauseCategory.SIDELOAD_CONFLICT.value)

    def test_correlation_missing_runtime(self):
        report = self.forensics.analyze_mock(
            application_name="CyberGame.exe",
            faulting_module="vcruntime140_1.dll",
            exception_code="0xc0000005",
        )
        self.assertEqual(report.root_cause_category, CrashCauseCategory.MISSING_RUNTIME.value)
        self.assertEqual(report.confidence, "HIGH")
        cmds = [step.command for step in report.remediation_steps if step.command]
        self.assertTrue(any("deps" in c for c in cmds))

    def test_correlation_emulator_entrypoint_missing(self):
        report = self.forensics.analyze_mock(
            application_name="Game.exe",
            faulting_module="steam_api64.dll",
            exception_code="0xc0000139",
        )
        self.assertEqual(report.root_cause_category, CrashCauseCategory.EMULATOR_INCOMPATIBILITY.value)
        self.assertIn("Entry Point Not Found", report.root_cause_description)
        cmds = [step.command for step in report.remediation_steps if step.command]
        self.assertTrue(any("replace-emu" in c or "clean-all" in c for c in cmds))

    def test_correlation_steam_stub_packed(self):
        # Create an executable containing SteamStub .bind signature
        stub_exe = self.work_dir / "SteamStubbedGame.exe"
        stub_exe.write_bytes(b"MZ" + b"\x00" * 40 + b"SteamDrmPfn" + b"\x00" * 20 + b".bind" + b"\x00" * 100)

        report = self.forensics.analyze_mock(
            application_name="SteamStubbedGame.exe",
            faulting_module="SteamStubbedGame.exe",
            exception_code="0xc0000005",
            app_path=str(stub_exe),
            game_dir=self.work_dir,
        )
        self.assertEqual(report.root_cause_category, CrashCauseCategory.STEAM_STUB_PACKED.value)
        self.assertEqual(report.confidence, "HIGH")
        cmds = [step.command for step in report.remediation_steps if step.command]
        self.assertTrue(any("steamless" in c for c in cmds))

    def test_correlation_sideload_proxy_conflict(self):
        report = self.forensics.analyze_mock(
            application_name="ModdedGame.exe",
            faulting_module="version.dll",
            exception_code="0xc0000005",
        )
        self.assertEqual(report.root_cause_category, CrashCauseCategory.SIDELOAD_CONFLICT.value)
        cmds = [step.command for step in report.remediation_steps if step.command]
        self.assertTrue(any("sideload" in c for c in cmds))

    def test_correlation_firewall_socket_trap(self):
        report = self.forensics.analyze_mock(
            application_name="CoopGame.exe",
            faulting_module="ws2_32.dll",
            exception_code="0xc0000005",
        )
        self.assertEqual(report.root_cause_category, CrashCauseCategory.FIREWALL_SOCKET_BLOCK.value)
        self.assertIn("Firewall", report.root_cause_description)

    def test_correlation_arch_mismatch(self):
        report = self.forensics.analyze_mock(
            application_name="CrashApp.exe",
            faulting_module="CrashApp.exe",
            exception_code="0xc000007b",
        )
        self.assertEqual(report.root_cause_category, CrashCauseCategory.ARCH_MISMATCH.value)

    def test_correlation_illegal_instruction(self):
        report = self.forensics.analyze_mock(
            application_name="AvxGame.exe",
            faulting_module="AvxGame.exe",
            exception_code="0xc000001d",
        )
        self.assertEqual(report.root_cause_category, CrashCauseCategory.ILLEGAL_INSTRUCTION.value)

    def test_correlation_cpp_exception(self):
        report = self.forensics.analyze_mock(
            application_name="EngineGame.exe",
            faulting_module="KERNELBASE.dll",
            exception_code="0xe06d7363",
        )
        self.assertEqual(report.root_cause_category, CrashCauseCategory.CPP_UNHANDLED_EXCEPTION.value)

    def test_get_event_log_crashes_offline_graceful(self):
        # Must execute without unhandled exceptions on any host
        res = self.forensics.get_event_log_crashes(app_name="NonExistentGame12345.exe")
        self.assertIsInstance(res, list)

    def test_scan_wer_archives_empty_dir(self):
        empty_dir = self.work_dir / "EmptyWer"
        empty_dir.mkdir()
        res = self.forensics.scan_wer_archives(search_dirs=[empty_dir])
        self.assertEqual(res, [])


if __name__ == "__main__":
    unittest.main()
