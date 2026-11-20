"""
Unit and integration tests for gamecleaner.analyzer.memory_scanner.
Covers:
- Loaded module enumeration & synthetic mock execution
- Unauthorized DLL injections from %TEMP%, %APPDATA%, Downloads
- Unsigned and untrusted DLLs in process space
- Malicious WinSock send/recv detour hooks & crypto miner detection
- Sideloaded DLL verification (System32 vs game folder mods vs external injections)
- Structured MemoryAuditReport generation and serialization
"""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from gamecleaner.analyzer.memory_scanner import (
    MemoryScanner,
    MemoryAuditReport,
    ModuleInfo,
    SuspiciousModule,
    HOOK_LIBRARY_PATTERNS,
    CRYPTO_MINER_KEYWORDS,
    WINSOCK_HOOK_APIS,
)
from gamecleaner.analyzer.threat_rules import ThreatCategory, ThreatSeverity


class TestMemoryScannerDataClasses(unittest.TestCase):
    """Tests for ModuleInfo, SuspiciousModule, and MemoryAuditReport dataclasses."""

    def test_module_info_to_dict(self):
        mod = ModuleInfo(
            name="test.dll",
            path=r"C:\Games\MyGame\test.dll",
            base_address=0x180000000,
            size=102400,
            is_signed=True,
            signature_status="Valid",
            hook_indicators=["hook_init"],
            description="Test Module",
        )
        d = mod.to_dict()
        self.assertEqual(d["name"], "test.dll")
        self.assertEqual(d["base_address"], hex(0x180000000))
        self.assertEqual(d["signature_status"], "Valid")
        self.assertIn("hook_init", d["hook_indicators"])

    def test_suspicious_module_to_dict(self):
        sm = SuspiciousModule(
            name="inject.dll",
            path=r"C:\Users\Test\AppData\Local\Temp\inject.dll",
            threat_category=ThreatCategory.INJECTION.value,
            severity=ThreatSeverity.CRITICAL.value,
            reasons=["Loaded from Temp directory", "Detour hook"],
            signature_status="NotSigned",
            base_address=hex(0x7FFA1234),
        )
        d = sm.to_dict()
        self.assertEqual(d["name"], "inject.dll")
        self.assertEqual(d["severity"], ThreatSeverity.CRITICAL.value)
        self.assertEqual(len(d["reasons"]), 2)

    def test_memory_audit_report_properties_and_markdown(self):
        # Clean report
        clean_rep = MemoryAuditReport(
            pid=1234,
            process_name="Game.exe",
            modules_scanned=20,
            suspicious_modules=[],
            threat_level=ThreatSeverity.CLEAN.value,
            recommendations=["All clean"],
        )
        self.assertTrue(clean_rep.is_safe)
        self.assertFalse(clean_rep.has_critical_threat)

        # Critical report
        crit_sm = SuspiciousModule(
            name="miner.dll",
            path=r"C:\Temp\miner.dll",
            threat_category=ThreatCategory.COINMINER.value,
            severity=ThreatSeverity.CRITICAL.value,
            reasons=["Cryptocurrency miner"],
        )
        crit_rep = MemoryAuditReport(
            pid=5678,
            process_name="InfectedGame.exe",
            modules_scanned=25,
            suspicious_modules=[crit_sm],
            threat_level=ThreatSeverity.CRITICAL.value,
            recommendations=["Terminate process immediately"],
        )
        self.assertFalse(crit_rep.is_safe)
        self.assertTrue(crit_rep.has_critical_threat)

        md = crit_rep.summary_markdown()
        self.assertIn("# Memory Security Audit Report", md)
        self.assertIn("InfectedGame.exe", md)
        self.assertIn("miner.dll", md)
        self.assertIn("CRITICAL", md)
        self.assertIn("Terminate process immediately", md)

        d = crit_rep.to_dict()
        self.assertEqual(d["pid"], 5678)
        self.assertTrue(d["has_critical_threat"])


class TestPathAndLocationChecks(unittest.TestCase):
    """Tests path resolution and location checking for untrusted directories and system directories."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.game_dir = Path(self.temp_dir.name) / "GameFolder"
        self.game_dir.mkdir(parents=True, exist_ok=True)
        self.scanner = MemoryScanner(game_dir=self.game_dir)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_is_windows_system_path(self):
        self.assertTrue(self.scanner.is_windows_system_path(r"C:\Windows\System32\kernel32.dll"))
        self.assertTrue(self.scanner.is_windows_system_path(r"C:\Windows\SysWOW64\ntdll.dll"))
        self.assertTrue(self.scanner.is_windows_system_path(r"C:\Windows\WinSxS\msvcp140.dll"))
        self.assertFalse(self.scanner.is_windows_system_path(r"C:\Games\Game.exe"))
        self.assertFalse(self.scanner.is_windows_system_path(r"C:\Users\John\Downloads\hook.dll"))

    def test_is_inside_game_dir(self):
        game_dll = self.game_dir / "bin" / "game.dll"
        outside_dll = Path(self.temp_dir.name) / "outside.dll"
        self.assertTrue(self.scanner.is_inside_game_dir(game_dll))
        self.assertFalse(self.scanner.is_inside_game_dir(outside_dll))

    def test_check_untrusted_location(self):
        # Temp path
        is_untr, label = self.scanner.check_untrusted_location(r"C:\Users\User\AppData\Local\Temp\payload.dll")
        self.assertTrue(is_untr)
        self.assertEqual(label, "TEMP")

        # Roaming AppData path
        is_untr, label = self.scanner.check_untrusted_location(r"C:\Users\User\AppData\Roaming\secret\stealer.dll")
        self.assertTrue(is_untr)
        self.assertEqual(label, "APPDATA")

        # Downloads path
        is_untr, label = self.scanner.check_untrusted_location(r"C:\Users\User\Downloads\mod_installer.dll")
        self.assertTrue(is_untr)
        self.assertEqual(label, "DOWNLOADS")

        # System path is not untrusted
        is_untr, _ = self.scanner.check_untrusted_location(r"C:\Windows\System32\user32.dll")
        self.assertFalse(is_untr)

        # File inside game dir is not treated as external untrusted injection
        game_file = self.game_dir / "steam_api64.dll"
        is_untr, _ = self.scanner.check_untrusted_location(game_file)
        self.assertFalse(is_untr)


class TestMaliciousHooksAndCryptoMiners(unittest.TestCase):
    """Tests detection of detour hooks into WinSock and cryptocurrency miners."""

    def setUp(self):
        self.scanner = MemoryScanner()

    def test_crypto_miner_detection_by_name(self):
        for kw in ("xmrig.dll", "libmicrohttpd-dll.dll", "cryptonight_worker.dll", "stratum_proxy.dll"):
            mod = ModuleInfo(name=kw, path=f"C:\\Games\\{kw}")
            is_mal, reasons, cat, sev = self.scanner.check_malicious_hooks(mod)
            self.assertTrue(is_mal, f"Failed to detect miner for {kw}")
            self.assertEqual(sev, ThreatSeverity.CRITICAL.value)
            self.assertEqual(cat, ThreatCategory.COINMINER.value)

    def test_crypto_miner_detection_by_indicator(self):
        mod = ModuleInfo(
            name="helper.dll",
            path=r"C:\Games\helper.dll",
            hook_indicators=["Connecting to monero pool", "nicehash stratum worker"],
        )
        is_mal, reasons, cat, sev = self.scanner.check_malicious_hooks(mod)
        self.assertTrue(is_mal)
        self.assertEqual(cat, ThreatCategory.COINMINER.value)
        self.assertEqual(sev, ThreatSeverity.CRITICAL.value)

    def test_detour_hook_library_detection(self):
        for hook_lib in ("minhook.dll", "detours.dll", "easyhook64.dll", "ws2_32_hook.dll", "sockspy.dll"):
            mod = ModuleInfo(name=hook_lib, path=f"C:\\Games\\{hook_lib}")
            is_mal, reasons, cat, sev = self.scanner.check_malicious_hooks(mod)
            self.assertTrue(is_mal, f"Failed to detect hook library {hook_lib}")
            self.assertEqual(sev, ThreatSeverity.CRITICAL.value)

    def test_winsock_detour_hook_detection(self):
        mod = ModuleInfo(
            name="network_monitor.dll",
            path=r"C:\Games\network_monitor.dll",
            hook_indicators=["Detour wsasend export", "Hooking recv on ws2_32.dll"],
        )
        is_mal, reasons, cat, sev = self.scanner.check_malicious_hooks(mod)
        self.assertTrue(is_mal)
        self.assertEqual(sev, ThreatSeverity.CRITICAL.value)
        self.assertTrue(any("WinSock" in r for r in reasons))

    def test_clean_module_hooks_check(self):
        mod = ModuleInfo(name="clean_game_logic.dll", path=r"C:\Games\clean_game_logic.dll")
        is_mal, reasons, cat, sev = self.scanner.check_malicious_hooks(mod)
        self.assertFalse(is_mal)
        self.assertEqual(sev, ThreatSeverity.CLEAN.value)


class TestSideloadedDLLVerification(unittest.TestCase):
    """Tests verification of sideload-prone Windows system DLLs (version.dll, dxgi.dll, etc.)."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.game_dir = Path(self.temp_dir.name) / "GameDir"
        self.game_dir.mkdir(parents=True, exist_ok=True)
        self.scanner = MemoryScanner(game_dir=self.game_dir)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_sideload_in_system32_is_clean(self):
        # If version.dll is loaded from System32, it is legitimate
        mod = ModuleInfo(name="version.dll", path=r"C:\Windows\System32\version.dll")
        is_susp, reasons, cat, sev = self.scanner.check_sideload_status(mod, self.game_dir)
        self.assertFalse(is_susp)
        self.assertEqual(sev, ThreatSeverity.CLEAN.value)

    def test_sideload_in_game_dir_reshade_mod(self):
        # Legitimate ReShade mod loader proxy
        mod = ModuleInfo(
            name="dxgi.dll",
            path=str(self.game_dir / "dxgi.dll"),
            description="ReShade Post-Processing Effect Runtime",
        )
        is_susp, reasons, cat, sev = self.scanner.check_sideload_status(mod, self.game_dir)
        self.assertFalse(is_susp)
        self.assertEqual(sev, ThreatSeverity.LOW.value)
        self.assertTrue(any("ReShade" in r for r in reasons))

    def test_sideload_in_game_dir_bepinex_mod(self):
        mod = ModuleInfo(
            name="version.dll",
            path=str(self.game_dir / "version.dll"),
            description="BepInEx Unity Doorstop proxy",
        )
        is_susp, reasons, cat, sev = self.scanner.check_sideload_status(mod, self.game_dir)
        self.assertFalse(is_susp)
        self.assertEqual(sev, ThreatSeverity.LOW.value)
        self.assertTrue(any("BepInEx" in r for r in reasons))

    def test_sideload_in_game_dir_unknown_proxy(self):
        # Unrecognized version.dll in game folder (potential crack hook or proxy)
        mod = ModuleInfo(
            name="version.dll",
            path=str(self.game_dir / "version.dll"),
            description="Unknown generic wrapper",
        )
        is_susp, reasons, cat, sev = self.scanner.check_sideload_status(mod, self.game_dir)
        self.assertTrue(is_susp)
        self.assertEqual(sev, ThreatSeverity.MEDIUM.value)
        self.assertEqual(cat, ThreatCategory.HACKTOOL_CRACK.value)

    def test_sideload_outside_game_and_system_dir_is_critical(self):
        # Hostile sideload injection: version.dll loaded from %TEMP% or arbitrary location
        mod = ModuleInfo(
            name="version.dll",
            path=r"C:\Users\John\AppData\Local\Temp\version.dll",
            description="",
        )
        is_susp, reasons, cat, sev = self.scanner.check_sideload_status(mod, self.game_dir)
        self.assertTrue(is_susp)
        self.assertEqual(sev, ThreatSeverity.CRITICAL.value)
        self.assertEqual(cat, ThreatCategory.INJECTION.value)
        self.assertTrue(any("hijacking" in r.lower() for r in reasons))


class TestFullMemoryScanAndReporting(unittest.TestCase):
    """End-to-end memory audit scanning on synthetic process data."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.game_dir = Path(self.temp_dir.name) / "TargetGame"
        self.game_dir.mkdir(parents=True, exist_ok=True)
        self.scanner = MemoryScanner(game_dir=self.game_dir)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_scan_clean_process(self):
        modules = [
            ModuleInfo(name="Game.exe", path=str(self.game_dir / "Game.exe"), is_signed=True, signature_status="Valid"),
            ModuleInfo(name="kernel32.dll", path=r"C:\Windows\System32\kernel32.dll", is_signed=True, signature_status="Valid"),
            ModuleInfo(name="user32.dll", path=r"C:\Windows\System32\user32.dll", is_signed=True, signature_status="Valid"),
            ModuleInfo(name="d3d11.dll", path=r"C:\Windows\System32\d3d11.dll", is_signed=True, signature_status="Valid"),
        ]

        report = self.scanner.scan_modules(modules, pid=1001, process_name="CleanGame.exe", game_dir=self.game_dir)
        self.assertEqual(report.pid, 1001)
        self.assertEqual(report.process_name, "CleanGame.exe")
        self.assertEqual(report.modules_scanned, 4)
        self.assertEqual(len(report.suspicious_modules), 0)
        self.assertTrue(report.is_safe)
        self.assertEqual(report.threat_level, ThreatSeverity.CLEAN.value)
        self.assertTrue(any("clean" in r.lower() for r in report.recommendations))

    def test_scan_temp_injection(self):
        modules = [
            ModuleInfo(name="Game.exe", path=str(self.game_dir / "Game.exe")),
            ModuleInfo(name="kernel32.dll", path=r"C:\Windows\System32\kernel32.dll"),
            # Unauthorized DLL mapped from Temp folder
            ModuleInfo(
                name="dropper_payload.dll",
                path=r"C:\Users\Target\AppData\Local\Temp\dropper_payload.dll",
                signature_status="NotSigned",
            ),
        ]

        report = self.scanner.scan_modules(modules, pid=2002, process_name="VictimGame.exe", game_dir=self.game_dir)
        self.assertFalse(report.is_safe)
        self.assertEqual(report.threat_level, ThreatSeverity.HIGH.value)
        self.assertEqual(len(report.suspicious_modules), 1)

        sm = report.suspicious_modules[0]
        self.assertEqual(sm.name, "dropper_payload.dll")
        self.assertTrue(any("TEMP" in r for r in sm.reasons))

    def test_scan_crypto_miner_and_detour_hook(self):
        modules = [
            ModuleInfo(name="Game.exe", path=str(self.game_dir / "Game.exe")),
            # Crypto miner mapped into game process
            ModuleInfo(
                name="xmrig64.dll",
                path=r"C:\Users\Target\AppData\Local\xmrig64.dll",
                signature_status="NotSigned",
            ),
            # Detour hook intercepting WinSock
            ModuleInfo(
                name="ws2_32_hook.dll",
                path=r"C:\Users\Target\Downloads\ws2_32_hook.dll",
                hook_indicators=["Detour recv on ws2_32.dll"],
                signature_status="NotSigned",
            ),
        ]

        report = self.scanner.scan_modules(modules, pid=3003, process_name="CompromisedGame.exe", game_dir=self.game_dir)
        self.assertTrue(report.has_critical_threat)
        self.assertEqual(report.threat_level, ThreatSeverity.CRITICAL.value)
        self.assertEqual(len(report.suspicious_modules), 2)

        # Check recommendations
        rec_text = " ".join(report.recommendations)
        self.assertIn("IMMEDIATE ACTION REQUIRED", rec_text)
        self.assertIn("quarantine", rec_text.lower())
        self.assertIn("firewall", rec_text.lower())

    def test_scan_with_dict_modules(self):
        # Tests that dictionary representations of modules can also be passed directly
        dict_modules = [
            {"name": "Game.exe", "path": str(self.game_dir / "Game.exe")},
            {
                "name": "minhook.dll",
                "path": r"C:\Windows\Temp\minhook.dll",
                "signature_status": "NotSigned",
                "hook_indicators": ["minhook detour"],
            },
        ]

        report = self.scanner.scan_modules(dict_modules, pid=4004, process_name="DictTest.exe")
        self.assertEqual(report.modules_scanned, 2)
        self.assertTrue(report.has_critical_threat)
        self.assertEqual(len(report.suspicious_modules), 1)

    def test_scan_process_with_mocked_modules(self):
        # Test scan_process by mocking get_loaded_modules
        mock_mods = [
            ModuleInfo(name="Game.exe", path=str(self.game_dir / "Game.exe")),
            ModuleInfo(name="ntdll.dll", path=r"C:\Windows\System32\ntdll.dll"),
        ]

        with patch.object(self.scanner, "get_loaded_modules", return_value=mock_mods):
            report = self.scanner.scan_process(pid=9999, game_dir=self.game_dir)
            self.assertEqual(report.pid, 9999)
            self.assertEqual(report.modules_scanned, 2)
            self.assertTrue(report.is_safe)

    def test_find_game_processes_mock(self):
        mock_proc_1 = MagicMock()
        mock_proc_1.info = {"pid": 111, "name": "SniperElite.exe", "exe": r"D:\Games\SniperElite.exe"}
        mock_proc_2 = MagicMock()
        mock_proc_2.info = {"pid": 222, "name": "explorer.exe", "exe": r"C:\Windows\explorer.exe"}

        with patch("gamecleaner.analyzer.memory_scanner.psutil.process_iter", return_value=[mock_proc_1, mock_proc_2]):
            matches = self.scanner.find_game_processes("sniper")
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0]["pid"], 111)


if __name__ == "__main__":
    unittest.main()
