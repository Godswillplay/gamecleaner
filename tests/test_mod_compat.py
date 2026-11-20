"""
Unit tests for Mod Compatibility & Framework Auditor.
Tests detection, validation of genuine mod frameworks (ReShade, Special K, Script Extenders,
BepInEx, ASI Loaders), proxy chain auditing, and malware impersonation detection.
"""
import json
import os
from pathlib import Path
import tempfile
import unittest

from gamecleaner.analyzer.mod_compat import (
    ModAuditReport,
    ModChainLink,
    ModCompatibilityAuditor,
    ModConflict,
    ModDetection,
    ModFrameworkType,
)
from gamecleaner.analyzer.threat_rules import ThreatCategory, ThreatSeverity


class TestModCompatibilityAuditor(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.game_dir = Path(self.temp_dir.name).resolve()
        self.auditor = ModCompatibilityAuditor(self.game_dir)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_mock_pe(
        self,
        path: Path,
        arch: str = "x64",
        extra_bytes: bytes = b"",
        import_names: list = None,
    ) -> None:
        """Helper to create mock PE binaries with headers and optional imports."""
        path.parent.mkdir(parents=True, exist_ok=True)
        data = bytearray(b"MZ" + b"\x00" * 58)
        data.extend((0x80).to_bytes(4, "little"))
        data.extend(b"\x00" * (0x80 - len(data)))
        data.extend(b"PE\x00\x00")
        machine = 0x8664 if arch == "x64" else 0x014C
        data.extend(machine.to_bytes(2, "little"))
        data.extend(b"\x00" * 20)
        data.extend(extra_bytes)
        if import_names:
            for imp in import_names:
                data.extend(imp.encode("utf-8") + b"\x00")
        path.write_bytes(bytes(data))

    def test_empty_folder_clean_audit(self):
        report = self.auditor.audit()
        self.assertEqual(len(report.detected_mods), 0)
        self.assertEqual(len(report.conflicts), 0)
        self.assertEqual(len(report.chains), 0)
        self.assertIn("No game mod frameworks detected", report.summary)

    def test_detect_genuine_reshade(self):
        reshade_dll = self.game_dir / "dxgi.dll"
        self._create_mock_pe(reshade_dll, "x64", b"crosire ReShade effectruntime reshade.me")
        (self.game_dir / "ReShade.ini").write_text("[GENERAL]\nEffectSearchPaths=reshade-shaders\n", encoding="utf-8")
        (self.game_dir / "reshade-shaders").mkdir()

        detection = self.auditor.inspect_dll(reshade_dll)
        self.assertIsNotNone(detection)
        self.assertEqual(detection.framework, ModFrameworkType.RESHADE)
        self.assertTrue(detection.is_genuine)
        self.assertFalse(detection.is_malware_impersonation)
        self.assertGreaterEqual(detection.confidence, 0.8)
        self.assertEqual(detection.severity, ThreatSeverity.LOW)
        self.assertEqual(detection.threat_category, ThreatCategory.HACKTOOL_CRACK)

    def test_detect_genuine_special_k(self):
        sk_dll = self.game_dir / "SpecialK64.dll"
        self._create_mock_pe(sk_dll, "x64", b"Special K by Kaldaien - HDR / Frame Pacing")
        (self.game_dir / "SpecialK.ini").write_text("[SpecialK.System]\nSilent=true\n", encoding="utf-8")

        detection = self.auditor.inspect_dll(sk_dll)
        self.assertIsNotNone(detection)
        self.assertEqual(detection.framework, ModFrameworkType.SPECIAL_K)
        self.assertTrue(detection.is_genuine)
        self.assertFalse(detection.is_malware_impersonation)

    def test_detect_genuine_script_extender(self):
        # SKSE64 loader and dll
        skse_loader = self.game_dir / "skse64_loader.exe"
        self._create_mock_pe(skse_loader, "x64", b"Skyrim Script Extender 64")
        skse_dll = self.game_dir / "skse64_1_5_97.dll"
        self._create_mock_pe(skse_dll, "x64", b"skse silverlock ianpatt behippo SKSEPlugin")
        (self.game_dir / "Data" / "SKSE").mkdir(parents=True)

        report = self.auditor.audit()
        frameworks = [m.framework for m in report.detected_mods]
        self.assertIn(ModFrameworkType.SCRIPT_EXTENDER, frameworks)
        self.assertTrue(any(m.is_genuine for m in report.detected_mods))

    def test_detect_genuine_bepinex_unity(self):
        winhttp = self.game_dir / "winhttp.dll"
        self._create_mock_pe(winhttp, "x64", b"UnityDoorstop BepInEx mono-2.0")

        # doorstop_config.ini
        doorstop_cfg = self.game_dir / "doorstop_config.ini"
        doorstop_cfg.write_text("[UnityDoorstop]\nenabled=true\ntargetAssembly=BepInEx\\core\\BepInEx.Preloader.dll\n", encoding="utf-8")

        bep_core = self.game_dir / "BepInEx" / "core"
        bep_core.mkdir(parents=True)
        (bep_core / "BepInEx.Core.dll").write_bytes(b"MZ" + b"\x00" * 100)
        (bep_core / "BepInEx.Preloader.dll").write_bytes(b"MZ" + b"\x00" * 100)

        detection = self.auditor.inspect_dll(winhttp)
        self.assertIsNotNone(detection)
        self.assertEqual(detection.framework, ModFrameworkType.BEPINEX)
        self.assertTrue(detection.is_genuine)
        self.assertFalse(detection.is_malware_impersonation)

    def test_detect_genuine_asi_loader(self):
        dinput8 = self.game_dir / "dinput8.dll"
        self._create_mock_pe(dinput8, "x64", b"Ultimate ASI Loader by ThirteenAG")
        scripts_dir = self.game_dir / "scripts"
        scripts_dir.mkdir()
        (scripts_dir / "WidescreenFix.asi").write_bytes(b"MZ" + b"\x00" * 50)

        detection = self.auditor.inspect_dll(dinput8)
        self.assertIsNotNone(detection)
        self.assertEqual(detection.framework, ModFrameworkType.ASI_LOADER)
        self.assertTrue(detection.is_genuine)

    def test_audit_healthy_proxy_chain_specialk_reshade(self):
        """Special K dxgi.dll configured to chain load ReShade64.dll, and ReShade64.dll exists."""
        dxgi_dll = self.game_dir / "dxgi.dll"
        self._create_mock_pe(dxgi_dll, "x64", b"Special K by Kaldaien")

        dxgi_ini = self.game_dir / "dxgi.ini"
        dxgi_ini.write_text(
            "[Import.ReShade]\nArchitecture=x64\nRole=ThirdParty\nFilename=ReShade64.dll\n",
            encoding="utf-8",
        )

        reshade_dll = self.game_dir / "ReShade64.dll"
        self._create_mock_pe(reshade_dll, "x64", b"crosire ReShade effectruntime")

        chains = self.auditor.audit_chains()
        self.assertEqual(len(chains), 1)
        ch = chains[0]
        self.assertEqual(ch.source_dll, "dxgi.dll")
        self.assertEqual(ch.target_dll, "ReShade64.dll")
        self.assertEqual(ch.status, "HEALTHY")
        self.assertTrue(ch.is_target_present)

        conflicts = self.auditor.find_conflicts([], chains)
        self.assertEqual(len(conflicts), 0)

    def test_audit_broken_proxy_chain_target_missing(self):
        """Special K dxgi.ini points to ReShade64.dll, but ReShade64.dll is missing."""
        dxgi_ini = self.game_dir / "dxgi.ini"
        dxgi_ini.write_text(
            "[Import.ReShade]\nArchitecture=x64\nRole=ThirdParty\nFilename=ReShade64.dll\n",
            encoding="utf-8",
        )

        chains = self.auditor.audit_chains()
        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0].status, "BROKEN_TARGET_MISSING")

        conflicts = self.auditor.find_conflicts([], chains)
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0].conflict_type, "BROKEN_CHAIN")
        self.assertIn("not found on disk", conflicts[0].description)

    def test_audit_slot_contention_collision(self):
        """ReShade and Special K both in same directory claiming dxgi.dll / d3d11.dll with NO chain."""
        reshade_dll = self.game_dir / "dxgi.dll"
        self._create_mock_pe(reshade_dll, "x64", b"crosire ReShade")

        specialk_dll = self.game_dir / "d3d11.dll"
        self._create_mock_pe(specialk_dll, "x64", b"Special K by Kaldaien")

        report = self.auditor.audit()
        self.assertEqual(len(report.detected_mods), 2)
        # Should flag slot contention conflict
        self.assertTrue(any(c.conflict_type == "SLOT_CONTENTION" for c in report.conflicts))

    def test_detect_malware_masquerading_as_mod_loader(self):
        """
        Malicious trojan named dxgi.dll placed in game root with no ReShade signatures/assets,
        but containing stealth process injection APIs (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread).
        """
        malware_dll = self.game_dir / "dxgi.dll"
        self._create_mock_pe(
            malware_dll,
            "x64",
            b"CompletelyFakePayloadNoModSignatures",
            import_names=["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
        )

        # In sideload / mod inspection
        from gamecleaner.analyzer.sideload_auditor import SideloadAuditor
        sideload_auditor = SideloadAuditor(self.game_dir)
        finding = sideload_auditor.scan_file(malware_dll, [])
        self.assertIsNotNone(finding)
        self.assertFalse(finding.is_legitimate_mod)
        self.assertEqual(finding.severity, ThreatSeverity.HIGH)


if __name__ == "__main__":
    unittest.main()
