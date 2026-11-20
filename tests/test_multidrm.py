"""
Unit tests for Unified Multi-DRM Orchestrator (Steam, Epic EOS, Ubisoft, GOG).
"""
import json
import os
from pathlib import Path
import tempfile
import unittest

from gamecleaner.cleaner.multidrm import (
    DRMLayer,
    DRMPlatform,
    MultiDRMOrchestrator,
    MultiDRMReport,
)


class TestMultiDRMOrchestrator(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.game_dir = Path(self.temp_dir.name).resolve()
        self.orchestrator = MultiDRMOrchestrator(self.game_dir)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_mock_pe(self, path: Path, arch: str = "x64", extra_bytes: bytes = b"") -> None:
        """Helper to create a minimal mock PE binary with valid machine header."""
        path.parent.mkdir(parents=True, exist_ok=True)
        data = bytearray(b"MZ" + b"\x00" * 58)
        data.extend((0x80).to_bytes(4, "little"))
        data.extend(b"\x00" * (0x80 - len(data)))
        data.extend(b"PE\x00\x00")
        machine = 0x8664 if arch == "x64" else 0x014C
        data.extend(machine.to_bytes(2, "little"))
        data.extend(b"\x00" * 20)
        data.extend(extra_bytes)
        path.write_bytes(bytes(data))

    def test_triage_empty_or_clean_folder(self):
        report = self.orchestrator.triage()
        self.assertEqual(len(report.layers_found), 0)
        self.assertFalse(report.is_hybrid)
        self.assertIn("No known commercial DRM", report.summary)

    def test_triage_single_steam_drm(self):
        steam_dll = self.game_dir / "steam_api64.dll"
        self._create_mock_pe(steam_dll, "x64", b"Valve Corporation Steamworks")
        (self.game_dir / "steam_appid.txt").write_text("1091500", encoding="utf-8")

        report = self.orchestrator.triage()
        self.assertEqual(len(report.layers_found), 1)
        self.assertFalse(report.is_hybrid)

        layer = report.layers_found[0]
        self.assertEqual(layer.platform, DRMPlatform.STEAM)
        self.assertEqual(layer.metadata.get("app_id"), "1091500")
        self.assertIn("Single DRM layer detected", report.summary)

    def test_triage_single_eos_drm(self):
        eos_dll = self.game_dir / "EOSSDK-Win64-Shipping.dll"
        self._create_mock_pe(eos_dll, "x64", b"EOS_Initialize EOS_Platform_Create")
        (self.game_dir / "epic_emu.ini").write_text("[Epic]\nAppName=AlanWake2\n", encoding="utf-8")

        report = self.orchestrator.triage()
        self.assertEqual(len(report.layers_found), 1)
        self.assertFalse(report.is_hybrid)

        layer = report.layers_found[0]
        self.assertEqual(layer.platform, DRMPlatform.EPIC)
        self.assertEqual(layer.metadata.get("AppName"), "AlanWake2")

    def test_triage_single_ubisoft_drm(self):
        uplay_dll = self.game_dir / "uplay_r1_loader64.dll"
        self._create_mock_pe(uplay_dll, "x64", b"Ubisoft Uplay")

        report = self.orchestrator.triage()
        self.assertEqual(len(report.layers_found), 1)
        self.assertFalse(report.is_hybrid)

        layer = report.layers_found[0]
        self.assertEqual(layer.platform, DRMPlatform.UBISOFT)

    def test_triage_single_gog_drm_free(self):
        gog_info = self.game_dir / "goggame-1420790433.info"
        info_data = {
            "gameId": "1420790433",
            "name": "The Witcher 3: Wild Hunt",
            "dlcs": ["Hearts of Stone", "Blood and Wine"],
        }
        gog_info.write_text(json.dumps(info_data), encoding="utf-8")

        galaxy_dll = self.game_dir / "Galaxy64.dll"
        self._create_mock_pe(galaxy_dll, "x64", b"GOG Galaxy SDK")

        report = self.orchestrator.triage()
        self.assertEqual(len(report.layers_found), 1)
        self.assertFalse(report.is_hybrid)

        layer = report.layers_found[0]
        self.assertEqual(layer.platform, DRMPlatform.GOG)
        self.assertEqual(layer.metadata.get("game_id"), "1420790433")
        self.assertEqual(layer.metadata.get("name"), "The Witcher 3: Wild Hunt")
        self.assertEqual(len(layer.metadata.get("dlcs", [])), 2)

    def test_triage_hybrid_steam_and_eos(self):
        """Games like Borderlands 3 and Death Stranding contain both Steamworks and EOS SDK."""
        steam_dll = self.game_dir / "steam_api64.dll"
        self._create_mock_pe(steam_dll, "x64", b"Valve Steamworks")
        (self.game_dir / "steam_appid.txt").write_text("397540", encoding="utf-8")

        eos_dll = self.game_dir / "EOSSDK-Win64-Shipping.dll"
        self._create_mock_pe(eos_dll, "x64", b"EOS_Initialize Nemirtingas")
        (self.game_dir / "epic_emu.ini").write_text("[Epic]\nAppName=Borderlands3\n", encoding="utf-8")

        report = self.orchestrator.triage()
        self.assertEqual(len(report.layers_found), 2)
        self.assertTrue(report.is_hybrid)

        platforms = {l.platform for l in report.layers_found}
        self.assertIn(DRMPlatform.STEAM, platforms)
        self.assertIn(DRMPlatform.EPIC, platforms)
        self.assertIn("Hybrid Multi-DRM Architecture Detected", report.summary)

    def test_sanitize_hybrid_steam_and_eos(self):
        """Sanitizes both Steam and EOS layers simultaneously with clean configs and emulators."""
        # Setup Steam
        steam_dll = self.game_dir / "steam_api64.dll"
        self._create_mock_pe(steam_dll, "x64", b"Untrusted scene steam crack")
        (self.game_dir / "steam_appid.txt").write_text("397540", encoding="utf-8")

        # Setup EOS
        eos_dll = self.game_dir / "EOSSDK-Win64-Shipping.dll"
        self._create_mock_pe(eos_dll, "x64", b"Untrusted scene eos crack")
        (self.game_dir / "epic_emu.ini").write_text(
            "[Epic]\nAppName=Borderlands3\nCatalogItemId=item123\nAccountId=acc456\n",
            encoding="utf-8",
        )

        # Mock clean EOS emulator
        clean_eos = self.game_dir / "clean_eos_stub.dll"
        clean_eos.write_bytes(b"MZ" + b"\x00" * 1500 + b"Clean EOS Stub")

        report = self.orchestrator.sanitize(
            replace_steam=True,
            replace_eos=True,
            custom_clean_eos_dll=clean_eos,
        )

        self.assertTrue(report.is_hybrid)
        self.assertIn("steam_api64.dll", report.replaced_files)
        self.assertIn("EOSSDK-Win64-Shipping.dll", report.replaced_files)

        # Verify Steam config generated
        self.assertTrue((self.game_dir / "steam_settings" / "steam_appid.txt").exists())

        # Verify Epic config preserved and generated
        epic_cfg = self.game_dir / "epic_emu.ini"
        self.assertTrue(epic_cfg.exists())
        epic_content = epic_cfg.read_text(encoding="utf-8")
        self.assertIn("AppName = Borderlands3", epic_content)
        self.assertIn("CatalogItemId = item123", epic_content)
        self.assertIn("AccountId = acc456", epic_content)

    def test_rollback_all_multidrm(self):
        steam_dll = self.game_dir / "steam_api64.dll"
        orig_steam_bytes = b"MZ" + b"\x00" * 100 + b"OriginalSteamCrack"
        steam_dll.write_bytes(orig_steam_bytes)
        (self.game_dir / "steam_appid.txt").write_text("480", encoding="utf-8")

        eos_dll = self.game_dir / "EOSSDK-Win64-Shipping.dll"
        orig_eos_bytes = b"MZ" + b"\x00" * 100 + b"OriginalEOSCrack"
        eos_dll.write_bytes(orig_eos_bytes)

        clean_eos = self.game_dir / "clean_eos.dll"
        clean_eos.write_bytes(b"MZ" + b"\x00" * 1000 + b"CleanEOS")

        self.orchestrator.sanitize(
            replace_steam=True,
            replace_eos=True,
            custom_clean_eos_dll=clean_eos,
        )

        # Verify backups were taken
        rollback_res = self.orchestrator.rollback_all()
        self.assertIn("steam_ubisoft_rollbacks", rollback_res)
        self.assertIn("eos_rollbacks", rollback_res)

        # Verify original files restored
        self.assertEqual(steam_dll.read_bytes(), orig_steam_bytes)
        self.assertEqual(eos_dll.read_bytes(), orig_eos_bytes)


if __name__ == "__main__":
    unittest.main()
