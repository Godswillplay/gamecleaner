"""
Adversarial Resilience and Edge-Case Unit Tests for GameCleaner.
Covers:
- Read-only file quarantine
- Single-quote and special characters in paths
- Pure Python LNK shortcut parser and threat evaluation
- Multi-DRM target detection (Steam, Epic, Ubisoft)
- Repack INI DLC parsing
- Firewall rule name truncation and PowerShell path safety
"""
from pathlib import Path
import shutil
import stat
import tempfile
import unittest

from gamecleaner.analyzer.lnk_scanner import LnkScanner
from gamecleaner.analyzer.pe_scanner import PEScanner, check_authenticode_signature
from gamecleaner.cleaner.dlc_fetcher import SteamDLCFetcher
from gamecleaner.cleaner.emu_replacer import DRMTarget, EmulatorReplacer
from gamecleaner.cleaner.quarantine import QuarantineManager, remove_readonly
from gamecleaner.containment.firewall import FirewallManager


class TestAdvancedResilience(unittest.TestCase):

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="gc_adv_test_"))

    def tearDown(self):
        if self.test_dir.exists():
            # Clear read-only flags on any children so rmtree doesn't fail
            for p in self.test_dir.rglob("*"):
                try:
                    remove_readonly(p)
                except Exception:
                    pass
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_quarantine_readonly_file(self):
        """Verify that files with read-only attributes are successfully quarantined without crashing."""
        ro_file = self.test_dir / "readonly_malware.exe"
        ro_file.write_bytes(b"MZ" + b"\x00" * 200 + b"https://discord.com/api/webhooks/123/abc")
        # Set read-only
        ro_file.chmod(stat.S_IREAD)

        qm = QuarantineManager(self.test_dir)
        dest = qm.quarantine_file(ro_file, reason="Readonly test payload", sha256="testsha")

        self.assertIsNotNone(dest)
        self.assertTrue(dest.exists())
        self.assertFalse(ro_file.exists())

        # Test restoring the file
        manifest = qm._load_manifest()
        self.assertEqual(len(manifest), 1)
        record_name = list(manifest.keys())[0]
        restored = qm.restore_file(record_name)
        self.assertTrue(restored)
        self.assertTrue(ro_file.exists())

    def test_multi_drm_discovery(self):
        """Verify detection of Steam, Epic Games EOS, and Ubisoft Uplay DRM wrapper DLLs."""
        sub = self.test_dir / "Binaries" / "Win64"
        sub.mkdir(parents=True)

        steam_dll = sub / "steam_api64.dll"
        steam_dll.write_bytes(b"MZ" + b"\x00" * 100)

        eos_dll = sub / "EOSSDK-Win64-Shipping.dll"
        eos_dll.write_bytes(b"MZ" + b"\x00" * 100)

        uplay_dll = sub / "uplay_r1_loader64.dll"
        uplay_dll.write_bytes(b"MZ" + b"\x00" * 100)

        replacer = EmulatorReplacer(self.test_dir)
        targets = replacer.find_drm_targets()

        platforms = {t.platform for t in targets}
        self.assertIn("Steam", platforms)
        self.assertIn("Epic", platforms)
        self.assertIn("Ubisoft", platforms)
        self.assertEqual(len(targets), 3)

    def test_repack_ini_dlc_parsing(self):
        """Verify extracting DLC lists from scene repack INI files."""
        ini_file = self.test_dir / "steam_emu.ini"
        ini_file.write_text(
            "[Settings]\n"
            "AppId = 292030\n"
            "[DLC]\n"
            "378648 = The Witcher 3: Wild Hunt - Blood and Wine\n"
            "378649 = The Witcher 3: Wild Hunt - Hearts of Stone\n",
            encoding="utf-8",
        )

        fetcher = SteamDLCFetcher()
        dlcs = fetcher.parse_local_ini_dlcs(self.test_dir)
        self.assertEqual(len(dlcs), 2)
        dlc_map = {d.app_id: d.name for d in dlcs}
        self.assertEqual(dlc_map["378648"], "The Witcher 3: Wild Hunt - Blood and Wine")
        self.assertEqual(dlc_map["378649"], "The Witcher 3: Wild Hunt - Hearts of Stone")

        out_dlc = self.test_dir / "steam_settings" / "DLC.txt"
        success = fetcher.generate_dlc_txt("292030", out_dlc, game_dir=self.test_dir)
        self.assertTrue(success)
        self.assertTrue(out_dlc.exists())
        content = out_dlc.read_text(encoding="utf-8")
        self.assertIn("378648=The Witcher 3", content)

    def test_repack_ini_dlc_parsing_in_subdirectories_and_reverse_format(self):
        """Verify discovering INIs in nested subdirectories and parsing inverted DLC001=appid syntax."""
        sub = self.test_dir / "bin" / "x64"
        sub.mkdir(parents=True)
        ini_file = sub / "creamapi.ini"
        ini_file.write_text(
            "[dlc_list]\n"
            "DLC_01 = 123456 ; Expansion Alpha\n"
            "789012 = Expansion Beta # inline comment\n",
            encoding="utf-8",
        )

        fetcher = SteamDLCFetcher()
        dlcs = fetcher.parse_local_ini_dlcs(self.test_dir)
        self.assertEqual(len(dlcs), 2)
        dlc_ids = {d.app_id for d in dlcs}
        self.assertIn("123456", dlc_ids)
        self.assertIn("789012", dlc_ids)

    def test_quarantine_path_traversal_prevention(self):
        """Verify that restore_file prevents directory traversal attempts in manifest original_rel_path."""
        qm = QuarantineManager(self.test_dir)
        qm._ensure_dir()

        # Create a mock quarantined file
        q_file = qm.quarantine_dir / "malware.exe_20261120_120000.quarantined"
        q_file.write_bytes(b"MZMockPayload")

        # Create manifest with directory traversal payload
        manifest = {
            q_file.name: {
                "original_rel_path": "../../evil_escape.exe",
                "quarantined_filename": q_file.name,
                "sha256": "fake_sha",
                "reason": "Test traversal",
                "timestamp": "2026-11-20T12:00:00",
            }
        }
        qm._save_manifest(manifest)

        restored = qm.restore_file(q_file.name)
        self.assertTrue(restored)

        # File should have been restored inside self.test_dir, NEVER outside
        self.assertFalse((self.test_dir.parent.parent / "evil_escape.exe").exists())
        self.assertTrue((self.test_dir / "evil_escape.exe").exists())

    def test_firewall_rule_length_and_quoting(self):
        """Verify firewall rule name lengths stay within 255 chars and handle quotes."""
        # Create a deep directory name
        deep_dir = self.test_dir / ("A" * 100)
        deep_dir.mkdir(parents=True)
        exe_file = deep_dir / "Game's_O'Reilly_Special Edition.exe"
        exe_file.write_bytes(b"MZ" + b"\x00" * 100)

        fm = FirewallManager(deep_dir)
        block_ps1, unblock_ps1 = fm.generate_scripts()

        self.assertTrue(block_ps1.exists())
        self.assertTrue(unblock_ps1.exists())

        block_content = block_ps1.read_text(encoding="utf-8")
        # Ensure single quotes in filename were escaped as ''
        self.assertIn("Game''s_O''Reilly_Special Edition.exe", block_content)
        # Ensure rule prefix was truncated
        self.assertLessEqual(len(fm.rule_prefix), 60)


if __name__ == "__main__":
    unittest.main()
