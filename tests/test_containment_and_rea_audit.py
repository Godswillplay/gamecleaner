"""
Unit tests for Containment, Isolation, and Reverse Engineering audit fixes.
Verifies FirewallManager, SandboxGenerator, ShellIntegration, AsarUnpacker, and InterfaceExtractor.
"""
import os
from pathlib import Path
import shutil
import struct
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from gamecleaner.containment.firewall import FirewallManager
from gamecleaner.containment.sandbox import SandboxGenerator
from gamecleaner.containment.shell_integration import ShellIntegrationManager
from gamecleaner.rea.asar_unpacker import AsarUnpacker
from gamecleaner.rea.disassembler import BinaryDisassembler
from gamecleaner.rea.interface_extractor import InterfaceExtractor
from gamecleaner.rea.setup_manager import REASetupManager


class TestContainmentAndREAAudit(unittest.TestCase):

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="gc_audit_")).resolve()

    def tearDown(self):
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_firewall_fix_and_run_script_generation(self):
        """Verifies Fix_Firewall_And_Run.bat is generated and contains required logic."""
        fm = FirewallManager(self.test_dir)
        dummy_exe = self.test_dir / "game.exe"
        dummy_exe.write_text("dummy")

        block_ps1, unblock_ps1 = fm.generate_scripts()
        fix_bat = self.test_dir / "Fix_Firewall_And_Run.bat"

        self.assertTrue(block_ps1.exists())
        self.assertTrue(unblock_ps1.exists())
        self.assertTrue(fix_bat.exists())

        # Verify scripts have -NoPause param and guarded pause
        block_content = block_ps1.read_text(encoding="utf-8")
        self.assertIn("[switch]$NoPause", block_content)
        self.assertIn("[Console]::IsInputRedirected", block_content)

        unblock_content = unblock_ps1.read_text(encoding="utf-8")
        self.assertIn("[switch]$NoPause", unblock_content)
        self.assertIn("[Console]::IsInputRedirected", unblock_content)

        # Verify Fix_Firewall_And_Run.bat content
        fix_content = fix_bat.read_text(encoding="utf-8")
        self.assertIn("Start-Process cmd", fix_content)
        self.assertIn("Verb RunAs", fix_content)
        self.assertIn("Remove-NetFirewallRule", fix_content)
        self.assertIn("block_game_network.ps1", fix_content)
        self.assertIn("-NoPause", fix_content)
        self.assertIn("bin\\x64", fix_content)
        self.assertIn("cd /d", fix_content)

    def test_sandbox_generator_aliases_and_subdirectories(self):
        """Verifies SandboxGenerator has is_supported, generate_batch_runner, and subdirectory support."""
        sg = SandboxGenerator(self.test_dir)
        self.assertIsInstance(sg.is_supported, bool)

        bat_path = sg.generate_batch_runner()
        self.assertTrue(bat_path.exists())
        self.assertEqual(bat_path.name, "Launch_Game_Isolated.bat")

        bat_content = bat_path.read_text(encoding="utf-8")
        self.assertIn("bin\\x64", bat_content)
        self.assertIn("Binaries\\Win64", bat_content)
        self.assertIn("cd /d", bat_content)
        self.assertIn("start \"\"", bat_content)

    @patch("winreg.CreateKey")
    @patch("winreg.SetValueEx")
    def test_shell_integration_spaces_resilience(self, mock_set_val, mock_create_key):
        """Verifies context menu commands use cmd.exe /c for resilient path quoting."""
        mgr = ShellIntegrationManager()
        mgr.home_dir = self.test_dir / "home with spaces"
        mgr.home_dir.mkdir(parents=True)
        mgr.bat_path = mgr.home_dir / "clean_game_context.bat"
        mgr.archive_bat_path = mgr.home_dir / "unpack_clean_context.bat"

        mock_create_key.return_value.__enter__.return_value = MagicMock()
        ok, msg = mgr.install()
        self.assertTrue(ok)

        # Check recorded SetValueEx calls
        command_calls = [call for call in mock_set_val.call_args_list if "cmd.exe" in str(call)]
        self.assertGreater(len(command_calls), 0)

        # Verify batch files were created
        self.assertTrue(mgr.bat_path.exists())
        self.assertTrue(mgr.archive_bat_path.exists())

    def test_asar_unpacker_aligned_offset_and_traversal(self):
        """Verifies AsarUnpacker correctly calculates 4-byte aligned payload offset and blocks traversal."""
        unpacker = AsarUnpacker()
        asar_path = self.test_dir / "app.asar"
        out_dir = self.test_dir / "extracted"

        import json
        header = {
            "files": {
                "hello.txt": {"size": 11, "offset": "0"},
                "../evil.exe": {"size": 4, "offset": "11"},
            }
        }
        json_bytes = json.dumps(header).encode("utf-8")
        json_len = len(json_bytes)
        padding = (4 - (json_len % 4)) % 4
        inner_size = json_len + 4
        header_pickle_size = 8 + json_len + padding

        payload = b"HELLO WORLD" + b"EVIL"
        asar_data = struct.pack("<IIII", 4, header_pickle_size, inner_size, json_len) + json_bytes + (b"\x00" * padding) + payload
        asar_path.write_bytes(asar_data)

        self.assertTrue(unpacker.is_asar(asar_path))
        extracted = unpacker.unpack(asar_path, out_dir)

        # hello.txt should be extracted cleanly
        hello_file = out_dir / "hello.txt"
        self.assertTrue(hello_file.exists())
        self.assertEqual(hello_file.read_bytes(), b"HELLO WORLD")

        # evil.exe path traversal MUST be blocked
        evil_file = self.test_dir / "evil.exe"
        self.assertFalse(evil_file.exists())

    def test_interface_extractor_utf16_support(self):
        """Verifies InterfaceExtractor extracts both ASCII and UTF-16LE Steam interface strings."""
        extractor = InterfaceExtractor()
        fake_bin = self.test_dir / "game_wide.exe"

        ascii_part = b"SteamClient020\x00SteamUser021\x00"
        wide_part = "SteamFriends017\x00SteamHTTP012\x00".encode("utf-16le")

        fake_bin.write_bytes(b"MZ" + b"\x00" * 100 + ascii_part + b"\x00" * 50 + wide_part)

        interfaces = extractor.extract_from_binary(fake_bin)
        self.assertIn("SteamClient020", interfaces)
        self.assertIn("SteamUser021", interfaces)
        self.assertIn("SteamFriends017", interfaces)
        self.assertIn("SteamHTTP012", interfaces)

    def test_disassembler_zero_entrypoint(self):
        """Verifies disassembler returns None when AddressOfEntryPoint is 0."""
        disasm = BinaryDisassembler()
        fake_bin = self.test_dir / "no_ep.dll"
        # Write minimal dummy file
        fake_bin.write_bytes(b"MZ" + b"\x00" * 500)

        # Should handle cleanly without exception
        res = disasm.disassemble_entry_point(fake_bin)
        self.assertIsNone(res)

    def test_setup_manager_check(self):
        """Verifies REASetupManager executes environment audit without errors."""
        mgr = REASetupManager()
        status = mgr.check_environment()
        self.assertIsInstance(status.java_installed, bool)
        self.assertIsInstance(status.node_installed, bool)
        self.assertIsInstance(status.npm_installed, bool)
        self.assertIsInstance(status.rea_installed, bool)
        self.assertIsInstance(status.ghidra_installed, bool)


if __name__ == "__main__":
    unittest.main()
