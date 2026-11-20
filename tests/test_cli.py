"""
Comprehensive test suite for GameCleaner CLI subcommands and command dispatch.
"""
import argparse
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import zipfile

from gamecleaner import cli


class TestGameCleanerCLI(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.work_dir = Path(self.temp_dir.name).resolve()

        # Create mock game folder
        self.game_dir = self.work_dir / "TestGame"
        self.game_dir.mkdir(parents=True, exist_ok=True)
        (self.game_dir / "game.exe").write_bytes(b"MZ" + b"\x00" * 512)
        (self.game_dir / "steam_api64.dll").write_bytes(b"MZ" + b"\x00" * 512)
        (self.game_dir / "steam_appid.txt").write_text("480", encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_handle_scan(self):
        args = argparse.Namespace(path=str(self.game_dir))
        # Should execute scan without throwing any exceptions
        cli.handle_scan(args)

    def test_handle_scan_nonexistent_path(self):
        args = argparse.Namespace(path=str(self.work_dir / "NonExistentFolder"))
        with self.assertRaises(SystemExit) as cm:
            cli.handle_scan(args)
        self.assertEqual(cm.exception.code, 1)

    def test_handle_clean_all_directory(self):
        args = argparse.Namespace(
            path=str(self.game_dir),
            output=None,
            no_quarantine=False,
            no_replace_emu=False,
            no_migrate_saves=False,
            no_firewall=False,
            no_sandbox=False,
        )
        cli.handle_clean_all(args)
        # Verify reports and containment scripts were created
        self.assertTrue((self.game_dir / "gamecleaner_report.json").exists())
        self.assertTrue((self.game_dir / "gamecleaner_report.md").exists())
        self.assertTrue((self.game_dir / "block_game_network.ps1").exists())
        self.assertTrue((self.game_dir / "Fix_Firewall_And_Run.bat").exists())
        self.assertTrue(any(self.game_dir.glob("Sandbox_*.wsb")))

    def test_handle_clean_all_archive(self):
        # Create a zip archive
        zip_path = self.work_dir / "packaged_game.zip"
        dest_dir = self.work_dir / "ExtractedGame"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("launcher.exe", b"MZ" + b"\x00" * 512)
            zf.writestr("steam_api.dll", b"MZ" + b"\x00" * 512)
            zf.writestr("steam_appid.txt", "1091500")

        args = argparse.Namespace(
            path=str(zip_path),
            output=str(dest_dir),
            no_quarantine=False,
            no_replace_emu=False,
            no_migrate_saves=False,
            no_firewall=False,
            no_sandbox=False,
        )
        cli.handle_clean_all(args)
        self.assertTrue(dest_dir.exists())
        self.assertTrue((dest_dir / "launcher.exe").exists())
        self.assertTrue((dest_dir / "Fix_Firewall_And_Run.bat").exists())

    def test_handle_unpack(self):
        zip_path = self.work_dir / "setup_test.zip"
        out_dir = self.work_dir / "UnpackedGame"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("game.exe", b"MZ" + b"\x00" * 256)

        args = argparse.Namespace(
            installer=str(zip_path),
            output=str(out_dir),
            no_clean=False,
        )
        cli.handle_unpack(args)
        self.assertTrue(out_dir.exists())
        self.assertTrue((out_dir / "game.exe").exists())

    def test_handle_migrate_saves(self):
        (self.game_dir / "steam_emu.ini").write_text("[Settings]\nAppId=480\nUserName=TestUser\n")
        args = argparse.Namespace(
            path=str(self.game_dir),
            app_id=None,
        )
        cli.handle_migrate_saves(args)
        # Verify Goldberg identity configuration files
        settings_dir = self.game_dir / "steam_settings"
        self.assertTrue(settings_dir.exists())
        self.assertTrue((settings_dir / "account_name.txt").exists())

    def test_handle_firewall(self):
        args = argparse.Namespace(
            path=str(self.game_dir),
            elevate=False,
        )
        cli.handle_firewall(args)
        self.assertTrue((self.game_dir / "block_game_network.ps1").exists())
        self.assertTrue((self.game_dir / "unblock_game_network.ps1").exists())
        self.assertTrue((self.game_dir / "Fix_Firewall_And_Run.bat").exists())

    def test_handle_sandbox(self):
        args = argparse.Namespace(
            path=str(self.game_dir),
            read_write=False,
        )
        # Must execute without AttributeError on generate_batch_runner or is_supported
        cli.handle_sandbox(args)
        wsb_files = list(self.game_dir.glob("Sandbox_*.wsb"))
        self.assertEqual(len(wsb_files), 1)
        self.assertTrue((self.game_dir / "Launch_Game_Isolated.bat").exists())

    def test_handle_replace_emu(self):
        args = argparse.Namespace(
            path=str(self.game_dir),
            custom_dll=None,
        )
        cli.handle_replace_emu(args)
        # steam_api64.dll should be replaced with clean Goldberg emulator
        clean_size = (self.game_dir / "steam_api64.dll").stat().st_size
        self.assertGreater(clean_size, 100000)

    def test_handle_inspect(self):
        exe_path = self.game_dir / "game.exe"
        args = argparse.Namespace(binary_path=str(exe_path))
        cli.handle_inspect(args)
        # Should generate REA evidence file
        evidence_file = Path.cwd() / f"REA_EVIDENCE_{exe_path.name}.md"
        if evidence_file.exists():
            evidence_file.unlink()  # Clean up

    @patch("gamecleaner.containment.ShellIntegrationManager.install")
    @patch("gamecleaner.containment.ShellIntegrationManager.uninstall")
    def test_handle_setup(self, mock_uninstall, mock_install):
        mock_install.return_value = (True, "Installed")
        mock_uninstall.return_value = (True, "Uninstalled")

        args = argparse.Namespace(
            all=False,
            check=True,
            ghidra=False,
            context_menu=True,
            remove_context_menu=False,
            unpacker=False,
        )
        cli.handle_setup(args)
        mock_install.assert_called_once()

    def test_main_dispatch_commands(self):
        # Test help/no args exits with code 0
        with patch.object(sys, "argv", ["gamecleaner"]):
            with self.assertRaises(SystemExit) as cm:
                cli.main()
            self.assertEqual(cm.exception.code, 0)

        # Test scan command parsing
        with patch.object(sys, "argv", ["gamecleaner", "scan", str(self.game_dir)]):
            with patch("gamecleaner.cli.handle_scan") as mock_scan:
                cli.main()
                mock_scan.assert_called_once()

        # Test firewall command parsing
        with patch.object(sys, "argv", ["gamecleaner", "firewall", str(self.game_dir), "--elevate"]):
            with patch("gamecleaner.cli.handle_firewall") as mock_fw:
                cli.main()
                mock_fw.assert_called_once()
                self.assertTrue(mock_fw.call_args[0][0].elevate)

        # Test sandbox command parsing
        with patch.object(sys, "argv", ["gamecleaner", "sandbox", str(self.game_dir), "--read-write"]):
            with patch("gamecleaner.cli.handle_sandbox") as mock_sb:
                cli.main()
                mock_sb.assert_called_once()
                self.assertTrue(mock_sb.call_args[0][0].read_write)


if __name__ == "__main__":
    unittest.main()
