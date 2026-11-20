"""
Unit tests for CLI commands, SandboxGenerator fixes, and Rollback/Quarantine CLI workflows.
"""
import io
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from gamecleaner.cleaner import EmulatorReplacer, QuarantineManager
from gamecleaner.containment import SandboxGenerator, is_sandbox_supported
from gamecleaner.cli import main, handle_sandbox, handle_quarantine, handle_rollback, handle_status, handle_scan


class TestCliAndSandboxAudit(unittest.TestCase):

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="gc_audit_test_")).resolve()

    def tearDown(self):
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_sandbox_generator_attributes_and_runner(self):
        """Verify SandboxGenerator has is_supported and generate_batch_runner without AttributeError."""
        sg = SandboxGenerator(self.test_dir)
        self.assertIsInstance(sg.is_supported, bool)
        self.assertEqual(sg.is_supported, is_sandbox_supported())

        # Test batch runner creation
        bat = sg.generate_batch_runner()
        self.assertTrue(bat.exists())
        self.assertEqual(bat.name, "Launch_Game_Isolated.bat")

        # Test WSB XML escaping
        special_dir = self.test_dir / "Game & Co 'Special'"
        special_dir.mkdir(parents=True, exist_ok=True)
        sg_special = SandboxGenerator(special_dir)
        wsb = sg_special.generate_wsb()
        self.assertTrue(wsb.exists())
        content = wsb.read_text(encoding="utf-8")
        self.assertIn("&amp;", content)

    def test_cli_sandbox_command_execution(self):
        """Verify handle_sandbox runs without raising AttributeError."""
        class Args:
            path = str(self.test_dir)
            read_write = False

        handle_sandbox(Args())
        self.assertTrue((self.test_dir / f"Sandbox_{SandboxGenerator(self.test_dir).game_name}.wsb").exists())
        self.assertTrue((self.test_dir / "Launch_Game_Isolated.bat").exists())

    def test_cli_quarantine_commands(self):
        """Test CLI quarantine list, add, and restore workflows."""
        qm = QuarantineManager(self.test_dir)
        test_file = self.test_dir / "bad_dropper.exe"
        test_file.write_text("evil payload")

        class AddArgs:
            path = str(self.test_dir)
            add = str(test_file)
            reason = "Test Trojan"
            restore = None
            restore_all = False

        handle_quarantine(AddArgs())
        self.assertFalse(test_file.exists())
        quarantined = qm.list_quarantined()
        self.assertEqual(len(quarantined), 1)

        # Test list
        class ListArgs:
            path = str(self.test_dir)
            add = None
            restore = None
            restore_all = False
            list = True

        handle_quarantine(ListArgs())

        # Test restore
        class RestoreArgs:
            path = str(self.test_dir)
            add = None
            restore = quarantined[0].quarantined_filename
            restore_all = False

        handle_quarantine(RestoreArgs())
        self.assertTrue(test_file.exists())
        self.assertEqual(len(qm.list_quarantined()), 0)

    def test_cli_rollback_commands(self):
        """Test EmulatorReplacer list_backups, rollback_all, and CLI rollback command."""
        er = EmulatorReplacer(self.test_dir)
        dummy_dll = self.test_dir / "steam_api64.dll"
        dummy_dll.write_bytes(b"MZOriginalDllContent")

        from gamecleaner.cleaner.emu_replacer import DRMTarget
        target = DRMTarget(
            dll_name="steam_api64.dll",
            architecture="x64",
            full_path=dummy_dll,
            relative_path="steam_api64.dll",
            has_appid_file=False,
            platform="Steam",
        )
        backup_path = er.backup_dll(target)
        self.assertTrue(backup_path.exists())

        backups = er.list_backups()
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0]["backup_file"], backup_path.name)

        # Overwrite original DLL
        dummy_dll.write_bytes(b"MZReplacedEmulatorContent")

        # Rollback via CLI
        class RollbackArgs:
            path = str(self.test_dir)
            backup = backup_path.name
            all = False
            list = False

        handle_rollback(RollbackArgs())
        self.assertEqual(dummy_dll.read_bytes(), b"MZOriginalDllContent")

    def test_cli_status_command(self):
        """Test status command executes without error on empty or populated game directory."""
        class StatusArgs:
            path = str(self.test_dir)

        handle_status(StatusArgs())

    def test_cli_scan_single_file(self):
        """Verify scanning a single binary directly does not raise NotADirectoryError."""
        fake_binary = self.test_dir / "game.exe"
        fake_binary.write_bytes(b"MZ" + b"\x00" * 1024)

        class ScanArgs:
            path = str(fake_binary)

        handle_scan(ScanArgs())


if __name__ == "__main__":
    unittest.main()
