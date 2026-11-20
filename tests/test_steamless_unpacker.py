"""
Unit tests for SteamlessUnpacker defensive DRM removal module.
"""
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from gamecleaner.cleaner.steamless_unpacker import SteamlessResult, SteamlessUnpacker


class TestSteamlessUnpacker(unittest.TestCase):
    """Test suite for Steamless CLI orchestration, backup, file swap, and PE validation."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.work_dir = Path(self.temp_dir.name).resolve()
        self.tools_dir = self.work_dir / "tools" / "steamless"
        self.tools_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_availability_not_found(self):
        """When Steamless CLI is missing, is_available() should return False."""
        unpacker = SteamlessUnpacker(
            tools_dir=self.work_dir / "nonexistent_tools",
            steamless_path=None,
        )
        with patch("shutil.which", return_value=None):
            self.assertFalse(unpacker.is_available())
            self.assertIsNone(unpacker.get_steamless_path())

    def test_availability_custom_path(self):
        """Explicitly provided Steamless executable path is detected."""
        fake_cli = self.work_dir / "Steamless.CLI.exe"
        fake_cli.write_text("dummy cli", encoding="utf-8")

        unpacker = SteamlessUnpacker(steamless_path=fake_cli)
        self.assertTrue(unpacker.is_available())
        self.assertEqual(unpacker.get_steamless_path(), fake_cli.resolve())

    def test_availability_in_tools_dir(self):
        """Steamless in custom tools_dir is detected."""
        fake_cli = self.tools_dir / "Steamless.CLI.exe"
        fake_cli.write_text("dummy cli", encoding="utf-8")

        unpacker = SteamlessUnpacker(tools_dir=self.work_dir / "tools")
        self.assertTrue(unpacker.is_available())
        self.assertEqual(unpacker.get_steamless_path(), fake_cli.resolve())

    def test_availability_via_system_path(self):
        """Steamless on system PATH is detected."""
        fake_path_exe = self.work_dir / "system_path" / "Steamless.CLI.exe"
        fake_path_exe.parent.mkdir(parents=True, exist_ok=True)
        fake_path_exe.write_text("dummy cli", encoding="utf-8")

        unpacker = SteamlessUnpacker()
        with patch("shutil.which", return_value=str(fake_path_exe)):
            self.assertTrue(unpacker.is_available())
            self.assertEqual(unpacker.get_steamless_path(), fake_path_exe.resolve())

    def test_unpack_target_file_not_found(self):
        """Unpacking a non-existent binary returns an error result."""
        fake_cli = self.tools_dir / "Steamless.CLI.exe"
        fake_cli.write_text("dummy cli", encoding="utf-8")

        unpacker = SteamlessUnpacker(steamless_path=fake_cli)
        res = unpacker.unpack_binary(self.work_dir / "nonexistent.exe")
        self.assertFalse(res.success)
        self.assertIn("does not exist", res.error_message)
        self.assertIsNone(res.unpacked_path)
        self.assertIsNone(res.backup_created)

    def test_unpack_steamless_not_available(self):
        """Unpacking when Steamless CLI is not installed returns guidance error."""
        game_exe = self.work_dir / "game.exe"
        game_exe.write_bytes(b"MZ" + b"\x00" * 100)

        unpacker = SteamlessUnpacker(
            steamless_path=None,
            tools_dir=self.work_dir / "empty_tools",
        )
        with patch("shutil.which", return_value=None):
            res = unpacker.unpack_binary(game_exe)
            self.assertFalse(res.success)
            self.assertIn("Steamless.CLI.exe not found", res.error_message)

    def test_unpack_cli_execution_failure(self):
        """Handles subprocess failure gracefully."""
        fake_cli = self.tools_dir / "Steamless.CLI.exe"
        fake_cli.write_text("dummy cli", encoding="utf-8")
        game_exe = self.work_dir / "game.exe"
        game_exe.write_bytes(b"MZ" + b"\x00" * 100)

        unpacker = SteamlessUnpacker(steamless_path=fake_cli)
        with patch("subprocess.run", side_effect=OSError("CLI crash")):
            res = unpacker.unpack_binary(game_exe)
            self.assertFalse(res.success)
            self.assertIn("Failed to execute Steamless CLI", res.error_message)

    def test_unpack_no_output_file_generated(self):
        """When Steamless runs but produces no unpacked file, returns error."""
        fake_cli = self.tools_dir / "Steamless.CLI.exe"
        fake_cli.write_text("dummy cli", encoding="utf-8")
        game_exe = self.work_dir / "game.exe"
        game_exe.write_bytes(b"MZ" + b"\x00" * 100)

        unpacker = SteamlessUnpacker(steamless_path=fake_cli)
        fake_proc = MagicMock(returncode=1, stdout="No unpacker could process file", stderr="")
        with patch("subprocess.run", return_value=fake_proc):
            res = unpacker.unpack_binary(game_exe)
            self.assertFalse(res.success)
            self.assertIn("without generating an unpacked file", res.error_message)

    def test_successful_unpack_flow(self):
        """Full successful workflow: unpacks binary, backs up original, swaps binary, validates .bind removal."""
        fake_cli = self.tools_dir / "Steamless.CLI.exe"
        fake_cli.write_text("dummy cli", encoding="utf-8")

        game_exe = self.work_dir / "game.exe"
        original_bytes = b"MZ" + b"\x00" * 50 + b".bind" + b"SteamDrmPfn" + b"\x00" * 50
        game_exe.write_bytes(original_bytes)

        unpacker = SteamlessUnpacker(steamless_path=fake_cli)
        self.assertTrue(unpacker.has_bind_section(game_exe))

        # Side-effect simulating Steamless creating game.exe.unpacked.exe
        unpacked_bytes = b"MZ" + b"\x00" * 200  # Clean unpacked binary without .bind
        def fake_run(cmd, **kwargs):
            unpacked_file = game_exe.with_name("game.exe.unpacked.exe")
            unpacked_file.write_bytes(unpacked_bytes)
            return MagicMock(returncode=0, stdout="Unpacked successfully!", stderr="")

        with patch("subprocess.run", side_effect=fake_run):
            res = unpacker.unpack_binary(game_exe, backup=True)

        self.assertTrue(res.success)
        self.assertIsNone(res.error_message)
        self.assertEqual(res.original_path, str(game_exe.resolve()))
        self.assertEqual(res.unpacked_path, str(game_exe.resolve()))
        self.assertIsNotNone(res.backup_created)

        # Verify backup exists in .gamecleaner_backup/
        backup_path = Path(res.backup_created)
        self.assertTrue(backup_path.is_file())
        self.assertEqual(backup_path.read_bytes(), original_bytes)

        # Verify backup_manifest.json
        manifest_file = game_exe.parent / ".gamecleaner_backup" / "backup_manifest.json"
        self.assertTrue(manifest_file.is_file())
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        self.assertIn(backup_path.name, manifest)
        self.assertEqual(manifest[backup_path.name]["type"], "steamless_steamstub_backup")

        # Verify swapped game.exe now contains unpacked content
        self.assertEqual(game_exe.read_bytes(), unpacked_bytes)
        # Verify .bind section is gone
        self.assertFalse(unpacker.has_bind_section(game_exe))

    def test_unpack_without_backup(self):
        """When backup=False, swapping succeeds without creating .gamecleaner_backup."""
        fake_cli = self.tools_dir / "Steamless.CLI.exe"
        fake_cli.write_text("dummy cli", encoding="utf-8")

        game_exe = self.work_dir / "game_nobackup.exe"
        game_exe.write_bytes(b"MZ" + b"\x00" * 50 + b".bind" + b"\x00" * 50)

        unpacker = SteamlessUnpacker(steamless_path=fake_cli)

        def fake_run(cmd, **kwargs):
            unpacked_file = game_exe.with_name("game_nobackup.exe.unpacked.exe")
            unpacked_file.write_bytes(b"MZ" + b"\x00" * 150)
            return MagicMock(returncode=0, stdout="Unpacked", stderr="")

        with patch("subprocess.run", side_effect=fake_run):
            res = unpacker.unpack_binary(game_exe, backup=False)

        self.assertTrue(res.success)
        self.assertIsNone(res.backup_created)
        backup_dir = game_exe.parent / ".gamecleaner_backup"
        self.assertFalse(backup_dir.exists())

    def test_unpack_validation_failure_bind_still_present(self):
        """If unpacked binary still contains .bind section, unpack fails validation."""
        fake_cli = self.tools_dir / "Steamless.CLI.exe"
        fake_cli.write_text("dummy cli", encoding="utf-8")

        game_exe = self.work_dir / "stubborn_game.exe"
        game_exe.write_bytes(b"MZ" + b"\x00" * 50 + b".bind" + b"\x00" * 50)

        unpacker = SteamlessUnpacker(steamless_path=fake_cli)

        # Simulate unpacked file that still has .bind
        def fake_run(cmd, **kwargs):
            unpacked_file = game_exe.with_name("stubborn_game.exe.unpacked.exe")
            unpacked_file.write_bytes(b"MZ" + b"\x00" * 50 + b".bind" + b"\x00" * 50)
            return MagicMock(returncode=0, stdout="Unpacked", stderr="")

        with patch("subprocess.run", side_effect=fake_run):
            res = unpacker.unpack_binary(game_exe, backup=True)

        self.assertFalse(res.success)
        self.assertIn("Integrity check failed: .bind section is still detected", res.error_message)

    def test_ntfs_evasion_swap_locked_file(self):
        """Simulates locked original file where rename-first evasion (.gc_old) is required."""
        fake_cli = self.tools_dir / "Steamless.CLI.exe"
        fake_cli.write_text("dummy cli", encoding="utf-8")

        game_exe = self.work_dir / "locked_game.exe"
        game_exe.write_bytes(b"MZ" + b"\x00" * 100)

        unpacker = SteamlessUnpacker(steamless_path=fake_cli)

        unpacked_file = game_exe.with_name("locked_game.exe.unpacked.exe")
        unpacked_file.write_bytes(b"MZ" + b"\x00" * 200)

        # Mock first os.replace to raise PermissionError (locked file simulation)
        orig_replace = os.replace
        first_call = True

        def mock_replace(src, dst):
            nonlocal first_call
            if first_call and dst == str(game_exe):
                first_call = False
                raise PermissionError("Access is denied (locked by process)")
            return orig_replace(src, dst)

        with patch("os.replace", side_effect=mock_replace):
            unpacker._swap_binary(unpacked_file, game_exe)

        # Binary should have been replaced successfully via the evasion path
        self.assertEqual(game_exe.read_bytes(), b"MZ" + b"\x00" * 200)


if __name__ == "__main__":
    unittest.main()
