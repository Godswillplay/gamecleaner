import argparse
import tempfile
import unittest
from pathlib import Path

from gamecleaner.cli import (
    handle_verify,
    handle_deps,
    handle_sideload,
    handle_shield,
    handle_drivers,
    handle_proton,
    handle_monitor,
    handle_steamless,
    handle_save_sync,
    handle_anticheat,
    handle_mods,
    handle_eos,
    handle_crash_log,
    handle_mem_audit,
    handle_cloud_save,
)
from gamecleaner.cleaner.integrity_verifier import MANIFEST_FILENAME


class TestNewCLICommands(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.game_dir = Path(self.temp_dir.name)

        # Populate a sample game structure
        (self.game_dir / "Game.exe").write_bytes(b"MZ" + b"\x00" * 100)
        (self.game_dir / "steam_appid.txt").write_text("480\n", encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_cli_verify_create_and_check(self):
        # 1. Create manifest via CLI
        args = argparse.Namespace(path=str(self.game_dir), create=True, check=False)
        handle_verify(args)
        self.assertTrue((self.game_dir / MANIFEST_FILENAME).exists())

        # 2. Check manifest via CLI
        check_args = argparse.Namespace(path=str(self.game_dir), create=False, check=True)
        handle_verify(check_args)

    def test_cli_deps_audit(self):
        args = argparse.Namespace(path=str(self.game_dir), install=False)
        handle_deps(args)

    def test_cli_sideload_audit(self):
        # Place a mock sideload DLL
        (self.game_dir / "version.dll").write_bytes(b"MZ" + b"\x00" * 100)
        args = argparse.Namespace(path=str(self.game_dir))
        handle_sideload(args)

    def test_cli_shield(self):
        args = argparse.Namespace(path=str(self.game_dir), apply=False, remove=False, elevate=False)
        handle_shield(args)
        self.assertTrue((self.game_dir / "Apply_Process_Shield.ps1").exists())
        self.assertTrue((self.game_dir / "Remove_Process_Shield.ps1").exists())

    def test_cli_drivers(self):
        # Place a mock driver binary and script
        (self.game_dir / "test.sys").write_bytes(b"MZ" + b"\x00" * 100)
        (self.game_dir / "install.bat").write_text('sc create Svc binPath= "%~dp0test.sys"\n', encoding="utf-8")
        args = argparse.Namespace(path=str(self.game_dir))
        handle_drivers(args)

    def test_cli_proton(self):
        args = argparse.Namespace(path=str(self.game_dir))
        handle_proton(args)
        self.assertTrue((self.game_dir / "run_proton.sh").exists())
        self.assertTrue((self.game_dir / "setup_steamdeck.sh").exists())

    def test_cli_monitor(self):
        # Run a quick 1-second sample on game executable
        args = argparse.Namespace(path=str(self.game_dir / "Game.exe"), duration=1)
        handle_monitor(args)

    def test_cli_steamless_unavailable(self):
        # When steamless is not on path or tools
        args = argparse.Namespace(path=str(self.game_dir / "Game.exe"))
        with self.assertRaises(SystemExit):
            handle_steamless(args)

    def test_cli_save_sync(self):
        # 1. Snapshot
        args = argparse.Namespace(path=str(self.game_dir), restore=None, list=False, snapshot=True, note="Test note", app_id="480")
        handle_save_sync(args)

        # 2. List
        list_args = argparse.Namespace(path=str(self.game_dir), restore=None, list=True, snapshot=False, note="", app_id="480")
        handle_save_sync(list_args)


    def test_cli_anticheat(self):
        # Place a mock anti-cheat setup
        (self.game_dir / "EasyAntiCheat_Setup.exe").write_bytes(b"MZ" + b"\x00" * 100)
        args = argparse.Namespace(path=str(self.game_dir))
        handle_anticheat(args)

    def test_cli_mods(self):
        # Place mock ReShade mod files
        (self.game_dir / "dxgi.dll").write_bytes(b"MZ" + b"\x00" * 100)
        (self.game_dir / "ReShade.ini").write_text("[GENERAL]\n", encoding="utf-8")
        args = argparse.Namespace(path=str(self.game_dir))
        handle_mods(args)

    def test_cli_eos(self):
        # Place mock EOS SDK DLL
        (self.game_dir / "EOSSDK-Win64-Shipping.dll").write_bytes(b"MZ" + b"\x00" * 100)
        args = argparse.Namespace(path=str(self.game_dir), clean=True)
        handle_eos(args)

    def test_cli_crash_log(self):
        args = argparse.Namespace(path=str(self.game_dir / "Game.exe"))
        handle_crash_log(args)

    def test_cli_mem_audit_current_pid(self):
        import os
        args = argparse.Namespace(pid=os.getpid(), name=None)
        handle_mem_audit(args)

    def test_cli_cloud_save_export(self):
        args = argparse.Namespace(path=str(self.game_dir), export_deck=True, import_steam=None, app_id="480")
        handle_cloud_save(args)


if __name__ == "__main__":
    unittest.main()
