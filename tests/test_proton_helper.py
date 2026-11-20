"""
Unit tests for GameCleaner ProtonHelper and Linux / Steam Deck containment.
"""

from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from gamecleaner.containment.proton_helper import (
    ProtonHelper,
    ProtonScriptResult,
    is_network_isolation_supported,
    write_posix_script,
)


class TestProtonHelper(unittest.TestCase):

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="gc_test_proton_")).resolve()
        self.helper = ProtonHelper(self.test_dir)

    def tearDown(self):
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_discover_executable_in_root(self):
        """Discovers primary executable located in the root directory."""
        exe = self.test_dir / "SniperElite.exe"
        exe.write_bytes(b"MZ" + b"\x00" * 4096)

        found = self.helper.discover_executable()
        self.assertIsNotNone(found)
        self.assertEqual(found.resolve(), exe.resolve())

    def test_discover_executable_in_subdirectories(self):
        """Discovers primary executable nested in bin/x64 or Binaries/Win64."""
        bin_dir = self.test_dir / "bin" / "x64"
        bin_dir.mkdir(parents=True)
        exe = bin_dir / "GameEngine.exe"
        exe.write_bytes(b"MZ" + b"\x00" * 8192)

        found = self.helper.discover_executable()
        self.assertIsNotNone(found)
        self.assertEqual(found.resolve(), exe.resolve())

    def test_discover_executable_filters_helpers_and_uninstaller(self):
        """Ignores uninstallers, crash reporters, and DirectX installers."""
        unins = self.test_dir / "unins000.exe"
        unins.write_bytes(b"MZ" + b"\x00" * 2048)

        crash = self.test_dir / "crash_reporter.exe"
        crash.write_bytes(b"MZ" + b"\x00" * 2048)

        dx = self.test_dir / "dxsetup.exe"
        dx.write_bytes(b"MZ" + b"\x00" * 2048)

        real_game = self.test_dir / "RealGame.exe"
        real_game.write_bytes(b"MZ" + b"\x00" * 10240)

        found = self.helper.discover_executable()
        self.assertIsNotNone(found)
        self.assertEqual(found.name, "RealGame.exe")

    def test_discover_emulators(self):
        """Discovers installed Goldberg emulator DLLs."""
        self.assertEqual(self.helper.discover_emulators(), [])

        (self.test_dir / "steam_api64.dll").write_bytes(b"MZ" + b"\x00" * 1024)
        sub = self.test_dir / "bin"
        sub.mkdir()
        (sub / "steam_api.dll").write_bytes(b"MZ" + b"\x00" * 1024)

        found = self.helper.discover_emulators()
        self.assertIn("steam_api.dll", found)
        self.assertIn("steam_api64.dll", found)

    def test_discover_appid_from_text_and_settings(self):
        """Discovers AppID from steam_appid.txt or steam_settings/steam_appid.txt."""
        # 1. Root text file
        (self.test_dir / "steam_appid.txt").write_text("227100\n", encoding="utf-8")
        self.assertEqual(self.helper.discover_appid(), "227100")

        # 2. Settings subfolder
        (self.test_dir / "steam_appid.txt").unlink()
        settings = self.test_dir / "steam_settings"
        settings.mkdir()
        (settings / "steam_appid.txt").write_text("550\n", encoding="utf-8")
        self.assertEqual(self.helper.discover_appid(), "550")

    def test_discover_appid_from_ini(self):
        """Discovers AppID from repack configuration INI files."""
        ini_content = "[Steam]\nAppId=292030\nUserName=Player\n"
        (self.test_dir / "steam_emu.ini").write_text(ini_content, encoding="utf-8")

        self.assertEqual(self.helper.discover_appid(), "292030")

    def test_get_dll_overrides(self):
        """Verifies WINEDLLOVERRIDES string format."""
        overrides = self.helper.get_dll_overrides()
        self.assertIn("steam_api=n,b", overrides)
        self.assertIn("steam_api64=n,b", overrides)

    def test_generate_run_proton_script_posix_endings(self):
        """Generates run_proton.sh ensuring strict LF line endings and proper content."""
        exe = self.test_dir / "Game.exe"
        exe.write_bytes(b"MZ" + b"\x00" * 1024)
        (self.test_dir / "steam_appid.txt").write_text("227100\n", encoding="utf-8")

        script_path = self.helper.generate_run_script(executable=exe)
        self.assertTrue(script_path.exists())

        # Verify strict POSIX LF line endings (zero \r bytes)
        raw_bytes = script_path.read_bytes()
        self.assertNotIn(b"\r\n", raw_bytes)
        self.assertNotIn(b"\r", raw_bytes)
        self.assertIn(b"\n", raw_bytes)

        content = script_path.read_text(encoding="utf-8")
        self.assertIn("#!/usr/bin/env bash", content)
        self.assertIn('export WINEDLLOVERRIDES="steam_api=n,b;steam_api64=n,b"', content)
        self.assertIn("unshare -n", content)
        self.assertIn("firejail --noprofile --net=none", content)
        self.assertIn('export SteamAppId="227100"', content)
        self.assertIn("Game.exe", content)

    def test_generate_steamdeck_setup(self):
        """Generates setup_steamdeck.sh with desktop shortcuts and save folder initialization."""
        (self.test_dir / "steam_appid.txt").write_text("227100\n", encoding="utf-8")

        setup_path = self.helper.generate_steamdeck_setup()
        self.assertTrue(setup_path.exists())

        raw_bytes = setup_path.read_bytes()
        self.assertNotIn(b"\r\n", raw_bytes)

        content = setup_path.read_text(encoding="utf-8")
        self.assertIn("Goldberg SteamEmu Saves/227100", content)
        self.assertIn("[Desktop Entry]", content)
        self.assertIn("run_proton.sh", content)

    def test_generate_all(self):
        """Executes full discovery and returns populated ProtonScriptResult."""
        exe = self.test_dir / "MyGame.exe"
        exe.write_bytes(b"MZ" + b"\x00" * 1024)
        (self.test_dir / "steam_appid.txt").write_text("480\n", encoding="utf-8")

        result = self.helper.generate_all()
        self.assertIsInstance(result, ProtonScriptResult)
        self.assertTrue(result.script_path.exists())
        self.assertTrue(result.setup_script_path.exists())
        self.assertEqual(result.executable_name, "MyGame.exe")
        self.assertEqual(result.appid, "480")
        self.assertEqual(result.overrides, "steam_api=n,b;steam_api64=n,b")
        self.assertIsInstance(result.network_isolation_supported, bool)

    def test_write_posix_script_enforces_lf(self):
        """Ensures write_posix_script strips CRLF and produces exact LF endings."""
        crlf_content = "#!/bin/bash\r\necho 'Hello World'\r\nexit 0\r\n"
        out_file = self.test_dir / "test_lf.sh"
        write_posix_script(out_file, crlf_content)

        raw = out_file.read_bytes()
        self.assertNotIn(b"\r", raw)
        self.assertEqual(raw, b"#!/bin/bash\necho 'Hello World'\nexit 0\n")

    @patch("sys.platform", "linux")
    @patch("shutil.which")
    @patch("subprocess.run")
    def test_is_network_isolation_supported_linux_unshare(self, mock_run, mock_which):
        """Verifies network isolation detection when unshare -n succeeds on Linux."""
        mock_which.side_effect = lambda cmd: "/usr/bin/unshare" if cmd == "unshare" else None
        mock_run.return_value.returncode = 0

        self.assertTrue(is_network_isolation_supported())

    @patch("sys.platform", "win32")
    def test_is_network_isolation_supported_windows(self):
        """On Windows host, network isolation returns False."""
        self.assertFalse(is_network_isolation_supported())


if __name__ == "__main__":
    unittest.main()
