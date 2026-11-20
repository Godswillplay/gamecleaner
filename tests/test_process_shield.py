import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from gamecleaner.containment.process_shield import ProcessShield, ShieldResult


class TestProcessShield(unittest.TestCase):
    """Unit tests for ProcessShield (Exploit Protection & Process Mitigation)."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.game_dir = Path(self.temp_dir.name).resolve()

        # Setup mock game binaries
        (self.game_dir / "Game.exe").write_bytes(b"MZ" + b"\x00" * 100)
        bin_dir = self.game_dir / "bin" / "x64"
        bin_dir.mkdir(parents=True)
        (bin_dir / "GameSub.exe").write_bytes(b"MZ" + b"\x00" * 100)

        # Ignored files
        quar_dir = self.game_dir / ".quarantine"
        quar_dir.mkdir()
        (quar_dir / "Miner.exe").write_bytes(b"MZ" + b"\x00" * 100)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_find_executables_and_names(self):
        shield = ProcessShield(self.game_dir)
        found = shield.find_executables()
        names = shield.get_target_exe_names()

        self.assertEqual(len(found), 2)
        self.assertIn("Game.exe", names)
        self.assertIn("GameSub.exe", names)
        self.assertNotIn("Miner.exe", names)

    def test_explicit_executables_override(self):
        shield = ProcessShield(self.game_dir, exes=["CustomGame.exe"])
        names = shield.get_target_exe_names()
        self.assertEqual(names, ["CustomGame.exe"])

    def test_generate_scripts_content(self):
        shield = ProcessShield(self.game_dir)
        apply_script, remove_script = shield.generate_scripts()

        self.assertTrue(apply_script.exists())
        self.assertTrue(remove_script.exists())

        apply_text = apply_script.read_text(encoding="utf-8")
        self.assertIn("Set-ProcessMitigation", apply_text)
        self.assertIn("-Enable DisallowChildProcessCreation,StrictHandleCheck", apply_text)
        self.assertIn("'Game.exe'", apply_text)
        self.assertIn("'GameSub.exe'", apply_text)
        self.assertIn("param(\n    [switch]$NoPause\n)", apply_text)

        remove_text = remove_script.read_text(encoding="utf-8")
        self.assertIn("Set-ProcessMitigation", remove_text)
        self.assertIn("-Disable DisallowChildProcessCreation,StrictHandleCheck", remove_text)
        self.assertIn("'Game.exe'", remove_text)
        self.assertIn("'GameSub.exe'", remove_text)

    @patch("gamecleaner.containment.process_shield.is_running_as_admin", return_value=True)
    @patch("subprocess.run")
    def test_apply_elevated(self, mock_run, mock_admin):
        # Mock successful Set-ProcessMitigation execution and inspection
        mock_proc_set = MagicMock()
        mock_proc_set.returncode = 0
        mock_proc_set.stdout = ""
        mock_proc_set.stderr = ""

        # Mock inspect response
        inspect_json = json.dumps({"Exe": "Game.exe", "Disallow": True, "Strict": True})
        mock_proc_inspect = MagicMock()
        mock_proc_inspect.returncode = 0
        mock_proc_inspect.stdout = inspect_json

        mock_run.side_effect = [mock_proc_set, mock_proc_inspect, mock_proc_set, mock_proc_inspect]

        shield = ProcessShield(self.game_dir)
        results = shield.apply()

        self.assertEqual(len(results), 2)
        for r in results:
            self.assertTrue(r.applied)
            self.assertTrue(r.disallow_child_process)
            self.assertTrue(r.strict_handle)
            self.assertIsNotNone(r.script_path)
            self.assertTrue(r.script_path.exists())

    @patch("gamecleaner.containment.process_shield.is_running_as_admin", return_value=False)
    def test_apply_non_elevated(self, mock_admin):
        shield = ProcessShield(self.game_dir)
        results = shield.apply()

        self.assertEqual(len(results), 2)
        for r in results:
            self.assertFalse(r.applied)
            self.assertFalse(r.disallow_child_process)
            self.assertFalse(r.strict_handle)
            self.assertIsNotNone(r.script_path)
            self.assertTrue(r.script_path.exists())
            self.assertIn("Requires Administrator", r.details)

    @patch("gamecleaner.containment.process_shield.is_running_as_admin", return_value=True)
    @patch("subprocess.run")
    def test_remove_elevated(self, mock_run, mock_admin):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        shield = ProcessShield(self.game_dir, exes=["Game.exe"])
        results = shield.remove()

        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertTrue(r.applied)
        self.assertFalse(r.disallow_child_process)
        self.assertFalse(r.strict_handle)
        self.assertIn("disabled directly", r.details)

    @patch("gamecleaner.containment.process_shield.is_running_as_admin", return_value=False)
    def test_remove_non_elevated(self, mock_admin):
        shield = ProcessShield(self.game_dir, exes=["Game.exe"])
        results = shield.remove()

        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertFalse(r.applied)
        self.assertIn("Requires Administrator", r.details)

    @patch("subprocess.run")
    def test_inspect_mitigations_active(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = json.dumps({"Exe": "Game.exe", "Disallow": True, "Strict": True})
        mock_run.return_value = mock_proc

        shield = ProcessShield(self.game_dir)
        res = shield.inspect_mitigations("Game.exe")

        self.assertTrue(res.applied)
        self.assertTrue(res.disallow_child_process)
        self.assertTrue(res.strict_handle)
        self.assertEqual(res.exe_name, "Game.exe")

    @patch("subprocess.run")
    def test_inspect_mitigations_not_set(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = json.dumps({"Exe": "Game.exe", "Disallow": False, "Strict": False})
        mock_run.return_value = mock_proc

        shield = ProcessShield(self.game_dir)
        res = shield.inspect_mitigations("Game.exe")

        self.assertFalse(res.applied)
        self.assertFalse(res.disallow_child_process)
        self.assertFalse(res.strict_handle)

    @patch("subprocess.run")
    def test_request_elevation_and_apply(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        shield = ProcessShield(self.game_dir)
        success = shield.request_elevation_and_apply()
        self.assertTrue(success)
        mock_run.assert_called_once()
        cmd_arg = mock_run.call_args[0][0]
        self.assertIn("Start-Process powershell -Verb RunAs", cmd_arg[3])


if __name__ == "__main__":
    unittest.main()
