import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from gamecleaner.containment.shell_integration import ShellIntegrationManager


class TestShellIntegration(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.mgr = ShellIntegrationManager()
        self.mgr.home_dir = Path(self.temp_dir.name).resolve()
        self.mgr.bat_path = self.mgr.home_dir / "clean_game_context.bat"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_ensure_launcher_script(self):
        bat = self.mgr._ensure_launcher_script()
        self.assertTrue(bat.exists())
        content = bat.read_text(encoding="utf-8")
        self.assertIn("gamecleaner.cli clean-all", content)
        self.assertIn("pause", content)

    @patch("winreg.CreateKey")
    @patch("winreg.SetValueEx")
    def test_install_mock(self, mock_set_val, mock_create_key):
        mock_create_key.return_value.__enter__.return_value = MagicMock()
        ok, msg = self.mgr.install()
        self.assertTrue(ok)
        self.assertIn("successfully", msg.lower())


if __name__ == "__main__":
    unittest.main()
