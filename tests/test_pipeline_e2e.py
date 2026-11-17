"""
End-to-End Pipeline integration test.
"""
from pathlib import Path
import shutil
import tempfile
import unittest

from gamecleaner.pipeline import GameCleanerPipeline


class TestPipelineE2E(unittest.TestCase):

    def setUp(self):
        self.game_dir = Path(tempfile.mkdtemp(prefix="mock_game_"))
        self.explorer_path = Path(r"C:\Windows\explorer.exe")

        # 1. Create a clean game executable
        if self.explorer_path.exists():
            shutil.copy2(str(self.explorer_path), str(self.game_dir / "mygame.exe"))
        else:
            (self.game_dir / "mygame.exe").write_bytes(b"MZ" + b"\x00" * 1024)

        # 2. Create a mock steam_api64.dll
        (self.game_dir / "steam_api64.dll").write_bytes(b"MZ" + b"\x00" * 2048)

        # 3. Create a malicious dropper file with suspicious string payload
        malicious_content = (
            b"MZ" + b"\x00" * 512 +
            b"https://discord.com/api/webhooks/1234567890/abcdefghijklmnopqrstuvwxyz123456" +
            b"\x00" * 512
        )
        (self.game_dir / "shady_patcher.exe").write_bytes(malicious_content)

    def tearDown(self):
        if self.game_dir.exists():
            shutil.rmtree(self.game_dir, ignore_errors=True)

    def test_full_pipeline_run(self):
        pipeline = GameCleanerPipeline(
            target_dir=self.game_dir,
            auto_quarantine=True,
            auto_replace_emu=True,
            auto_firewall=True,
            generate_sandbox=True,
        )

        report = pipeline.run_full_pipeline()

        # Check findings
        self.assertGreaterEqual(report.total_files_scanned, 2)

        # Check malicious file was quarantined
        self.assertFalse((self.game_dir / "shady_patcher.exe").exists())
        quarantine_dir = self.game_dir / ".gamecleaner_quarantine"
        self.assertTrue(quarantine_dir.exists())
        quarantined_files = list(quarantine_dir.glob("*.quarantined"))
        self.assertEqual(len(quarantined_files), 1)

        # Check firewall scripts
        self.assertTrue((self.game_dir / "block_game_network.ps1").exists())
        self.assertTrue((self.game_dir / "unblock_game_network.ps1").exists())

        # Check sandbox file
        wsb_files = list(self.game_dir.glob("Sandbox_*.wsb"))
        self.assertEqual(len(wsb_files), 1)

        # Check reports
        self.assertTrue((self.game_dir / "gamecleaner_report.json").exists())
        self.assertTrue((self.game_dir / "gamecleaner_report.md").exists())


if __name__ == "__main__":
    unittest.main()
