import tempfile
import unittest
from pathlib import Path

from gamecleaner.analyzer.runtime_auditor import RuntimeAuditor, RuntimeAuditReport, DiscoveredRedist


class TestRuntimeAuditor(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.game_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_discover_bundled_repack_redists(self):
        # Create mock _CommonRedist structure
        dx_dir = self.game_dir / "_CommonRedist" / "DirectX" / "Jun2010"
        dx_dir.mkdir(parents=True)
        (dx_dir / "DXSETUP.exe").write_bytes(b"MZ" + b"\x00" * 50)

        vc_dir = self.game_dir / "_CommonRedist" / "vcredist" / "2019"
        vc_dir.mkdir(parents=True)
        (vc_dir / "vc_redist.x64.exe").write_bytes(b"MZ" + b"\x00" * 50)

        auditor = RuntimeAuditor(self.game_dir)
        redists = auditor.discover_redists()

        self.assertEqual(len(redists), 2)
        redist_names = [r.name for r in redists]
        self.assertIn("DirectX End-User Runtimes", redist_names)
        self.assertIn("Visual C++ Redistributable", redist_names)

        # Check recommended silent arguments
        for r in redists:
            if "DirectX" in r.name:
                self.assertEqual(r.recommended_silent_args, "/silent")
            elif "Visual C++" in r.name:
                self.assertEqual(r.recommended_silent_args, "/quiet /norestart")

    def test_empty_directory_audit(self):
        empty_dir = self.game_dir / "EmptyGame"
        empty_dir.mkdir()
        auditor = RuntimeAuditor(empty_dir)
        report = auditor.audit()
        self.assertEqual(report.scanned_binaries_count, 0)
        self.assertTrue(report.is_ready_to_play)
        self.assertEqual(len(report.missing_dependencies), 0)


if __name__ == "__main__":
    unittest.main()
