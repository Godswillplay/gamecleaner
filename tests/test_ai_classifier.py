import tempfile
import unittest
from pathlib import Path

from gamecleaner.analyzer.ai_classifier import AIDecompilerClassifier
from gamecleaner.analyzer.pe_scanner import PEScanResult
from gamecleaner.analyzer.threat_rules import ThreatSeverity


class TestAIDecompilerClassifier(unittest.TestCase):

    def setUp(self):
        self.classifier = AIDecompilerClassifier()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.sample_file = Path(self.temp_dir.name) / "test_hook.dll"
        self.sample_file.write_bytes(b"MZ" + b"\x00" * 500)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_evaluate_offline_heuristics_malware(self):
        mock_result = PEScanResult(
            file_name="injector.exe",
            file_path=self.sample_file,
            file_size=1024,
            is_pe=True,
            architecture="x64",
            overall_severity=ThreatSeverity.CRITICAL.value,
            threat_score=90,
            recommended_action="QUARANTINE",
            verdict="Suspicious",
            sha256="abcdef1234567890",
        )
        mock_result.sensitive_imports_found = ["WriteProcessMemory", "CreateRemoteThread"]
        verdict, conf = self.classifier._evaluate_offline_heuristics(
            mock_result,
            critical_strings=["Network: http://evil-c2.com/drop", "powershell -enc ..."],
        )
        self.assertEqual(verdict, "MALICIOUS_PROCESS_INJECTION")
        self.assertGreaterEqual(conf, 0.90)

    def test_build_triage_payload(self):
        mock_result = PEScanResult(
            file_name="test_hook.dll",
            file_path=self.sample_file,
            file_size=512,
            is_pe=True,
            architecture="x64",
            overall_severity=ThreatSeverity.LOW.value,
            threat_score=10,
            recommended_action="KEEP",
            verdict="Clean",
            sha256="dummyhash",
        )
        payload = self.classifier.build_triage_payload(mock_result)
        self.assertEqual(payload.architecture, "x64")
        self.assertIn("Task for AI Security Analyst", payload.formatted_llm_prompt)
        self.assertIn("BENIGN_CRACK or HOSTILE_MALWARE", payload.formatted_llm_prompt)


if __name__ == "__main__":
    unittest.main()
