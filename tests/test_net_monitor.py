"""
Unit tests for GameCleaner NetworkMonitor and real-time socket triage.
"""

from collections import namedtuple
import json
import os
from pathlib import Path
import shutil
import socket
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from gamecleaner.containment.net_monitor import (
    CATEGORY_COINMINER_POOL,
    CATEGORY_LOOPBACK,
    CATEGORY_PRIVATE_LAN,
    CATEGORY_PUBLIC_INTERNET,
    COINMINER_PORTS,
    ConnectionRecord,
    NetworkAuditReport,
    NetworkMonitor,
    categorize_endpoint,
)

# Mock psutil namedtuple objects matching psutil._common.sconn
MockAddr = namedtuple("MockAddr", ["ip", "port"])
MockConn = namedtuple("MockConn", ["fd", "family", "type", "laddr", "raddr", "status", "pid"])


class TestNetworkMonitor(unittest.TestCase):

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="gc_test_netmon_")).resolve()
        self.monitor = NetworkMonitor(target="SniperElite.exe", target_dir=self.test_dir)

    def tearDown(self):
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_categorize_loopback(self):
        """Verifies loopback addresses are categorized as LOOPBACK."""
        self.assertEqual(categorize_endpoint("127.0.0.1", 5000), CATEGORY_LOOPBACK)
        self.assertEqual(categorize_endpoint("127.0.0.2", 27015), CATEGORY_LOOPBACK)
        self.assertEqual(categorize_endpoint("::1", 8080), CATEGORY_LOOPBACK)
        self.assertEqual(categorize_endpoint("localhost", 1234), CATEGORY_LOOPBACK)
        self.assertEqual(categorize_endpoint("", 0), CATEGORY_LOOPBACK)

    def test_categorize_private_lan_rfc1918(self):
        """Verifies RFC 1918 subnets and local listening bindings are categorized as PRIVATE_LAN."""
        # 10.0.0.0/8
        self.assertEqual(categorize_endpoint("10.0.0.1", 80), CATEGORY_PRIVATE_LAN)
        self.assertEqual(categorize_endpoint("10.254.1.99", 27015), CATEGORY_PRIVATE_LAN)

        # 172.16.0.0/12
        self.assertEqual(categorize_endpoint("172.16.0.5", 8080), CATEGORY_PRIVATE_LAN)
        self.assertEqual(categorize_endpoint("172.31.255.254", 443), CATEGORY_PRIVATE_LAN)

        # 192.168.0.0/16
        self.assertEqual(categorize_endpoint("192.168.1.1", 80), CATEGORY_PRIVATE_LAN)
        self.assertEqual(categorize_endpoint("192.168.100.50", 27015), CATEGORY_PRIVATE_LAN)

        # Link-local and wildcard 0.0.0.0 binding
        self.assertEqual(categorize_endpoint("169.254.1.1", 5000), CATEGORY_PRIVATE_LAN)
        self.assertEqual(categorize_endpoint("0.0.0.0", 27015), CATEGORY_PRIVATE_LAN)

    def test_categorize_public_internet(self):
        """Verifies external internet addresses are categorized as PUBLIC_INTERNET."""
        self.assertEqual(categorize_endpoint("8.8.8.8", 53), CATEGORY_PUBLIC_INTERNET)
        self.assertEqual(categorize_endpoint("1.1.1.1", 80), CATEGORY_PUBLIC_INTERNET)
        self.assertEqual(categorize_endpoint("93.184.216.34", 443), CATEGORY_PUBLIC_INTERNET)
        self.assertEqual(categorize_endpoint("142.250.190.46", 443), CATEGORY_PUBLIC_INTERNET)

    def test_categorize_coinminer_pool_ports(self):
        """Verifies suspicious mining ports are categorized as COINMINER_POOL."""
        for port in (3333, 4444, 5555, 7777, 8888, 14444, 33333):
            # Port check should trigger even across external, private, or loopback IPs
            self.assertEqual(categorize_endpoint("198.51.100.1", port), CATEGORY_COINMINER_POOL)
            self.assertEqual(categorize_endpoint("10.0.0.5", port), CATEGORY_COINMINER_POOL)
            self.assertEqual(categorize_endpoint("127.0.0.1", port), CATEGORY_COINMINER_POOL)

    def test_categorize_coinminer_pool_domains(self):
        """Verifies suspicious mining domains are categorized as COINMINER_POOL."""
        mining_domains = [
            "pool.supportxmr.com",
            "stratum+tcp://xmr.nicehash.com",
            "eth.nanopool.org",
            "moneroocean.stream",
            "xmrpool.eu",
            "miningpoolhub.com",
        ]
        for domain in mining_domains:
            self.assertEqual(
                categorize_endpoint("1.2.3.4", 80, domain_or_host=domain),
                CATEGORY_COINMINER_POOL,
            )

    def test_connection_record_serialization(self):
        """Verifies ConnectionRecord dataclass converts properly to dictionary."""
        rec = ConnectionRecord(
            pid=1234,
            process_name="SniperElite.exe",
            laddr="127.0.0.1:50000",
            raddr="",
            status="LISTEN",
            category=CATEGORY_LOOPBACK,
            timestamp="2026-11-20T12:00:00Z",
            protocol="tcp",
            details="Local listening socket",
        )
        data = rec.to_dict()
        self.assertEqual(data["pid"], 1234)
        self.assertEqual(data["process_name"], "SniperElite.exe")
        self.assertEqual(data["category"], CATEGORY_LOOPBACK)
        self.assertEqual(data["status"], "LISTEN")

    def test_network_audit_report_safety_and_serialization(self):
        """Verifies NetworkAuditReport JSON generation, safety check, and disk persistence."""
        rec_safe = ConnectionRecord(
            pid=1234,
            process_name="SniperElite.exe",
            laddr="127.0.0.1:50000",
            raddr="127.0.0.1:27015",
            status="ESTABLISHED",
            category=CATEGORY_LOOPBACK,
            timestamp="2026-11-20T12:00:00Z",
        )
        report = NetworkAuditReport(
            target_name="SniperElite",
            timestamp="2026-11-20T12:00:00Z",
            duration_seconds=3.0,
            total_connections_observed=1,
            categories_count={
                CATEGORY_LOOPBACK: 1,
                CATEGORY_PRIVATE_LAN: 0,
                CATEGORY_PUBLIC_INTERNET: 0,
                CATEGORY_COINMINER_POOL: 0,
            },
            records=[rec_safe],
            suspicious_count=0,
            is_safe=True,
            summary="Clean & Isolated",
        )

        # JSON String
        json_str = report.to_json()
        data = json.loads(json_str)
        self.assertTrue(data["is_safe"])
        self.assertEqual(data["total_connections_observed"], 1)

        # File save
        out_file = self.test_dir / "audit_test.json"
        saved_path = report.save_json(out_file)
        self.assertTrue(saved_path.exists())
        loaded = json.loads(saved_path.read_text(encoding="utf-8"))
        self.assertEqual(loaded["target_name"], "SniperElite")
        self.assertEqual(len(loaded["records"]), 1)

    def test_sample_connections_mocked(self):
        """Samples simulated socket connections covering all four triage categories."""
        # Setup mock process discovery and network connections
        mock_proc = MagicMock()
        mock_proc.info = {"pid": 5555, "name": "SniperElite.exe"}

        mock_psutil = MagicMock()
        mock_psutil.process_iter.return_value = [mock_proc]
        mock_psutil.net_connections.return_value = [
            # 1. Safe Loopback
            MockConn(fd=1, family=socket.AF_INET, type=socket.SOCK_STREAM,
                     laddr=MockAddr("127.0.0.1", 50001), raddr=MockAddr("127.0.0.1", 27015),
                     status="ESTABLISHED", pid=5555),
            # 2. LAN Co-op
            MockConn(fd=2, family=socket.AF_INET, type=socket.SOCK_STREAM,
                     laddr=MockAddr("192.168.1.100", 50002), raddr=MockAddr("192.168.1.150", 27015),
                     status="ESTABLISHED", pid=5555),
            # 3. Public Telemetry Beacon
            MockConn(fd=3, family=socket.AF_INET, type=socket.SOCK_STREAM,
                     laddr=MockAddr("192.168.1.100", 50003), raddr=MockAddr("93.184.216.34", 443),
                     status="ESTABLISHED", pid=5555),
            # 4. Hostile Coinminer Pool Connection (Port 3333)
            MockConn(fd=4, family=socket.AF_INET, type=socket.SOCK_STREAM,
                     laddr=MockAddr("192.168.1.100", 50004), raddr=MockAddr("198.51.100.2", 3333),
                     status="ESTABLISHED", pid=5555),
        ]

        with patch("gamecleaner.containment.net_monitor.psutil", mock_psutil):
            records = self.monitor.sample_connections()
            self.assertEqual(len(records), 4)

        categories = [r.category for r in records]
        self.assertIn(CATEGORY_LOOPBACK, categories)
        self.assertIn(CATEGORY_PRIVATE_LAN, categories)
        self.assertIn(CATEGORY_PUBLIC_INTERNET, categories)
        self.assertIn(CATEGORY_COINMINER_POOL, categories)

        # Build report and check threat analysis
        report = self.monitor.build_report(duration_seconds=1.5)
        self.assertFalse(report.is_safe)
        self.assertEqual(report.categories_count[CATEGORY_COINMINER_POOL], 1)
        self.assertEqual(report.categories_count[CATEGORY_PUBLIC_INTERNET], 1)
        self.assertIn("CRITICAL ALERT", report.summary)
        self.assertEqual(len(report.coinminer_alerts), 1)

    def test_generate_audit_report_creates_expected_filename(self):
        """Verifies generate_audit_report writes net_audit_<game>.json."""
        # Add a mock record
        self.monitor.records.append(ConnectionRecord(
            pid=9999,
            process_name="SniperElite.exe",
            laddr="127.0.0.1:40000",
            raddr="127.0.0.1:27015",
            status="ESTABLISHED",
            category=CATEGORY_LOOPBACK,
            timestamp="2026-11-20T12:00:00Z",
        ))

        json_file = self.monitor.generate_audit_report()
        self.assertTrue(json_file.exists())
        self.assertEqual(json_file.name, "net_audit_SniperElite.json")

        loaded = json.loads(json_file.read_text(encoding="utf-8"))
        self.assertEqual(loaded["target_name"], "SniperElite")
        self.assertEqual(loaded["categories_count"][CATEGORY_LOOPBACK], 1)

    def test_real_process_sampling(self):
        """Samples real connections from current Python process without errors."""
        cur_pid = os.getpid()
        mon = NetworkMonitor(target=cur_pid, target_dir=self.test_dir)
        records = mon.sample_connections()
        self.assertIsInstance(records, list)

        rep = mon.build_report()
        self.assertIsInstance(rep, NetworkAuditReport)
        self.assertEqual(rep.target_name, f"PID_{cur_pid}")


if __name__ == "__main__":
    unittest.main()
