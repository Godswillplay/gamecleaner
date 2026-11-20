"""
Unit and Integration Tests for GameCleaner WebUI and REST API Server.
Validates zero-dependency HTTP server, security headers, CSRF/DNS-rebinding protection,
endpoint routing, and asynchronous triage workflows.
"""

import json
from pathlib import Path
import tempfile
import time
from typing import Any, Dict, Optional, Tuple, Union
import unittest
import urllib.error
import urllib.parse
import urllib.request

from gamecleaner.web.api import WebAPI
from gamecleaner.web.server import WebDashboardServer, start_server, stop_server
from gamecleaner.web.templates import get_dashboard_html


def http_request(
    url: str,
    method: str = "GET",
    data: Optional[Union[Dict, str, bytes]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 20.0,
) -> Tuple[int, Dict[str, str], bytes]:
    """Helper executing synchronous HTTP requests via urllib with error capture."""
    headers = headers or {}
    body_bytes = None

    if data is not None:
        if isinstance(data, dict):
            body_bytes = json.dumps(data).encode("utf-8")
            headers.setdefault("Content-Type", "application/json")
        elif isinstance(data, str):
            body_bytes = data.encode("utf-8")
        else:
            body_bytes = data

    req = urllib.request.Request(url, data=body_bytes, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


class TestWebTemplates(unittest.TestCase):
    """Tests the single-page application dashboard template generation."""

    def test_dashboard_html_rendering(self):
        csrf = "test_csrf_token_12345"
        html = get_dashboard_html(csrf, {"host": "127.0.0.1", "port": 8443, "version": "1.0.0"})

        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn(f'content="{csrf}"', html)
        self.assertIn("GameCleaner", html)
        self.assertIn("TELEMETRY", html)
        self.assertIn("TRIAGE & SCANNER", html)
        self.assertIn("ONE-CLICK ACTIONS", html)
        self.assertIn("SAVE VAULT", html)
        self.assertIn("NETWORK RADAR", html)
        self.assertIn("X-CSRF-Token", html)


class TestWebAPIUnit(unittest.TestCase):
    """Direct unit tests for WebAPI controller without network transport."""

    def setUp(self):
        self.api = WebAPI(host="127.0.0.1", port=8443)
        self.temp_dir = tempfile.TemporaryDirectory()
        self.game_path = Path(self.temp_dir.name).resolve()

        # Create dummy game binaries
        (self.game_path / "game.exe").write_bytes(b"MZ" + b"\x00" * 200)
        (self.game_path / "steam_api64.dll").write_bytes(b"MZ" + b"\x00" * 200)
        (self.game_path / "steam_appid.txt").write_text("480", encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_get_status(self):
        status = self.api.get_status()
        self.assertEqual(status["status"], "operational")
        self.assertIn("tools", status)
        self.assertIn("goldberg", status["tools"])
        self.assertIn("innoextract", status["tools"])
        self.assertIn("steamless", status["tools"])

    def test_scan_sync_and_async(self):
        # Sync
        res = self.api.scan(self.game_path, async_mode=False)
        self.assertIn("total_files", res)
        self.assertGreaterEqual(res["total_files"], 1)
        self.assertIn("clean_count", res)
        self.assertIn("sideloads", res)

        # Async
        async_res = self.api.scan(self.game_path, async_mode=True)
        self.assertIn("job_id", async_res)
        self.assertEqual(async_res["status"], "running")

        # Poll job
        job_id = async_res["job_id"]
        for _ in range(50):
            job = self.api.get_job(job_id)
            if job and job["status"] in ("completed", "failed"):
                break
            time.sleep(0.05)

        self.assertEqual(job["status"], "completed")
        self.assertIsNotNone(job["result"])

    def test_clean_pipeline(self):
        res = self.api.clean(self.game_path, options={"auto_quarantine": False}, async_mode=False)
        self.assertIn("total_files_scanned", res)
        self.assertIn("target_dir", res)

    def test_snapshots_workflow(self):
        # Create
        c_res = self.api.create_snapshot(self.game_path, note="Test snapshot", appid="480")
        self.assertIn("success", c_res)

        # List
        l_res = self.api.list_snapshots(self.game_path)
        self.assertIn("snapshots", l_res)

        # Restore
        r_res = self.api.restore_snapshot(self.game_path, "nonexistent_snapshot.zip")
        self.assertFalse(r_res["success"])

    def test_containment_endpoints(self):
        # Shield
        shield_res = self.api.apply_shield(self.game_path, action="apply")
        self.assertEqual(shield_res["action"], "apply")
        self.assertIn("apply_script", shield_res)

        # Firewall
        fw_res = self.api.firewall(self.game_path, apply_rules=False)
        self.assertIn("block_script", fw_res)
        self.assertIn("fix_launcher", fw_res)

        # Sandbox
        sb_res = self.api.sandbox(self.game_path)
        self.assertIn("wsb_path", sb_res)

        # Network Monitor
        net_res = self.api.network_monitor()
        self.assertIn("records", net_res)


class TestWebServerIntegration(unittest.TestCase):
    """Full HTTP server integration tests covering requests, security headers, and CSRF."""

    @classmethod
    def setUpClass(cls):
        # Bind to port 0 for ephemeral port assignment
        cls.server = WebDashboardServer(host="127.0.0.1", port=0, csrf_protect=True)
        cls.server.start(open_browser=False, background=True)
        cls.base_url = cls.server.get_url()
        cls.csrf_token = cls.server.csrf_token

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_game = Path(self.temp_dir.name).resolve()
        (self.test_game / "game.exe").write_bytes(b"MZ" + b"\x00" * 300)
        (self.test_game / "steam_api64.dll").write_bytes(b"MZ" + b"\x00" * 300)
        (self.test_game / "steam_appid.txt").write_text("480", encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()

    # -------------------------------------------------------------------------
    # Static UI and Security Headers
    # -------------------------------------------------------------------------

    def test_get_dashboard_html_and_headers(self):
        status, headers, body = http_request(f"{self.base_url}/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers.get("Content-Type", ""))
        self.assertIn(b"GameCleaner", body)

        # Verify military-grade security headers
        self.assertIn("Content-Security-Policy", headers)
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(headers.get("Referrer-Policy"), "strict-origin-when-cross-origin")
        self.assertIn("no-store", headers.get("Cache-Control", ""))

    def test_dns_rebinding_host_header_protection(self):
        # Host header matching 127.0.0.1 or localhost is allowed
        status, _, _ = http_request(
            f"{self.base_url}/api/status",
            headers={"Host": "127.0.0.1"},
        )
        self.assertEqual(status, 200)

        # Hostile Host header simulating external DNS rebinding (evil.com) must be 403 Forbidden
        status_blocked, _, body_blocked = http_request(
            f"{self.base_url}/api/status",
            headers={"Host": "attacker.com"},
        )
        self.assertEqual(status_blocked, 403)
        self.assertIn(b"DNS rebinding protection", body_blocked)

    def test_cors_options_preflight(self):
        status, headers, _ = http_request(
            f"{self.base_url}/api/status",
            method="OPTIONS",
            headers={"Origin": "http://127.0.0.1:3000"},
        )
        self.assertEqual(status, 204)
        self.assertEqual(headers.get("Access-Control-Allow-Origin"), "http://127.0.0.1:3000")
        self.assertIn("GET", headers.get("Access-Control-Allow-Methods", ""))

    def test_csrf_protection_on_post(self):
        # POST without CSRF token should be rejected with 403
        status, _, body = http_request(
            f"{self.base_url}/api/scan",
            method="POST",
            data={"path": str(self.test_game)},
        )
        self.assertEqual(status, 403)
        self.assertIn(b"CSRF validation failed", body)

        # POST with wrong CSRF token should be rejected with 403
        status_wrong, _, _ = http_request(
            f"{self.base_url}/api/scan",
            method="POST",
            data={"path": str(self.test_game)},
            headers={"X-CSRF-Token": "invalid_csrf_token_value"},
        )
        self.assertEqual(status_wrong, 403)

        # POST with valid CSRF token succeeds
        status_ok, _, body_ok = http_request(
            f"{self.base_url}/api/scan",
            method="POST",
            data={"path": str(self.test_game)},
            headers={"X-CSRF-Token": self.csrf_token},
        )
        self.assertEqual(status_ok, 200)
        res = json.loads(body_ok.decode("utf-8"))
        self.assertIn("total_files", res)

    # -------------------------------------------------------------------------
    # REST API Endpoints
    # -------------------------------------------------------------------------

    def test_api_status_endpoint(self):
        status, _, body = http_request(f"{self.base_url}/api/status")
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertEqual(data["status"], "operational")
        self.assertIn("csrf_token", data)
        self.assertIn("tools", data)

    def test_api_scan_endpoint_validation(self):
        # Missing 'path' parameter
        status_bad, _, body_bad = http_request(
            f"{self.base_url}/api/scan",
            method="POST",
            data={},
            headers={"X-CSRF-Token": self.csrf_token},
        )
        self.assertEqual(status_bad, 400)
        self.assertIn(b"Missing required parameter", body_bad)

        # Nonexistent path
        status_404, _, body_404 = http_request(
            f"{self.base_url}/api/scan",
            method="POST",
            data={"path": "C:\\Definitely\\NonExistent\\GameFolder"},
            headers={"X-CSRF-Token": self.csrf_token},
        )
        self.assertEqual(status_404, 404)

    def test_api_scan_async_and_poll(self):
        status, _, body = http_request(
            f"{self.base_url}/api/scan",
            method="POST",
            data={"path": str(self.test_game), "async": True},
            headers={"X-CSRF-Token": self.csrf_token},
        )
        self.assertEqual(status, 200)
        job_data = json.loads(body.decode("utf-8"))
        self.assertIn("job_id", job_data)
        job_id = job_data["job_id"]

        # Poll job endpoint
        for _ in range(50):
            st, _, job_body = http_request(f"{self.base_url}/api/jobs/{job_id}")
            self.assertEqual(st, 200)
            job = json.loads(job_body.decode("utf-8"))
            if job["status"] in ("completed", "failed"):
                break
            time.sleep(0.05)

        self.assertEqual(job["status"], "completed")
        self.assertIn("clean_count", job["result"])

    def test_api_clean_endpoint(self):
        status, _, body = http_request(
            f"{self.base_url}/api/clean",
            method="POST",
            data={"path": str(self.test_game)},
            headers={"X-CSRF-Token": self.csrf_token},
        )
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertIn("total_files_scanned", data)

    def test_api_snapshots_endpoints(self):
        # 1. Create snapshot
        status_c, _, body_c = http_request(
            f"{self.base_url}/api/snapshots/create",
            method="POST",
            data={"path": str(self.test_game), "note": "Integration test snapshot", "appid": "480"},
            headers={"X-CSRF-Token": self.csrf_token},
        )
        self.assertEqual(status_c, 200)

        # 2. List snapshots
        query_path = urllib.parse.quote(str(self.test_game))
        status_l, _, body_l = http_request(f"{self.base_url}/api/snapshots?path={query_path}")
        self.assertEqual(status_l, 200)
        list_data = json.loads(body_l.decode("utf-8"))
        self.assertIn("snapshots", list_data)

        # 3. Restore snapshot (invalid name should return success=False cleanly)
        status_r, _, body_r = http_request(
            f"{self.base_url}/api/snapshots/restore",
            method="POST",
            data={"path": str(self.test_game), "snapshot": "nonexistent.zip"},
            headers={"X-CSRF-Token": self.csrf_token},
        )
        self.assertEqual(status_r, 200)
        rest_data = json.loads(body_r.decode("utf-8"))
        self.assertFalse(rest_data["success"])

    def test_api_shield_endpoint(self):
        status, _, body = http_request(
            f"{self.base_url}/api/shield",
            method="POST",
            data={"path": str(self.test_game), "action": "apply"},
            headers={"X-CSRF-Token": self.csrf_token},
        )
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertEqual(data["action"], "apply")
        self.assertIn("apply_script", data)

    def test_api_firewall_endpoint(self):
        status, _, body = http_request(
            f"{self.base_url}/api/firewall",
            method="POST",
            data={"path": str(self.test_game), "apply": False},
            headers={"X-CSRF-Token": self.csrf_token},
        )
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertIn("block_script", data)
        self.assertIn("fix_launcher", data)

    def test_api_sandbox_endpoint(self):
        status, _, body = http_request(
            f"{self.base_url}/api/sandbox",
            method="POST",
            data={"path": str(self.test_game)},
            headers={"X-CSRF-Token": self.csrf_token},
        )
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertIn("wsb_path", data)

    def test_api_emulator_replace_endpoint(self):
        status, _, body = http_request(
            f"{self.base_url}/api/emulator/replace",
            method="POST",
            data={"path": str(self.test_game)},
            headers={"X-CSRF-Token": self.csrf_token},
        )
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertIn("drm_targets_found", data)

    def test_api_network_monitor_endpoint(self):
        status, _, body = http_request(f"{self.base_url}/api/network")
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertIn("records", data)

    def test_api_quarantine_endpoint(self):
        query_path = urllib.parse.quote(str(self.test_game))
        status, _, body = http_request(f"{self.base_url}/api/quarantine?path={query_path}")
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertIn("quarantined_files", data)

    def test_api_not_found_and_malformed_json(self):
        # 404 Route
        status_404, _, _ = http_request(f"{self.base_url}/api/nonexistent_route")
        self.assertEqual(status_404, 404)

        # Malformed JSON
        status_400, _, body_400 = http_request(
            f"{self.base_url}/api/scan",
            method="POST",
            data="NOT_JSON_DATA",
            headers={"X-CSRF-Token": self.csrf_token, "Content-Type": "application/json"},
        )
        self.assertEqual(status_400, 400)
        self.assertIn(b"Malformed JSON", body_400)


class TestWebServerLifecycle(unittest.TestCase):
    """Tests server factory start_server and stop_server functions."""

    def test_factory_lifecycle(self):
        srv = start_server(host="127.0.0.1", port=0, open_browser=False, background=True)
        self.assertTrue(srv.is_running)
        self.assertGreater(srv.port, 0)

        url = srv.get_url()
        status, _, _ = http_request(f"{url}/api/status")
        self.assertEqual(status, 200)

        stop_server(srv)
        self.assertFalse(srv.is_running)


if __name__ == "__main__":
    unittest.main()
