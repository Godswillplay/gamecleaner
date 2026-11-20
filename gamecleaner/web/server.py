"""
GameCleaner Zero-Dependency Local Web Server.
Uses Python standard library http.server and threading to host a secure local
cybersecurity dashboard and REST API.
"""

import hmac
import http.server
import json
import logging
import os
from pathlib import Path
import secrets
import socket
import threading
from typing import Any, Dict, Optional, Tuple, Union
import urllib.parse
import webbrowser

from gamecleaner.web.api import WebAPI
from gamecleaner.web.templates import get_dashboard_html

logger = logging.getLogger("gamecleaner.web")


class GameCleanerHTTPHandler(http.server.BaseHTTPRequestHandler):
    """Zero-dependency HTTP request handler routing WebUI and REST API endpoints."""

    server: "DashboardHTTPServer"  # type annotation for custom server reference

    def log_message(self, format: str, *args: Any) -> None:
        """Suppresses default stderr logging, delegating to python logging."""
        logger.debug("%s - %s", self.address_string(), format % args)

    # -------------------------------------------------------------------------
    # Security Validation & Header Management
    # -------------------------------------------------------------------------

    def _is_host_valid(self) -> bool:
        """Validates Host header to protect against DNS rebinding attacks."""
        host_hdr = self.headers.get("Host")
        if not host_hdr:
            return True  # HTTP 1.0 or local client without Host header

        # Strip port if present
        host_name = host_hdr.split(":")[0].strip().lower()
        allowed = {"127.0.0.1", "localhost", "0.0.0.0", "::1", self.server.bind_host.lower()}
        return host_name in allowed

    def _check_csrf(self) -> bool:
        """Verifies CSRF token on mutating requests."""
        if not self.server.csrf_protect:
            return True

        token_sent = self.headers.get("X-CSRF-Token")
        if not token_sent:
            return False

        return hmac.compare_digest(token_sent, self.server.csrf_token)

    def _apply_security_headers(self, content_type: str = "application/json") -> None:
        """Applies military-grade web security headers to all responses."""
        self.send_header("Content-Type", content_type)
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self' 'unsafe-inline' data:; connect-src 'self' http://127.0.0.1:* http://localhost:*; object-src 'none'; base-uri 'self';",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")

        # CORS: Safely echo origin if it matches localhost or loopback
        origin = self.headers.get("Origin")
        if origin:
            parsed_origin = urllib.parse.urlparse(origin)
            if parsed_origin.hostname in ("127.0.0.1", "localhost"):
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token")

    def _send_json_response(self, data: Any, status: int = 200) -> None:
        """Serializes and sends a JSON payload with standard security headers."""
        try:
            payload = json.dumps(data, default=str).encode("utf-8")
        except Exception as e:
            self._send_error_response(f"Serialization error: {e}", status=500)
            return

        self.send_response(status)
        self._apply_security_headers("application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_error_response(self, message: str, status: int = 400, details: Optional[Any] = None) -> None:
        """Sends a structured JSON error response."""
        err_dict: Dict[str, Any] = {"error": message, "status": status}
        if details is not None:
            err_dict["details"] = details
        self._send_json_response(err_dict, status=status)

    def _parse_json_body(self) -> Optional[Dict[str, Any]]:
        """Safely parses incoming JSON request body with max-length safeguard."""
        try:
            length_str = self.headers.get("Content-Length", "0")
            length = int(length_str)
        except ValueError:
            self._send_error_response("Invalid Content-Length header", status=400)
            return None

        # Safeguard: Reject requests larger than 10MB
        if length > 10 * 1024 * 1024:
            self._send_error_response("Payload too large (limit 10MB)", status=413)
            return None

        if length == 0:
            return {}

        try:
            raw_data = self.rfile.read(length).decode("utf-8")
            return json.loads(raw_data)
        except json.JSONDecodeError as jde:
            self._send_error_response(f"Malformed JSON: {jde}", status=400)
            return None
        except Exception as e:
            self._send_error_response(f"Error reading body: {e}", status=400)
            return None

    # -------------------------------------------------------------------------
    # HTTP Verbs (OPTIONS, GET, POST)
    # -------------------------------------------------------------------------

    def do_OPTIONS(self) -> None:
        """Handles CORS preflight requests safely."""
        if not self._is_host_valid():
            self._send_error_response("Forbidden: Invalid Host header", status=403)
            return

        self.send_response(204)
        self._apply_security_headers("text/plain")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        """Routes GET requests for dashboard templates and read-only API data."""
        if not self._is_host_valid():
            self._send_error_response("Forbidden: Invalid Host header (DNS rebinding protection)", status=403)
            return

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # 1. Dashboard Single-Page Application Home
        if path == "/" or path == "/index.html":
            server_info = {
                "host": self.server.bind_host,
                "port": self.server.server_port,
                "version": self.server.api.version,
            }
            html_content = get_dashboard_html(self.server.csrf_token, server_info).encode("utf-8")
            self.send_response(200)
            self._apply_security_headers("text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html_content)))
            self.end_headers()
            self.wfile.write(html_content)
            return

        # 2. GET /api/status
        if path == "/api/status":
            status_data = self.server.api.get_status()
            status_data["csrf_token"] = self.server.csrf_token
            self._send_json_response(status_data)
            return

        # 3. GET /api/snapshots?path=<game>
        if path == "/api/snapshots":
            target_path = query.get("path", [None])[0]
            if not target_path:
                self._send_error_response("Missing required query parameter: 'path'", status=400)
                return
            try:
                res = self.server.api.list_snapshots(target_path)
                self._send_json_response(res)
            except Exception as e:
                self._send_error_response(str(e), status=400)
            return

        # 4. GET /api/network
        if path == "/api/network":
            target = query.get("target", [None])[0]
            try:
                res = self.server.api.network_monitor(target=target)
                self._send_json_response(res)
            except Exception as e:
                self._send_error_response(str(e), status=400)
            return

        # 5. GET /api/quarantine
        if path == "/api/quarantine":
            target_path = query.get("path", [None])[0]
            try:
                res = self.server.api.list_quarantine(target_path)
                self._send_json_response(res)
            except Exception as e:
                self._send_error_response(str(e), status=400)
            return

        # 6. GET /api/jobs/<job_id>
        if path.startswith("/api/jobs/"):
            job_id = path[len("/api/jobs/"):]
            job = self.server.api.get_job(job_id)
            if not job:
                self._send_error_response(f"Job not found: {job_id}", status=404)
                return
            self._send_json_response(job)
            return

        # 404 Route Not Found
        self._send_error_response(f"Endpoint not found: {path}", status=404)

    def do_POST(self) -> None:
        """Routes POST requests for scanning, clean pipeline, containment, and rollback."""
        if not self._is_host_valid():
            self._send_error_response("Forbidden: Invalid Host header (DNS rebinding protection)", status=403)
            return

        body = self._parse_json_body()
        if body is None:
            return

        if not self._check_csrf():
            self._send_error_response("Forbidden: CSRF validation failed (missing or invalid X-CSRF-Token)", status=403)
            return

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # 1. POST /api/scan
        if path == "/api/scan":
            target_path = body.get("path")
            if not target_path:
                self._send_error_response("Missing required parameter: 'path'", status=400)
                return
            async_mode = bool(body.get("async", False))
            try:
                res = self.server.api.scan(target_path, async_mode=async_mode)
                self._send_json_response(res)
            except FileNotFoundError as fnf:
                self._send_error_response(str(fnf), status=404)
            except Exception as e:
                self._send_error_response(str(e), status=500)
            return

        # 2. POST /api/clean
        if path == "/api/clean":
            target_path = body.get("path")
            if not target_path:
                self._send_error_response("Missing required parameter: 'path'", status=400)
                return
            async_mode = bool(body.get("async", False))
            options = body.get("options", {})
            try:
                res = self.server.api.clean(target_path, options=options, async_mode=async_mode)
                self._send_json_response(res)
            except FileNotFoundError as fnf:
                self._send_error_response(str(fnf), status=404)
            except Exception as e:
                self._send_error_response(str(e), status=500)
            return

        # 3. POST /api/snapshots/create
        if path == "/api/snapshots/create":
            target_path = body.get("path")
            if not target_path:
                self._send_error_response("Missing required parameter: 'path'", status=400)
                return
            note = body.get("note", "Web Dashboard Snapshot")
            appid = body.get("appid")
            try:
                res = self.server.api.create_snapshot(target_path, note=note, appid=appid)
                self._send_json_response(res)
            except FileNotFoundError as fnf:
                self._send_error_response(str(fnf), status=404)
            except Exception as e:
                self._send_error_response(str(e), status=500)
            return

        # 4. POST /api/snapshots/restore
        if path == "/api/snapshots/restore":
            target_path = body.get("path")
            snapshot = body.get("snapshot")
            if not target_path or not snapshot:
                self._send_error_response("Missing required parameters: 'path' and 'snapshot'", status=400)
                return
            try:
                res = self.server.api.restore_snapshot(target_path, snapshot)
                self._send_json_response(res)
            except FileNotFoundError as fnf:
                self._send_error_response(str(fnf), status=404)
            except Exception as e:
                self._send_error_response(str(e), status=500)
            return

        # 5. POST /api/shield
        if path == "/api/shield":
            target_path = body.get("path")
            if not target_path:
                self._send_error_response("Missing required parameter: 'path'", status=400)
                return
            action = body.get("action", "apply")
            exe_names = body.get("exe_names")
            try:
                res = self.server.api.apply_shield(target_path, action=action, exe_names=exe_names)
                self._send_json_response(res)
            except FileNotFoundError as fnf:
                self._send_error_response(str(fnf), status=404)
            except Exception as e:
                self._send_error_response(str(e), status=500)
            return

        # 6. POST /api/firewall
        if path == "/api/firewall":
            target_path = body.get("path")
            if not target_path:
                self._send_error_response("Missing required parameter: 'path'", status=400)
                return
            apply_rules = bool(body.get("apply", False))
            try:
                res = self.server.api.firewall(target_path, apply_rules=apply_rules)
                self._send_json_response(res)
            except FileNotFoundError as fnf:
                self._send_error_response(str(fnf), status=404)
            except Exception as e:
                self._send_error_response(str(e), status=500)
            return

        # 7. POST /api/sandbox
        if path == "/api/sandbox":
            target_path = body.get("path")
            if not target_path:
                self._send_error_response("Missing required parameter: 'path'", status=400)
                return
            read_only = bool(body.get("read_only", True))
            v_gpu = bool(body.get("v_gpu", True))
            allow_network = bool(body.get("allow_network", False))
            try:
                res = self.server.api.sandbox(target_path, read_only=read_only, v_gpu=v_gpu, allow_network=allow_network)
                self._send_json_response(res)
            except FileNotFoundError as fnf:
                self._send_error_response(str(fnf), status=404)
            except Exception as e:
                self._send_error_response(str(e), status=500)
            return

        # 8. POST /api/emulator/replace
        if path == "/api/emulator/replace":
            target_path = body.get("path")
            if not target_path:
                self._send_error_response("Missing required parameter: 'path'", status=400)
                return
            try:
                res = self.server.api.replace_emulator(target_path)
                self._send_json_response(res)
            except FileNotFoundError as fnf:
                self._send_error_response(str(fnf), status=404)
            except Exception as e:
                self._send_error_response(str(e), status=500)
            return

        # 404 Route Not Found
        self._send_error_response(f"Endpoint not found: {path}", status=404)


class DashboardHTTPServer(http.server.ThreadingHTTPServer):
    """Custom ThreadingHTTPServer maintaining API state, CSRF tokens, and security contexts."""

    def __init__(
        self,
        server_address: Tuple[str, int],
        RequestHandlerClass: Any,
        api: WebAPI,
        csrf_token: str,
        csrf_protect: bool = True,
        bind_host: str = "127.0.0.1",
    ) -> None:
        self.api = api
        self.csrf_token = csrf_token
        self.csrf_protect = csrf_protect
        self.bind_host = bind_host
        super().__init__(server_address, RequestHandlerClass)


class WebDashboardServer:
    """Manages the lifecycle of the local GameCleaner web dashboard server."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8443,
        api: Optional[WebAPI] = None,
        csrf_protect: bool = True,
    ) -> None:
        self.host = host
        self.port = port
        self.csrf_protect = csrf_protect
        self.csrf_token = secrets.token_hex(32)
        self.api = api or WebAPI(host=self.host, port=self.port)
        self._server: Optional[DashboardHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._is_running = False

    @property
    def is_running(self) -> bool:
        return self._is_running

    def get_url(self) -> str:
        """Returns the fully qualified URL to access the dashboard."""
        actual_port = self.port
        if self._server:
            actual_port = self._server.server_port
        return f"http://{self.host}:{actual_port}"

    def start(self, open_browser: bool = False, background: bool = False) -> None:
        """Binds socket, starts HTTP listener, and optionally opens browser."""
        if self._is_running:
            return

        # Bind to requested port, or ephemeral port if 0
        bind_address = (self.host, self.port)
        try:
            self._server = DashboardHTTPServer(
                bind_address,
                GameCleanerHTTPHandler,
                api=self.api,
                csrf_token=self.csrf_token,
                csrf_protect=self.csrf_protect,
                bind_host=self.host,
            )
        except OSError:
            # Fallback to ephemeral port if requested port is busy and was not 0
            if self.port != 0:
                logger.warning("Port %d busy; falling back to automatic port assignment.", self.port)
                self._server = DashboardHTTPServer(
                    (self.host, 0),
                    GameCleanerHTTPHandler,
                    api=self.api,
                    csrf_token=self.csrf_token,
                    csrf_protect=self.csrf_protect,
                    bind_host=self.host,
                )
            else:
                raise

        # Update actual bound port and API metadata
        self.port = self._server.server_port
        self.api.port = self.port
        self._is_running = True

        if open_browser:
            url = self.get_url()
            threading.Thread(target=lambda: webbrowser.open(url), daemon=True).start()

        if background:
            self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            self._thread.start()
        else:
            try:
                self._server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                self.stop()

    def stop(self) -> None:
        """Gracefully shuts down the web server and closes network sockets."""
        if not self._is_running or not self._server:
            return

        self._is_running = False
        try:
            self._server.shutdown()
            self._server.server_close()
        except Exception as e:
            logger.debug("Error during server shutdown: %s", e)

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)


def start_server(
    host: str = "127.0.0.1",
    port: int = 8443,
    open_browser: bool = False,
    background: bool = True,
    csrf_protect: bool = True,
) -> WebDashboardServer:
    """Convenience factory function starting a GameCleaner web server."""
    server = WebDashboardServer(host=host, port=port, csrf_protect=csrf_protect)
    server.start(open_browser=open_browser, background=background)
    return server


def stop_server(server: WebDashboardServer) -> None:
    """Gracefully stops a running WebDashboardServer."""
    if server:
        server.stop()


def main() -> None:
    """CLI entrypoint for starting the GameCleaner Visual Cybersecurity Dashboard."""
    import argparse
    parser = argparse.ArgumentParser(description="GameCleaner Visual Cybersecurity Dashboard")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind to (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8443, help="Port to listen on (default: 8443)")
    parser.add_argument("--open", action="store_true", help="Automatically open browser")
    parser.add_argument("--no-csrf", action="store_true", help="Disable CSRF validation")
    args = parser.parse_args()

    server = WebDashboardServer(host=args.host, port=args.port, csrf_protect=not args.no_csrf)
    print(f"GameCleaner Web Dashboard running at: {server.get_url()}")
    server.start(open_browser=args.open, background=False)


if __name__ == "__main__":
    main()
