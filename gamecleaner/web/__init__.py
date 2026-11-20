"""
GameCleaner WebUI & Visual Dashboard.
Provides a zero-dependency local HTTP server and dark-mode cybersecurity console.
"""

from gamecleaner.web.api import WebAPI
from gamecleaner.web.server import WebDashboardServer, start_server, stop_server

__all__ = [
    "WebAPI",
    "WebDashboardServer",
    "start_server",
    "stop_server",
]
