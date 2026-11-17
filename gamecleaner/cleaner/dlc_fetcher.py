"""
Steam Public Store DLC Auto-Fetcher: Automatically discovers all DLCs for an AppID and populates steam_settings/DLC.txt for Goldberg emulator.
"""
import configparser
from dataclasses import dataclass
import json
from pathlib import Path
from typing import Dict, List, Optional
import urllib.request


@dataclass
class DLCInfo:
    app_id: str
    name: str


class SteamDLCFetcher:
    """Discovers and downloads public DLC lists from local repack INIs or the official Steam Store API."""

    DLCFORAPP_URL = "https://store.steampowered.com/api/dlcforapp/?appid="
    APPDETAILS_URL = "https://store.steampowered.com/api/appdetails?appids="

    def parse_local_ini_dlcs(self, game_dir: Path) -> List[DLCInfo]:
        """Extracts DLC configurations from existing repack scene INI files."""
        results: List[DLCInfo] = []
        seen_ids = set()

        for ini_path in game_dir.glob("*.ini"):
            try:
                content = ini_path.read_text(encoding="utf-8", errors="ignore")
                parser = configparser.ConfigParser(allow_no_value=True, strict=False)
                parser.read_string(content)
                for section in parser.sections():
                    if section.lower() in ("dlc", "dlcs", "unlockdlc", "steam_dlc"):
                        for key, val in parser.items(section):
                            if key.isdigit() and key not in seen_ids:
                                seen_ids.add(key)
                                results.append(DLCInfo(app_id=key, name=val or f"DLC {key}"))
            except Exception:
                continue

        return results

    def fetch_dlc_list(self, app_id: str, fetch_names: bool = True, timeout: int = 5) -> List[DLCInfo]:
        """Queries the official public Steam store API to fetch all DLC IDs and names in a single fast query."""
        if not app_id or not app_id.isdigit():
            return []

        # 1. Try single-query dlcforapp endpoint (fastest, returns all DLCs with names)
        try:
            req = urllib.request.Request(
                f"{self.DLCFORAPP_URL}{app_id}",
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if data.get("status") == 1:
                    dlc_list = data.get("dlc", [])
                    results = []
                    for item in dlc_list:
                        d_id = str(item.get("id"))
                        d_name = item.get("name", f"DLC {d_id}")
                        results.append(DLCInfo(app_id=d_id, name=d_name))
                    if results:
                        return results
        except Exception:
            pass

        # 2. Fallback to appdetails endpoint
        try:
            req = urllib.request.Request(
                f"{self.APPDETAILS_URL}{app_id}",
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8")).get(app_id, {})
                if data.get("success"):
                    dlc_ids = data.get("data", {}).get("dlc", [])
                    return [DLCInfo(app_id=str(d_id), name=f"DLC {d_id}") for d_id in dlc_ids]
        except Exception:
            pass

        return []

    def generate_dlc_txt(self, app_id: str, output_path: Path, game_dir: Optional[Path] = None) -> bool:
        """Writes steam_settings/DLC.txt with all discovered DLCs (from local INI or online API)."""
        dlcs: List[DLCInfo] = []

        # First check local scene INI configs
        if game_dir and Path(game_dir).exists():
            dlcs = self.parse_local_ini_dlcs(Path(game_dir))

        # If none found locally, fetch from public Steam API
        if not dlcs and app_id and app_id.isdigit():
            dlcs = self.fetch_dlc_list(app_id)

        if not dlcs:
            return False

        output_path.parent.mkdir(parents=True, exist_ok=True)
        lines = [f"{d.app_id}={d.name}" for d in dlcs]
        output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return True
