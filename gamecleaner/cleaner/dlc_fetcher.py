"""
Steam Public Store DLC Auto-Fetcher: Automatically discovers all DLCs for an AppID and populates steam_settings/DLC.txt for Goldberg emulator.
"""
import configparser
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import ssl
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

    def _extract_from_text(self, content: str, results: List[DLCInfo], seen_ids: set):
        """Extracts DLC entries from raw text using regex when standard INI parsing fails."""
        # Find DLC sections
        pattern = re.compile(
            r"\[(?:dlc|dlcs|unlockdlc|steam_dlc|dlc_list|unlocked_dlc)\](.*?)(?=\n\s*\[|\Z)",
            re.IGNORECASE | re.DOTALL,
        )
        for match in pattern.finditer(content):
            section_body = match.group(1)
            for line in section_body.splitlines():
                line = line.split(";")[0].split("#")[0].strip()
                if not line:
                    continue
                # Support: DLC001 = 227101 = DLC Name, 227101 = DLC Name, or 227101
                m = re.search(r"(\d{3,10})\s*(?:=\s*([^;\r\n]+))?", line)
                if m:
                    dlc_id = m.group(1).strip()
                    dlc_name = (m.group(2) or "").strip().strip('"').strip("'")
                    if dlc_id not in seen_ids:
                        seen_ids.add(dlc_id)
                        results.append(DLCInfo(app_id=dlc_id, name=dlc_name or f"DLC {dlc_id}"))

    def parse_local_ini_dlcs(self, game_dir: Path) -> List[DLCInfo]:
        """Extracts DLC configurations from existing repack scene INI files in root and subdirectories."""
        results: List[DLCInfo] = []
        seen_ids = set()

        if not game_dir.exists():
            return results

        # Find all INI files in game root and subdirectories (excluding .gamecleaner)
        ini_candidates = []
        for root, _, files in os.walk(game_dir):
            if ".gamecleaner" in root:
                continue
            for file in files:
                if file.lower().endswith(".ini"):
                    ini_candidates.append(Path(root) / file)

        target_sections = ("dlc", "dlcs", "unlockdlc", "steam_dlc", "dlc_list", "unlocked_dlc")

        for ini_path in ini_candidates:
            try:
                content = ini_path.read_text(encoding="utf-8", errors="ignore")
                parsed_ok = False
                try:
                    parser = configparser.ConfigParser(allow_no_value=True, strict=False)
                    parser.read_string(content)
                    for section in parser.sections():
                        if section.lower() in target_sections:
                            parsed_ok = True
                            for key, val in parser.items(section):
                                key_str = str(key).strip().strip('"').strip("'")
                                val_str = str(val or "").strip().strip('"').strip("'").split(";")[0].split("#")[0].strip()

                                # Handle DLC001 = 227101 = DLC Name in val_str
                                m = re.search(r"(\d{3,10})\s*(?:=\s*([^;\r\n]+))?", f"{key_str}={val_str}")
                                if m:
                                    dlc_id = m.group(1).strip()
                                    dlc_name = (m.group(2) or "").strip().strip('"').strip("'")
                                    if dlc_id not in seen_ids:
                                        seen_ids.add(dlc_id)
                                        results.append(DLCInfo(app_id=dlc_id, name=dlc_name or f"DLC {dlc_id}"))
                except Exception:
                    parsed_ok = False

                # If standard configparser failed or found nothing, try regex fallback
                if not parsed_ok:
                    self._extract_from_text(content, results, seen_ids)
            except Exception:
                continue

        return results

    def fetch_dlc_list(self, app_id: str, fetch_names: bool = True, timeout: int = 5) -> List[DLCInfo]:
        """Queries the official public Steam store API to fetch all DLC IDs and names in a single fast query."""
        app_id_clean = str(app_id).strip()
        if not app_id_clean or not app_id_clean.isdigit():
            return []

        def _open_url(url: str):
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
            )
            try:
                ctx = ssl.create_default_context()
                return urllib.request.urlopen(req, timeout=timeout, context=ctx)
            except (ssl.SSLError, urllib.error.URLError):
                # Fallback to unverified SSL context if root certificates are missing
                unverified_ctx = ssl._create_unverified_context()
                return urllib.request.urlopen(req, timeout=timeout, context=unverified_ctx)

        # 1. Try single-query dlcforapp endpoint (fastest, returns all DLCs with names)
        try:
            with _open_url(f"{self.DLCFORAPP_URL}{app_id_clean}") as resp:
                raw_bytes = resp.read()
                if raw_bytes:
                    data = json.loads(raw_bytes.decode("utf-8", errors="ignore"))
                    if isinstance(data, dict) and data.get("status") == 1:
                        dlc_list = data.get("dlc", [])
                        results = []
                        seen_ids = set()
                        for item in dlc_list:
                            if not isinstance(item, dict):
                                continue
                            raw_id = item.get("id")
                            if raw_id is not None:
                                d_id = str(raw_id).strip()
                                if d_id.isdigit() and d_id not in seen_ids:
                                    seen_ids.add(d_id)
                                    d_name = str(item.get("name") or f"DLC {d_id}").strip()
                                    d_name = d_name.replace("\r", "").replace("\n", " ")
                                    results.append(DLCInfo(app_id=d_id, name=d_name))
                        if results:
                            return results
        except Exception:
            pass

        # 2. Fallback to appdetails endpoint
        try:
            with _open_url(f"{self.APPDETAILS_URL}{app_id_clean}") as resp:
                raw_bytes = resp.read()
                if raw_bytes:
                    data = json.loads(raw_bytes.decode("utf-8", errors="ignore"))
                    if isinstance(data, dict):
                        app_data = data.get(app_id_clean, {})
                        if isinstance(app_data, dict) and app_data.get("success"):
                            dlc_ids = app_data.get("data", {}).get("dlc", [])
                            results = []
                            seen_ids = set()
                            for d_id in dlc_ids:
                                s_id = str(d_id).strip()
                                if s_id.isdigit() and s_id not in seen_ids:
                                    seen_ids.add(s_id)
                                    results.append(DLCInfo(app_id=s_id, name=f"DLC {s_id}"))
                            return results
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
        if not dlcs and app_id and str(app_id).strip().isdigit():
            dlcs = self.fetch_dlc_list(str(app_id).strip())

        if not dlcs:
            # Fallback: create Goldberg unlock_all_dlc.txt so DLC content is unlocked offline
            try:
                out_p = Path(output_path).resolve()
                out_p.parent.mkdir(parents=True, exist_ok=True)
                unlock_file = out_p.parent / "unlock_all_dlc.txt"
                unlock_file.write_text("1", encoding="utf-8")
            except Exception:
                pass
            return False

        out_p = Path(output_path).resolve()
        out_p.parent.mkdir(parents=True, exist_ok=True)

        # Clear read-only if file already exists
        if out_p.exists():
            try:
                import stat
                os.chmod(out_p, stat.S_IWRITE | stat.S_IREAD)
            except Exception:
                pass

        # Deduplicate
        seen = set()
        deduped = []
        for d in dlcs:
            if d.app_id not in seen:
                seen.add(d.app_id)
                deduped.append(d)

        lines = [f"{d.app_id}={d.name}" for d in deduped]
        out_p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return True
