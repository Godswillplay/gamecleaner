"""
VirusTotal v3 hash lookup & threat classification client with caching and rate limit handling.
"""
from dataclasses import asdict, dataclass, field
import json
import os
from pathlib import Path
import re
import time
from typing import Dict, List, Optional
import requests


@dataclass
class VTAnalysisResult:
    queried: bool
    found: bool
    sha256: str
    positives: int = 0
    total_engines: int = 0
    malicious_votes: int = 0
    suspicious_votes: int = 0
    community_score: int = 0
    is_malware: bool = False
    is_crack_only: bool = False
    detected_families: List[str] = field(default_factory=list)
    engine_verdicts: Dict[str, str] = field(default_factory=dict)
    summary: str = "Not queried"


class VirusTotalClient:
    """Queries VirusTotal API v3 by SHA256 hash without uploading binary data."""

    BASE_URL = "https://www.virustotal.com/api/v3/files/"

    def __init__(
        self,
        api_key: Optional[str] = None,
        cache_path: Optional[Path] = None,
        cache_enabled: bool = True,
    ):
        self.api_key = api_key or os.environ.get("VT_API_KEY")
        self.cache_enabled = cache_enabled
        if cache_path is not None:
            self.cache_path = Path(cache_path)
        else:
            self.cache_path = Path.home() / ".gamecleaner" / "vt_cache.json"
        self._cache: Dict[str, dict] = self._load_cache()

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key and len(self.api_key.strip()) > 10)

    def _load_cache(self) -> Dict[str, dict]:
        if not self.cache_enabled:
            return {}
        try:
            if self.cache_path.exists():
                with open(self.cache_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        return data
        except Exception:
            pass
        return {}

    def _save_cache(self):
        if not self.cache_enabled:
            return
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            temp_path = self.cache_path.with_suffix(".tmp")
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(self._cache, f, indent=2)
            temp_path.replace(self.cache_path)
        except Exception:
            pass

    def lookup_hash(self, sha256_hash: str) -> VTAnalysisResult:
        sha256_hash = sha256_hash.strip().lower()

        # Check local cache first to avoid redundant API queries and conserve rate limits
        if self.cache_enabled and sha256_hash in self._cache:
            try:
                cached_data = dict(self._cache[sha256_hash])
                cached_at = cached_data.pop("cached_at", 0)
                # If cached entry was 'Not Found' (404), expire after 24 hours (86400s)
                is_expired_404 = (not cached_data.get("found", True)) and (time.time() - cached_at > 86400)
                if not is_expired_404:
                    return VTAnalysisResult(**cached_data)
            except Exception:
                pass

        if not self.is_configured:
            return VTAnalysisResult(
                queried=False,
                found=False,
                sha256=sha256_hash,
                summary="VirusTotal API key not configured (set VT_API_KEY env var)",
            )

        headers = {"x-apikey": self.api_key}
        url = f"{self.BASE_URL}{sha256_hash}"

        try:
            response = requests.get(url, headers=headers, timeout=10)

            # Handle Rate Limiting (HTTP 429)
            if response.status_code == 429:
                retry_after = 0
                try:
                    retry_after = int(response.headers.get("Retry-After", 0))
                except (ValueError, TypeError):
                    pass

                # If short backoff requested, attempt one retry
                if 0 < retry_after <= 5:
                    time.sleep(retry_after)
                    response = requests.get(url, headers=headers, timeout=10)

                if response.status_code == 429:
                    return VTAnalysisResult(
                        queried=True,
                        found=False,
                        sha256=sha256_hash,
                        summary="VirusTotal API Rate Limit Exceeded (HTTP 429: Public API quota limit reached).",
                    )

            if response.status_code == 404:
                result = VTAnalysisResult(
                    queried=True,
                    found=False,
                    sha256=sha256_hash,
                    summary="Hash not found in VirusTotal database (New or unique binary)",
                )
                if self.cache_enabled:
                    entry = asdict(result)
                    entry["cached_at"] = time.time()
                    self._cache[sha256_hash] = entry
                    self._save_cache()
                return result
            elif response.status_code != 200:
                return VTAnalysisResult(
                    queried=True,
                    found=False,
                    sha256=sha256_hash,
                    summary=f"VirusTotal API HTTP {response.status_code}",
                )

            data = response.json().get("data", {})
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            results = attributes.get("last_analysis_results", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())

            crack_keywords = {"crack", "hacktool", "riskware", "keygen", "patcher", "emulator", "pup", "pua", "gamehack"}
            malware_keywords = {"stealer", "trojan", "lumma", "redline", "vidar", "miner", "coinminer", "ransom", "spyware", "backdoor", "dropper"}

            families = []
            crack_votes = 0
            malware_votes = 0
            engine_map = {}

            for engine, res in results.items():
                category = res.get("category")
                result_str = (res.get("result") or "").lower()
                if category in ("malicious", "suspicious") and result_str:
                    engine_map[engine] = result_str
                    has_malware_kw = any(kw in result_str for kw in malware_keywords)
                    has_crack_kw = any(kw in result_str for kw in crack_keywords)

                    if has_malware_kw:
                        malware_votes += 1
                        families.append(result_str)
                    elif has_crack_kw:
                        crack_votes += 1

            # Robust classification: detect malware from specific family names OR high detection ratios
            is_crack_only = (crack_votes > 0 and malware_votes == 0 and (malicious <= crack_votes or malicious <= 3))
            is_malware = (
                malware_votes >= 3
                or (malicious >= 5 and not is_crack_only)
                or (total >= 15 and (malicious / total) >= 0.15 and not is_crack_only)
            )

            if is_malware:
                summary = f"DETECTED MALWARE: {malicious}/{total} engines flagged. Identified malware families: {', '.join(set(families[:3]))}"
            elif is_crack_only:
                summary = f"LIKELY BENIGN CRACK: {malicious}/{total} engines flagged (predominantly HackTool/Crack/PUP heuristics)."
            elif malicious > 0:
                summary = f"{malicious}/{total} security vendors flagged this file."
            else:
                summary = f"CLEAN: 0/{total} detections on VirusTotal."

            vt_result = VTAnalysisResult(
                queried=True,
                found=True,
                sha256=sha256_hash,
                positives=malicious,
                total_engines=total,
                malicious_votes=malicious,
                suspicious_votes=suspicious,
                is_malware=is_malware,
                is_crack_only=is_crack_only,
                detected_families=list(set(families)),
                engine_verdicts=engine_map,
                summary=summary,
            )

            # Cache the successful result
            if self.cache_enabled:
                self._cache[sha256_hash] = asdict(vt_result)
                self._save_cache()

            return vt_result

        except Exception as e:
            return VTAnalysisResult(
                queried=True,
                found=False,
                sha256=sha256_hash,
                summary=f"VirusTotal query failed: {str(e)}",
            )
