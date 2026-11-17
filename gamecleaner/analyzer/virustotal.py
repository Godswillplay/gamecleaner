"""
VirusTotal v3 hash lookup & threat classification client.
"""
from dataclasses import dataclass, field
import os
import re
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

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("VT_API_KEY")

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key and len(self.api_key.strip()) > 10)

    def lookup_hash(self, sha256_hash: str) -> VTAnalysisResult:
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
            if response.status_code == 404:
                return VTAnalysisResult(
                    queried=True,
                    found=False,
                    sha256=sha256_hash,
                    summary="Hash not found in VirusTotal database (New or unique binary)",
                )
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

            is_malware = malware_votes >= 3
            is_crack_only = (crack_votes > 0 and malware_votes < 2)

            if is_malware:
                summary = f"DETECTED MALWARE: {malicious}/{total} engines flagged. Identified malware families: {', '.join(set(families[:3]))}"
            elif is_crack_only:
                summary = f"LIKELY BENIGN CRACK: {malicious}/{total} engines flagged (predominantly HackTool/Crack/PUP heuristics)."
            elif malicious > 0:
                summary = f"{malicious}/{total} security vendors flagged this file."
            else:
                summary = f"CLEAN: 0/{total} detections on VirusTotal."

            return VTAnalysisResult(
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

        except Exception as e:
            return VTAnalysisResult(
                queried=True,
                found=False,
                sha256=sha256_hash,
                summary=f"VirusTotal query failed: {str(e)}",
            )
