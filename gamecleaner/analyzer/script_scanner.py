"""
Script & Batch Dropper Scanner: Audits .bat, .cmd, .vbs, and .ps1 files for hidden malware and droppers.
"""
from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import re
from typing import Dict, List, Optional

from gamecleaner.analyzer.threat_rules import ThreatCategory, ThreatSeverity


@dataclass
class ScriptFinding:
    category: str
    severity: str
    name: str
    details: str
    line_number: Optional[int] = None


@dataclass
class ScriptScanResult:
    file_path: Path
    file_name: str
    file_size: int
    extension: str
    sha256: str = ""
    findings: List[ScriptFinding] = field(default_factory=list)
    threat_score: int = 0
    overall_severity: str = ThreatSeverity.CLEAN.value
    verdict: str = "Clean Script"
    recommended_action: str = "KEEP"  # KEEP or QUARANTINE


# Legitimate redistributable installers to exclude from Temp/AppData execution flags
REDIST_EXE_REGEX = re.compile(
    r"(?:dxsetup|dxwebsetup|vcredist[a-z0-9_\-\.]*|vc_redist[a-z0-9_\-\.]*|oalinst|dotNetFx[a-z0-9_\-\.]*)\.exe",
    re.IGNORECASE,
)

SCRIPT_THREAT_PATTERNS = [
    {
        "pattern": re.compile(r"powershell(?:\.exe)?\s+.*-[eE](?:nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}", re.IGNORECASE),
        "name": "Encoded Base64 PowerShell Execution",
        "category": ThreatCategory.NETWORK_C2.value,
        "severity": ThreatSeverity.CRITICAL.value,
        "score": 50,
    },
    {
        "pattern": re.compile(r"powershell(?:\.exe)?\s+.*-w(?:indowstyle)?\s+hidden", re.IGNORECASE),
        "name": "Hidden Window PowerShell Launch",
        "category": ThreatCategory.NETWORK_C2.value,
        "severity": ThreatSeverity.HIGH.value,
        "score": 30,
    },
    {
        "pattern": re.compile(r"certutil(?:\.exe)?\s+-(?:urlcache|decode)", re.IGNORECASE),
        "name": "Certutil LOLBin Payload Downloader",
        "category": ThreatCategory.NETWORK_C2.value,
        "severity": ThreatSeverity.CRITICAL.value,
        "score": 45,
    },
    {
        "pattern": re.compile(r"bitsadmin(?:\.exe)?\s+/transfer", re.IGNORECASE),
        "name": "Bitsadmin Background File Download",
        "category": ThreatCategory.NETWORK_C2.value,
        "severity": ThreatSeverity.HIGH.value,
        "score": 35,
    },
    {
        "pattern": re.compile(r"(?:Invoke-WebRequest|iwr\s+|Invoke-RestMethod|irm\s+|DownloadFile|DownloadString)\s+.*https?://|curl(?:\.exe)?\s+.*(?:-o|-O|--output)\s+", re.IGNORECASE),
        "name": "Scripted Web Payload Downloader",
        "category": ThreatCategory.NETWORK_C2.value,
        "severity": ThreatSeverity.HIGH.value,
        "score": 35,
    },
    {
        "pattern": re.compile(r"https?://(?:canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+", re.IGNORECASE),
        "name": "Discord Webhook Data Exfiltration",
        "category": ThreatCategory.INFOSTEALER.value,
        "severity": ThreatSeverity.CRITICAL.value,
        "score": 50,
    },
    {
        "pattern": re.compile(r"bot[0-9]{8,10}:[a-zA-Z0-9_-]{35}", re.IGNORECASE),
        "name": "Telegram Bot Token Exfiltration",
        "category": ThreatCategory.INFOSTEALER.value,
        "severity": ThreatSeverity.CRITICAL.value,
        "score": 50,
    },
    # Modern Infostealers (Lumma, Stealc, Vidar, Redline)
    {
        "pattern": re.compile(r"lummac2|lumma(?:\s+stealer|_c2)|/api/v1/user|gate\.php\?act=|\.lumma\b", re.IGNORECASE),
        "name": "Lumma Stealer C2 Signature",
        "category": ThreatCategory.INFOSTEALER.value,
        "severity": ThreatSeverity.CRITICAL.value,
        "score": 50,
    },
    {
        "pattern": re.compile(r"stealc(?:\s+stealer|/api/|_gate)|stealc_[a-z0-9]+", re.IGNORECASE),
        "name": "Stealc Stealer Signature",
        "category": ThreatCategory.INFOSTEALER.value,
        "severity": ThreatSeverity.CRITICAL.value,
        "score": 50,
    },
    {
        "pattern": re.compile(r"vidar(?:\s+stealer|_api)|redline(?:\.client|stealer)|raccoon\s+stealer|agenttesla", re.IGNORECASE),
        "name": "Vidar / Redline Infostealer Signature",
        "category": ThreatCategory.INFOSTEALER.value,
        "severity": ThreatSeverity.CRITICAL.value,
        "score": 50,
    },
    {
        "pattern": re.compile(r"vssadmin(?:\.exe)?\s+delete\s+shadows", re.IGNORECASE),
        "name": "Volume Shadow Copy Deletion (Ransomware)",
        "category": ThreatCategory.INJECTION.value,
        "severity": ThreatSeverity.CRITICAL.value,
        "score": 50,
    },
    {
        "pattern": re.compile(r"(?:%TEMP%|%APPDATA%|\$env:TEMP|\$env:APPDATA)\\[a-zA-Z0-9_-]+\.exe", re.IGNORECASE),
        "name": "Execution from Temp/AppData Directory",
        "category": ThreatCategory.NETWORK_C2.value,
        "severity": ThreatSeverity.HIGH.value,
        "score": 25,
    },
    # Cryptocurrency Mining Artifacts & Pools
    {
        "pattern": re.compile(
            r"stratum(?:\+tcp|\+ssl|2\+tcp)?://|nicehash\.com|minexmr\.com|supportxmr\.com|nanopool\.org|unmineable\.com|moneroocean\.stream",
            re.IGNORECASE,
        ),
        "name": "Mining Pool Protocol / Domain",
        "category": ThreatCategory.COINMINER.value,
        "severity": ThreatSeverity.CRITICAL.value,
        "score": 50,
    },
    {
        "pattern": re.compile(
            r"xmrig(?:\.exe)?|cryptonight|randomx|--donate-level|--algo=(?:cryptonight|randomx|kawpow)|nbminer|ethminer|phoenixminer",
            re.IGNORECASE,
        ),
        "name": "Cryptocurrency Mining Artifacts",
        "category": ThreatCategory.COINMINER.value,
        "severity": ThreatSeverity.CRITICAL.value,
        "score": 50,
    },
]


class ScriptScanner:
    """Scans batch, cmd, PowerShell, and VBS scripts for malicious behavior."""

    SUPPORTED_EXTENSIONS = {".bat", ".cmd", ".vbs", ".ps1"}

    def scan_file(self, file_path: Path) -> ScriptScanResult:
        file_path = Path(file_path).resolve()
        ext = file_path.suffix.lower()
        result = ScriptScanResult(
            file_path=file_path,
            file_name=file_path.name,
            file_size=file_path.stat().st_size,
            extension=ext,
        )

        try:
            raw_bytes = file_path.read_bytes()
            result.sha256 = hashlib.sha256(raw_bytes).hexdigest()
            text_content = raw_bytes.decode(errors="ignore")
        except Exception as e:
            result.findings.append(ScriptFinding(
                category=ThreatCategory.BENIGN.value,
                severity=ThreatSeverity.LOW.value,
                name="Read Error",
                details=str(e),
            ))
            return result

        lines = text_content.splitlines()
        score = 0
        critical_count = 0
        high_count = 0

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            # Skip empty lines or standard batch comments (case-insensitive REM)
            stripped_upper = stripped.upper()
            if not stripped or stripped.startswith("::") or stripped_upper.startswith("REM ") or stripped_upper == "REM" or stripped.startswith("#"):
                continue

            # De-obfuscate batch caret insertions (c^m^d) and quote splits (p""o""w""e""r)
            deobf_line = stripped.replace("^", "").replace('""', '')

            for rule in SCRIPT_THREAT_PATTERNS:
                if rule["pattern"].search(line) or rule["pattern"].search(deobf_line):
                    # Prevent false positives on legitimate DirectX/VCRedist installers executed from temp
                    if rule["name"] == "Execution from Temp/AppData Directory" and (REDIST_EXE_REGEX.search(line) or REDIST_EXE_REGEX.search(deobf_line)):
                        continue

                    result.findings.append(ScriptFinding(
                        category=rule["category"],
                        severity=rule["severity"],
                        name=rule["name"],
                        details=f"Line {idx}: {stripped[:80]}",
                        line_number=idx,
                    ))
                    score += rule["score"]
                    if rule["severity"] == ThreatSeverity.CRITICAL.value:
                        critical_count += 1
                    elif rule["severity"] == ThreatSeverity.HIGH.value:
                        high_count += 1

        result.threat_score = min(score, 100)

        if critical_count > 0:
            result.overall_severity = ThreatSeverity.CRITICAL.value
            result.verdict = "DANGEROUS: Malicious Script Dropper"
            result.recommended_action = "QUARANTINE"
        elif high_count > 0:
            result.overall_severity = ThreatSeverity.HIGH.value
            result.verdict = "HIGH RISK: Suspicious Script Execution"
            result.recommended_action = "QUARANTINE"
        elif score > 0:
            result.overall_severity = ThreatSeverity.MEDIUM.value
            result.verdict = "SUSPICIOUS: Unconventional Commands in Script"
            result.recommended_action = "KEEP"
        else:
            result.overall_severity = ThreatSeverity.CLEAN.value
            result.verdict = "Clean Script"
            result.recommended_action = "KEEP"

        return result
