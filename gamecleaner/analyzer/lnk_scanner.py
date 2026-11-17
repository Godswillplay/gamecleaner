"""
Windows Shell Link (.lnk) Shortcut Scanner: Detects shortcut hijacking, hidden LOLBin execution, and external droppers.
"""
from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import re
import struct
from typing import List, Optional

from gamecleaner.analyzer.threat_rules import ThreatCategory, ThreatSeverity


@dataclass
class LnkFinding:
    category: str
    severity: str
    name: str
    details: str


@dataclass
class LnkScanResult:
    file_path: Path
    file_name: str
    extension: str = ".lnk"
    target_path: Optional[str] = None
    arguments: Optional[str] = None
    findings: List[LnkFinding] = field(default_factory=list)
    threat_score: int = 0
    overall_severity: str = ThreatSeverity.CLEAN.value
    verdict: str = "Clean Shortcut"
    recommended_action: str = "KEEP"  # KEEP or QUARANTINE


class LnkScanner:
    """Parses and audits Windows .lnk shortcut files for malicious commands and persistence."""

    CLSID_SHELL_LINK = b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"

    SUSPICIOUS_TARGETS = [
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "certutil.exe",
        "bitsadmin.exe",
    ]

    SUSPICIOUS_ARG_PATTERNS = [
        re.compile(r"-[eE](?:nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{15,}", re.IGNORECASE),
        re.compile(r"-w(?:indowstyle)?\s+hidden", re.IGNORECASE),
        re.compile(r"https?://[a-zA-Z0-9_\-\.]+", re.IGNORECASE),
        re.compile(r"certutil(?:\.exe)?\s+-(?:urlcache|decode)", re.IGNORECASE),
        re.compile(r"(?:%TEMP%|%APPDATA%|\$env:TEMP|\$env:APPDATA)", re.IGNORECASE),
        re.compile(r"curl\s+.*-o", re.IGNORECASE),
    ]

    def is_lnk_file(self, file_path: Path) -> bool:
        if file_path.suffix.lower() != ".lnk" or file_path.stat().st_size < 76:
            return False
        try:
            with open(file_path, "rb") as f:
                header_size = struct.unpack("<I", f.read(4))[0]
                clsid = f.read(16)
                return header_size == 0x4C and clsid == self.CLSID_SHELL_LINK
        except Exception:
            return False

    def scan_file(self, file_path: Path) -> LnkScanResult:
        file_path = Path(file_path).resolve()
        result = LnkScanResult(
            file_path=file_path,
            file_name=file_path.name,
        )

        try:
            raw_bytes = file_path.read_bytes()
        except Exception as e:
            return result

        # Extract ASCII and UTF-16 strings to find target path and arguments
        ascii_strings = [s.decode("ascii", errors="ignore") for s in re.findall(rb"[\x20-\x7E]{4,512}", raw_bytes)]
        utf16_strings = [s.decode("utf-16le", errors="ignore") for s in re.findall(rb"(?:[\x20-\x7E]\x00){4,512}", raw_bytes)]
        all_strings = ascii_strings + utf16_strings

        # Identify possible target executable
        for s in all_strings:
            s_lower = s.lower()
            for susp_target in self.SUSPICIOUS_TARGETS:
                if susp_target in s_lower:
                    result.target_path = s
                    result.findings.append(LnkFinding(
                        category=ThreatCategory.NETWORK_C2.value,
                        severity=ThreatSeverity.HIGH.value,
                        name=f"Suspicious Target: {susp_target}",
                        details=f"Shortcut points to system binary '{s}' rather than game executable",
                    ))
                    break

        # Check for suspicious argument strings
        full_text = " ".join(all_strings)
        score = 0
        critical_count = 0

        for pattern in self.SUSPICIOUS_ARG_PATTERNS:
            match = pattern.search(full_text)
            if match:
                sample = match.group(0)[:60]
                result.findings.append(LnkFinding(
                    category=ThreatCategory.NETWORK_C2.value,
                    severity=ThreatSeverity.CRITICAL.value,
                    name="Hostile Command Arguments in Shortcut",
                    details=f"Shortcut contains payload arguments: '{sample}'",
                ))
                score += 50
                critical_count += 1

        if result.target_path and not result.arguments:
            score += 30

        result.threat_score = min(score, 100)

        if critical_count > 0:
            result.overall_severity = ThreatSeverity.CRITICAL.value
            result.verdict = "DANGEROUS: Malicious / Hijacked LNK Shortcut"
            result.recommended_action = "QUARANTINE"
        elif result.threat_score >= 30:
            result.overall_severity = ThreatSeverity.HIGH.value
            result.verdict = "SUSPICIOUS: Shortcut Targets System LOLBin"
            result.recommended_action = "QUARANTINE"
        else:
            result.overall_severity = ThreatSeverity.CLEAN.value
            result.verdict = "Clean Shortcut"
            result.recommended_action = "KEEP"

        return result
