"""
Windows Shell Link (.lnk) Shortcut Scanner: Detects shortcut hijacking, hidden LOLBin execution, and external droppers.
"""
from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import re
import struct
from typing import List, Optional, Tuple

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
        re.compile(r"(?:curl|iwr|irm|bitsadmin|mshta|certutil|powershell|cmd).{1,60}https?://", re.IGNORECASE),
        re.compile(r"certutil(?:\.exe)?\s+-(?:urlcache|decode)", re.IGNORECASE),
        re.compile(r"(?:%TEMP%|%APPDATA%|\$env:TEMP|\$env:APPDATA)\\[a-zA-Z0-9_-]+\.exe", re.IGNORECASE),
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

    def _parse_ms_shllink(self, raw_bytes: bytes) -> Tuple[Optional[str], Optional[str]]:
        """Parses MS-SHLLINK binary structure to extract target path and command arguments."""
        if len(raw_bytes) < 76:
            return None, None
        try:
            header_size = struct.unpack("<I", raw_bytes[:4])[0]
            clsid = raw_bytes[4:20]
            if header_size != 0x4C or clsid != self.CLSID_SHELL_LINK:
                return None, None

            flags = struct.unpack("<I", raw_bytes[20:24])[0]
            offset = 76

            # HasLinkTargetIDList (0x01)
            if flags & 0x01:
                if offset + 2 > len(raw_bytes):
                    return None, None
                id_list_size = struct.unpack("<H", raw_bytes[offset:offset + 2])[0]
                offset += 2 + id_list_size

            # HasLinkInfo (0x02)
            target_path = None
            if flags & 0x02:
                if offset + 4 > len(raw_bytes):
                    return None, None
                link_info_size = struct.unpack("<I", raw_bytes[offset:offset + 4])[0]
                if offset + 20 <= len(raw_bytes):
                    link_info_header_size = struct.unpack("<I", raw_bytes[offset + 4:offset + 8])[0]
                    local_base_offset = struct.unpack("<I", raw_bytes[offset + 16:offset + 20])[0]
                    if offset + local_base_offset < len(raw_bytes):
                        raw_target = raw_bytes[offset + local_base_offset: offset + link_info_size].split(b"\x00")[0]
                        target_path = raw_target.decode("ascii", errors="ignore")
                    # If Unicode path present
                    if link_info_header_size >= 0x24 and offset + 28 <= len(raw_bytes):
                        local_base_offset_u = struct.unpack("<I", raw_bytes[offset + 28:offset + 32])[0]
                        if offset + local_base_offset_u < len(raw_bytes):
                            raw_u = raw_bytes[offset + local_base_offset_u: offset + link_info_size].split(b"\x00\x00")[0]
                            target_path = raw_u.decode("utf-16le", errors="ignore")
                offset += link_info_size

            is_unicode = bool(flags & 0x80)

            def _read_str(cur_off: int) -> Tuple[Optional[str], int]:
                if cur_off + 2 > len(raw_bytes):
                    return None, cur_off
                cch = struct.unpack("<H", raw_bytes[cur_off:cur_off + 2])[0]
                cur_off += 2
                if is_unicode:
                    byte_len = cch * 2
                    if cur_off + byte_len > len(raw_bytes):
                        return None, cur_off
                    val = raw_bytes[cur_off:cur_off + byte_len].decode("utf-16le", errors="ignore")
                    return val, cur_off + byte_len
                else:
                    if cur_off + cch > len(raw_bytes):
                        return None, cur_off
                    val = raw_bytes[cur_off:cur_off + cch].decode("latin-1", errors="ignore")
                    return val, cur_off + cch

            # Read StringData blocks in order:
            # 1. NAME_STRING (0x04)
            if flags & 0x04:
                _, offset = _read_str(offset)
            # 2. RELATIVE_PATH (0x08)
            rel_path = None
            if flags & 0x08:
                rel_path, offset = _read_str(offset)
            # 3. WORKING_DIR (0x10)
            if flags & 0x10:
                _, offset = _read_str(offset)
            # 4. COMMAND_LINE_ARGUMENTS (0x20)
            args = None
            if flags & 0x20:
                args, offset = _read_str(offset)

            final_target = target_path or rel_path
            return final_target, args
        except Exception:
            return None, None

    def scan_file(self, file_path: Path) -> LnkScanResult:
        file_path = Path(file_path).resolve()
        result = LnkScanResult(
            file_path=file_path,
            file_name=file_path.name,
        )

        try:
            raw_bytes = file_path.read_bytes()
        except Exception:
            return result

        # 1. Attempt standard MS-SHLLINK structural parsing
        target_path, arguments = self._parse_ms_shllink(raw_bytes)
        result.target_path = target_path
        result.arguments = arguments

        # 2. Extract ASCII and UTF-16 strings for fallback analysis & full text inspection
        ascii_strings = [s.decode("ascii", errors="ignore") for s in re.findall(rb"[\x20-\x7E]{4,512}", raw_bytes)]
        utf16_strings = [s.decode("utf-16le", errors="ignore") for s in re.findall(rb"(?:[\x20-\x7E]\x00){4,512}", raw_bytes)]
        all_strings = ascii_strings + utf16_strings

        # 3. If target_path or arguments missing (e.g. malformed/synthetic LNK), extract heuristically
        cmd_split_pattern = re.compile(
            r'^("?[a-zA-Z]:\\[^"\r\n]+?\.(?:exe|bat|cmd|vbs|ps1)"?|powershell(?:\.exe)?|cmd(?:\.exe)?|mshta(?:\.exe)?|cscript(?:\.exe)?|wscript(?:\.exe)?)\s+(.*)$',
            re.IGNORECASE,
        )
        for s in all_strings:
            m = cmd_split_pattern.match(s.strip())
            if m:
                if not result.target_path:
                    result.target_path = m.group(1).strip('"')
                if not result.arguments:
                    result.arguments = m.group(2).strip()
                break

        # If target_path was concatenated with arguments (e.g., in some malformed shortcuts)
        if result.target_path and not result.arguments:
            m = cmd_split_pattern.match(result.target_path.strip())
            if m:
                result.target_path = m.group(1).strip('"')
                result.arguments = m.group(2).strip()

        # If target_path is still not found, check strings for any executable path or suspicious target
        if not result.target_path:
            for s in all_strings:
                s_lower = s.lower()
                for susp in self.SUSPICIOUS_TARGETS:
                    if susp in s_lower:
                        result.target_path = s
                        break
                if result.target_path:
                    break

        # Check for suspicious targets (must be the actual target path or main launched executable)
        is_suspicious_target = False
        target_check = (result.target_path or "").lower()
        args_check = (result.arguments or "").lower()
        matched_susp_target = None
        for susp_target in self.SUSPICIOUS_TARGETS:
            if susp_target in target_check or (not target_check and susp_target in args_check.split()[:2]):
                is_suspicious_target = True
                matched_susp_target = susp_target
                break

        score = 0
        critical_count = 0

        if is_suspicious_target:
            result.findings.append(LnkFinding(
                category=ThreatCategory.NETWORK_C2.value,
                severity=ThreatSeverity.HIGH.value,
                name=f"Suspicious Target: {matched_susp_target}",
                details=f"Shortcut target executable is system utility '{result.target_path or matched_susp_target}'",
            ))
            score += 30

        # Check for suspicious argument strings (only in actual command line arguments)
        text_to_audit = result.arguments or ""
        for pattern in self.SUSPICIOUS_ARG_PATTERNS:
            match = pattern.search(text_to_audit)
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
