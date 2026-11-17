"""
Static PE (Portable Executable) binary scanner and entropy analyzer.
"""
from dataclasses import dataclass, field
import hashlib
import math
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import pefile

from gamecleaner.analyzer.threat_rules import (
    SENSITIVE_APIS,
    STANDARD_STEAM_EXPORTS,
    SUSPICIOUS_STRING_PATTERNS,
    ThreatCategory,
    ThreatSeverity,
)


@dataclass
class SectionInfo:
    name: str
    virtual_size: int
    raw_size: int
    entropy: float
    is_executable: bool
    is_suspicious_entropy: bool


@dataclass
class ThreatFinding:
    category: str
    severity: str
    name: str
    details: str


@dataclass
class PEScanResult:
    file_path: Path
    file_name: str
    file_size: int
    is_pe: bool
    architecture: str = "Unknown"  # x86 / x64
    md5: str = ""
    sha256: str = ""
    is_signed: bool = False
    is_packed: bool = False
    packer_type: Optional[str] = None
    max_entropy: float = 0.0
    sections: List[SectionInfo] = field(default_factory=list)
    imports: Dict[str, List[str]] = field(default_factory=dict)
    exports: List[str] = field(default_factory=list)
    is_steam_wrapper: bool = False
    findings: List[ThreatFinding] = field(default_factory=list)
    threat_score: int = 0  # 0 to 100
    overall_severity: str = ThreatSeverity.CLEAN.value
    verdict: str = "Clean"
    recommended_action: str = "KEEP"  # KEEP, REPLACE_WITH_CLEAN_EMU, FIREWALL_BLOCK, QUARANTINE


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte stream (0.0 to 8.0)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    occurrences = [0] * 256
    for byte in data:
        occurrences[byte] += 1
    for count in occurrences:
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def get_file_hashes(file_path: Path) -> tuple[str, str]:
    """Compute MD5 and SHA256 hashes of a file."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            md5.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()


class PEScanner:
    """Static inspection and heuristic analysis for Windows executables and DLLs."""

    def __init__(self, high_entropy_threshold: float = 7.1):
        self.high_entropy_threshold = high_entropy_threshold

    def scan_file(self, file_path: Path) -> PEScanResult:
        file_path = Path(file_path)
        if not file_path.is_file():
            raise FileNotFoundError(f"File not found: {file_path}")

        file_size = file_path.stat().st_size
        result = PEScanResult(
            file_path=file_path,
            file_name=file_path.name,
            file_size=file_size,
            is_pe=False,
        )

        # Quick check for PE magic (MZ header)
        try:
            with open(file_path, "rb") as f:
                header = f.read(2)
                if header != b"MZ":
                    return result
        except Exception as e:
            result.findings.append(ThreatFinding(
                category=ThreatCategory.BENIGN.value,
                severity=ThreatSeverity.LOW.value,
                name="Read Error",
                details=str(e),
            ))
            return result

        # Compute file hashes
        try:
            result.md5, result.sha256 = get_file_hashes(file_path)
        except Exception:
            pass

        # Parse PE
        try:
            pe = pefile.PE(str(file_path), fast_load=False)
            result.is_pe = True
        except pefile.PEFormatError:
            # File has MZ header but non-standard/corrupt PE structure; still scan strings
            self._scan_strings(file_path, result)
            if not result.findings:
                result.findings.append(ThreatFinding(
                    category=ThreatCategory.PACKED_OBFUSCATED.value,
                    severity=ThreatSeverity.MEDIUM.value,
                    name="Non-Standard PE Header",
                    details="Header is malformed or custom packed",
                ))
            self._evaluate_threat(result)
            return result
        except Exception as e:
            result.findings.append(ThreatFinding(
                category=ThreatCategory.BENIGN.value,
                severity=ThreatSeverity.LOW.value,
                name="Corrupt PE Header",
                details=str(e),
            ))
            self._scan_strings(file_path, result)
            self._evaluate_threat(result)
            return result

        try:
            # Architecture
            if pe.FILE_HEADER.Machine == 0x8664:
                result.architecture = "x64"
            elif pe.FILE_HEADER.Machine == 0x014C:
                result.architecture = "x86"
            elif pe.FILE_HEADER.Machine == 0xAA64:
                result.architecture = "ARM64"

            # Check digital signature directory
            security_dir = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
            if (
                len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > security_dir
                and pe.OPTIONAL_HEADER.DATA_DIRECTORY[security_dir].VirtualAddress != 0
                and pe.OPTIONAL_HEADER.DATA_DIRECTORY[security_dir].Size > 0
            ):
                result.is_signed = True

            # Sections and Entropy
            self._analyze_sections(pe, result)

            # Imports and Sensitive APIs
            self._analyze_imports(pe, result)

            # Exports and Steam wrapper detection
            self._analyze_exports(pe, result)

            # Scan raw content for suspicious regex patterns
            self._scan_strings(file_path, result)

            # Synthesize overall threat scoring and action recommendation
            self._evaluate_threat(result)

        finally:
            pe.close()

        return result

    def _analyze_sections(self, pe: pefile.PE, result: PEScanResult):
        known_packers = {
            "UPX0": "UPX",
            "UPX1": "UPX",
            ".vmp": "VMProtect",
            ".vmp0": "VMProtect",
            ".vmp1": "VMProtect",
            ".themida": "Themida",
            ".enigma": "Enigma Protector",
            ".aspack": "ASPack",
            ".petite": "Petite",
        }

        for sec in pe.sections:
            sec_name = sec.Name.decode(errors="ignore").strip("\x00")
            entropy = sec.get_entropy()
            is_exec = bool(sec.Characteristics & 0x20000000)
            is_suspicious = (entropy >= self.high_entropy_threshold and sec.SizeOfRawData > 4096)

            if entropy > result.max_entropy:
                result.max_entropy = entropy

            # Packer signature by section name
            for tag, packer_name in known_packers.items():
                if tag.lower() in sec_name.lower():
                    result.is_packed = True
                    result.packer_type = packer_name

            result.sections.append(SectionInfo(
                name=sec_name,
                virtual_size=sec.Misc_VirtualSize,
                raw_size=sec.SizeOfRawData,
                entropy=round(entropy, 3),
                is_executable=is_exec,
                is_suspicious_entropy=is_suspicious,
            ))

        if result.max_entropy > 7.3 and not result.is_signed:
            result.is_packed = True
            if not result.packer_type:
                result.packer_type = "Generic High-Entropy Crypter/Packer"
            result.findings.append(ThreatFinding(
                category=ThreatCategory.PACKED_OBFUSCATED.value,
                severity=ThreatSeverity.MEDIUM.value,
                name="Packed or Encrypted Executable",
                details=f"Detected maximum section entropy of {result.max_entropy} ({result.packer_type})",
            ))

    def _analyze_imports(self, pe: pefile.PE, result: PEScanResult):
        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode(errors="ignore").lower()
            imports_list = []
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode(errors="ignore")
                    imports_list.append(func_name)
                    # Match against sensitive APIs
                    if func_name in SENSITIVE_APIS:
                        rule = SENSITIVE_APIS[func_name]
                        result.findings.append(ThreatFinding(
                            category=rule["category"],
                            severity=rule["severity"],
                            name=f"Import: {func_name}",
                            details=f"From {dll_name}: {rule['description']}",
                        ))
            result.imports[dll_name] = imports_list

    def _analyze_exports(self, pe: pefile.PE, result: PEScanResult):
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    result.exports.append(exp.name.decode(errors="ignore"))

        # Check if it acts as a Steamworks wrapper
        file_lower = result.file_name.lower()
        if "steam_api" in file_lower or any(e in STANDARD_STEAM_EXPORTS for e in result.exports):
            result.is_steam_wrapper = True
            matched_steam = sum(1 for e in result.exports if e in STANDARD_STEAM_EXPORTS)
            if matched_steam >= 3:
                result.findings.append(ThreatFinding(
                    category=ThreatCategory.HACKTOOL_CRACK.value,
                    severity=ThreatSeverity.LOW.value,
                    name="Steamworks API Wrapper Hook",
                    details=f"Exports {matched_steam} standard Steam API functions (Crack/Emulator hook)",
                ))

    def _scan_strings(self, file_path: Path, result: PEScanResult):
        try:
            with open(file_path, "rb") as f:
                # Read up to 25MB for string inspection to maintain performance
                content = f.read(25 * 1024 * 1024)

            for item in SUSPICIOUS_STRING_PATTERNS:
                matches = item["pattern"].findall(content)
                if matches:
                    sample = matches[0].decode(errors="ignore")[:60]
                    result.findings.append(ThreatFinding(
                        category=item["category"],
                        severity=item["severity"],
                        name=f"Pattern: {item['name']}",
                        details=f"Detected payload signature: '{sample}'",
                    ))
        except Exception:
            pass

    def _evaluate_threat(self, result: PEScanResult):
        score = 0
        critical_count = 0
        high_count = 0
        medium_count = 0
        has_infostealer = False
        has_coinminer = False

        for f in result.findings:
            if f.severity == ThreatSeverity.CRITICAL.value:
                score += 45
                critical_count += 1
                if f.category == ThreatCategory.INFOSTEALER.value:
                    has_infostealer = True
                elif f.category == ThreatCategory.COINMINER.value:
                    has_coinminer = True
            elif f.severity == ThreatSeverity.HIGH.value:
                score += 25
                high_count += 1
            elif f.severity == ThreatSeverity.MEDIUM.value:
                score += 10
                medium_count += 1
            elif f.severity == ThreatSeverity.LOW.value:
                score += 2

        # Trust discount for validly signed binaries (prevents flagging legitimate OS / signed game engines)
        if result.is_signed and critical_count == 0:
            score = max(0, score - 50)
            high_count = 0
            medium_count = 0

        result.threat_score = min(score, 100)

        # Categorize overall severity and verdict
        if has_infostealer:
            result.overall_severity = ThreatSeverity.CRITICAL.value
            result.verdict = "DANGEROUS: Credential / Infostealer Trojan"
            result.recommended_action = "QUARANTINE"
        elif has_coinminer:
            result.overall_severity = ThreatSeverity.CRITICAL.value
            result.verdict = "DANGEROUS: Stealth Cryptocurrency Miner"
            result.recommended_action = "QUARANTINE"
        elif critical_count > 0:
            result.overall_severity = ThreatSeverity.CRITICAL.value
            result.verdict = "CRITICAL: Hostile Payload / Dropper"
            result.recommended_action = "QUARANTINE"
        elif high_count > 0:
            result.overall_severity = ThreatSeverity.HIGH.value
            result.verdict = "HIGH RISK: Suspicious Injection / Downloader"
            result.recommended_action = "QUARANTINE"
        elif result.is_steam_wrapper and not result.is_signed:
            result.overall_severity = ThreatSeverity.MEDIUM.value
            result.verdict = "SUSPICIOUS: Untrusted DRM Emulator Hook"
            result.recommended_action = "REPLACE_WITH_CLEAN_EMU"
        elif result.is_packed and not result.is_signed:
            result.overall_severity = ThreatSeverity.MEDIUM.value
            result.verdict = "SUSPICIOUS: Obfuscated / Packed Binary"
            result.recommended_action = "FIREWALL_BLOCK"
        elif medium_count > 0:
            result.overall_severity = ThreatSeverity.LOW.value
            result.verdict = "LOW RISK: Standard Game Hooks / Network APIs"
            result.recommended_action = "FIREWALL_BLOCK"
        else:
            result.overall_severity = ThreatSeverity.CLEAN.value
            result.verdict = "CLEAN: Standard Game File"
            result.recommended_action = "KEEP"
