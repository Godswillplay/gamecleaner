"""
String Cross-Reference and Artifact Analyzer: Extracts and categorizes strings across binary sections.
"""
from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Dict, List, Optional
import pefile


@dataclass
class StringEvidence:
    category: str  # NETWORK_C2, INFOSTEALER_TARGET, REGISTRY, ANTI_ANALYSIS, CRYPTO_WALLET
    value: str
    section: str
    offset: int
    is_wide: bool  # True if UTF-16


class StringCrossReferencer:
    """Extracts and contextualizes strings to discover stealth payloads and stealer targets."""

    CATEGORY_RULES = [
        ("NETWORK_C2", re.compile(r"https?://[a-zA-Z0-9_\-\.]+(?::[0-9]+)?/[^\s\"\'<>]*", re.IGNORECASE)),
        ("NETWORK_C2", re.compile(r"stratum\+(?:tcp|ssl)://[a-zA-Z0-9_\-\.]+", re.IGNORECASE)),
        ("INFOSTEALER_TARGET", re.compile(r"(?:Chrome|Brave-Browser|Edge|Firefox|Opera|Discord)\\(?:User Data|Local State|Login Data|Cookies)", re.IGNORECASE)),
        ("INFOSTEALER_TARGET", re.compile(r"\\Local Extension Settings\\[a-z]{32}", re.IGNORECASE)),
        ("CRYPTO_WALLET", re.compile(r"(?:MetaMask|Exodus|Electrum|Coinbase|Binance|Trust Wallet)", re.IGNORECASE)),
        ("REGISTRY", re.compile(r"Software\\Microsoft\\Windows\\CurrentVersion\\(?:Run|RunOnce|Internet Settings)", re.IGNORECASE)),
        ("ANTI_ANALYSIS", re.compile(r"(?:x64dbg|x32dbg|wireshark|fiddler|processhacker|regshot|vbox|vmware)", re.IGNORECASE)),
    ]

    def analyze_pe_strings(self, binary_path: Path, max_matches_per_cat: int = 25) -> List[StringEvidence]:
        binary_path = Path(binary_path)
        if not binary_path.exists():
            return []

        try:
            raw_data = binary_path.read_bytes()
        except Exception:
            return []

        # Parse sections with pefile to map offsets to section names
        sections = []
        try:
            pe = pefile.PE(data=raw_data, fast_load=True)
            for sec in pe.sections:
                sec_name = sec.Name.decode(errors="ignore").strip("\x00")
                sections.append((sec.PointerToRawData, sec.PointerToRawData + sec.SizeOfRawData, sec_name))
            pe.close()
        except Exception:
            pass

        def get_section_for_offset(offset: int) -> str:
            for start, end, name in sections:
                if start <= offset < end:
                    return name
            return "Overlay / Non-Section"

        evidence: List[StringEvidence] = []
        cat_counts: Dict[str, int] = {}

        # 1. ASCII strings
        ascii_matches = re.finditer(rb"[\x20-\x7E]{4,256}", raw_data)
        for m in ascii_matches:
            val = m.group(0).decode("ascii", errors="ignore")
            offset = m.start()
            for cat, rule in self.CATEGORY_RULES:
                if rule.search(val):
                    if cat_counts.get(cat, 0) < max_matches_per_cat:
                        evidence.append(StringEvidence(
                            category=cat,
                            value=val,
                            section=get_section_for_offset(offset),
                            offset=offset,
                            is_wide=False,
                        ))
                        cat_counts[cat] = cat_counts.get(cat, 0) + 1

        # 2. UTF-16 LE strings
        utf16_matches = re.finditer(rb"(?:[\x20-\x7E]\x00){4,128}", raw_data)
        for m in utf16_matches:
            val = m.group(0).decode("utf-16le", errors="ignore")
            offset = m.start()
            for cat, rule in self.CATEGORY_RULES:
                if rule.search(val):
                    if cat_counts.get(cat, 0) < max_matches_per_cat:
                        evidence.append(StringEvidence(
                            category=cat,
                            value=val,
                            section=get_section_for_offset(offset),
                            offset=offset,
                            is_wide=True,
                        ))
                        cat_counts[cat] = cat_counts.get(cat, 0) + 1

        return evidence
