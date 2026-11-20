"""
Steamworks Interface & Version Extractor: Reverse-engineers required Steam interfaces for 100% Goldberg compatibility.
"""
from pathlib import Path
import re
from typing import Dict, List, Set


# Single unified pattern for fast ASCII interface string matching
UNIFIED_INTERFACE_REGEX_BYTES = re.compile(
    rb"(?:Steam[A-Za-z]+|STEAMCONTROLLER_INTERFACE_VERSION)[0-9]{3}"
)

# Unified pattern for UTF-16LE wide interface strings
UNIFIED_INTERFACE_WIDE_BYTES = re.compile(
    rb"(?:(?:S\x00t\x00e\x00a\x00m\x00[A-Za-z]\x00(?:[A-Za-z]\x00)*)|"
    rb"(?:S\x00T\x00E\x00A\x00M\x00C\x00O\x00N\x00T\x00R\x00O\x00L\x00L\x00E\x00R\x00_\x00I\x00N\x00T\x00E\x00R\x00F\x00A\x00C\x00E\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00))"
    rb"[0-9]\x00[0-9]\x00[0-9]\x00"
)

INTERFACE_PATTERNS_STR = [
    re.compile(r"Steam[A-Za-z]+[0-9]{3}"),
    re.compile(r"STEAMCONTROLLER_INTERFACE_VERSION[0-9]{3}"),
]


def deduplicate_highest_interfaces(interfaces: List[str]) -> List[str]:
    """
    Given a list of interface strings (e.g. ['SteamUser019', 'SteamUser021']),
    keeps only the highest version number for each interface family.
    """
    version_map: Dict[str, int] = {}
    interface_name_map: Dict[str, str] = {}

    pattern = re.compile(r"^(.*?)([0-9]{3})$")
    for iface in interfaces:
        m = pattern.match(iface)
        if m:
            prefix, ver_str = m.group(1), m.group(2)
            ver = int(ver_str)
            if prefix not in version_map or ver > version_map[prefix]:
                version_map[prefix] = ver
                interface_name_map[prefix] = f"{prefix}{ver_str}"
        else:
            interface_name_map[iface] = iface

    return sorted(list(interface_name_map.values()))


class InterfaceExtractor:
    """Extracts Steamworks interface versions directly from game executables and DLLs."""

    def extract_from_binary(self, binary_path: Path) -> List[str]:
        """Scans a binary for all referenced Steam interface version strings in ASCII and UTF-16LE."""
        binary_path = Path(binary_path)
        if not binary_path.exists() or not binary_path.is_file():
            return []

        try:
            content = binary_path.read_bytes()
        except Exception:
            return []

        found_interfaces: Set[str] = set()

        # 1. Fast unified ASCII interface extraction
        for m in UNIFIED_INTERFACE_REGEX_BYTES.finditer(content):
            try:
                found_interfaces.add(m.group(0).decode("ascii"))
            except Exception:
                continue

        # 2. Fast unified UTF-16LE wide interface extraction
        for m in UNIFIED_INTERFACE_WIDE_BYTES.finditer(content):
            try:
                found_interfaces.add(m.group(0).decode("utf-16le"))
            except Exception:
                continue

        # 3. Fallback scan on wide string chunks (for variable-spaced or unicode text)
        wide_matches = re.finditer(rb"(?:[\x20-\x7E]\x00){10,45}", content)
        for wm in wide_matches:
            try:
                decoded = wm.group(0).decode("utf-16le")
                for pattern in INTERFACE_PATTERNS_STR:
                    for m in pattern.findall(decoded):
                        found_interfaces.add(m)
            except Exception:
                continue

        return sorted(list(found_interfaces))

    def extract_from_directory(self, target_dir: Path) -> List[str]:
        """Scans all .exe and .dll files in a directory to build a complete steam_interfaces list."""
        all_interfaces: Set[str] = set()
        for p in target_dir.rglob("*"):
            if p.is_file() and p.suffix.lower() in (".exe", ".dll"):
                if ".gamecleaner" in str(p) or ".quarantine" in str(p):
                    continue
                interfaces = self.extract_from_binary(p)
                all_interfaces.update(interfaces)

        return sorted(list(all_interfaces))

    def generate_interfaces_file(self, target_dir: Path, output_file: Path) -> bool:
        """
        Generates a clean steam_interfaces.txt file for Goldberg emulator
        with all extracted interface versions.
        """
        interfaces = self.extract_from_directory(target_dir)
        if not interfaces:
            # Fallback to standard baseline interfaces if none found
            interfaces = [
                "SteamClient020",
                "SteamUser021",
                "SteamFriends017",
                "SteamUtils010",
                "SteamMatchmaking009",
                "SteamUserStats012",
                "SteamApps008",
                "SteamNetworking006",
                "SteamRemoteStorage014",
                "SteamScreenshots003",
                "SteamHTTP012",
                "SteamUGC016",
                "SteamInventory003",
            ]

        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text("\n".join(interfaces) + "\n", encoding="utf-8")
        return True
