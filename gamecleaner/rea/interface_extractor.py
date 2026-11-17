"""
Steamworks Interface & Version Extractor: Reverse-engineers required Steam interfaces for 100% Goldberg compatibility.
"""
from pathlib import Path
import re
from typing import Dict, List, Set


# Common Steamworks interface prefixes
INTERFACE_PATTERNS = [
    re.compile(rb"SteamClient[0-9]{3}"),
    re.compile(rb"SteamUser[0-9]{3}"),
    re.compile(rb"SteamFriends[0-9]{3}"),
    re.compile(rb"SteamUtils[0-9]{3}"),
    re.compile(rb"SteamMatchmaking[0-9]{3}"),
    re.compile(rb"SteamMatchmakingServers[0-9]{3}"),
    re.compile(rb"SteamUserStats[0-9]{3}"),
    re.compile(rb"SteamApps[0-9]{3}"),
    re.compile(rb"SteamNetworking[0-9]{3}"),
    re.compile(rb"SteamRemoteStorage[0-9]{3}"),
    re.compile(rb"SteamScreenshots[0-9]{3}"),
    re.compile(rb"SteamHTTP[0-9]{3}"),
    re.compile(rb"SteamController[0-9]{3}"),
    re.compile(rb"STEAMCONTROLLER_INTERFACE_VERSION[0-9]{3}"),
    re.compile(rb"SteamUGC[0-9]{3}"),
    re.compile(rb"SteamAppList[0-9]{3}"),
    re.compile(rb"SteamMusic[0-9]{3}"),
    re.compile(rb"SteamMusicRemote[0-9]{3}"),
    re.compile(rb"SteamHTMLSurface[0-9]{3}"),
    re.compile(rb"SteamInventory[0-9]{3}"),
    re.compile(rb"SteamVideo[0-9]{3}"),
    re.compile(rb"SteamParentalSettings[0-9]{3}"),
    re.compile(rb"SteamInput[0-9]{3}"),
    re.compile(rb"SteamNetworkingSockets[0-9]{3}"),
    re.compile(rb"SteamNetworkingUtils[0-9]{3}"),
]


class InterfaceExtractor:
    """Extracts Steamworks interface versions directly from game executables and DLLs."""

    def extract_from_binary(self, binary_path: Path) -> List[str]:
        """Scans a binary for all referenced Steam interface version strings."""
        binary_path = Path(binary_path)
        if not binary_path.exists():
            return []

        try:
            content = binary_path.read_bytes()
        except Exception:
            return []

        found_interfaces: Set[str] = set()

        for pattern in INTERFACE_PATTERNS:
            matches = pattern.findall(content)
            for m in matches:
                try:
                    found_interfaces.add(m.decode("ascii"))
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
