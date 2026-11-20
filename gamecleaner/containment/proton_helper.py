"""
GameCleaner Proton & Steam Deck Containment Helper.
Generates robust Linux / Steam Deck Proton startup scripts (run_proton.sh)
with Wine DLL overrides (WINEDLLOVERRIDES) and network isolation namespaces (unshare -n / firejail).
"""

from dataclasses import dataclass
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
from typing import List, Optional, Set, Tuple, Union


@dataclass
class ProtonScriptResult:
    """Result metadata for generated Proton containment scripts."""
    script_path: Path
    overrides: str
    executable_name: str
    network_isolation_supported: bool
    setup_script_path: Optional[Path] = None
    appid: Optional[str] = None
    relative_exe_path: Optional[str] = None


def is_network_isolation_supported() -> bool:
    """
    Checks if the host system supports network namespace isolation (unshare -n)
    or firejail sandbox isolation. On Windows hosts, returns False.
    """
    if sys.platform != "linux":
        return False

    # Check unshare -n
    unshare_path = shutil.which("unshare")
    if unshare_path:
        try:
            res = subprocess.run(
                [unshare_path, "-n", "true"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=3,
            )
            if res.returncode == 0:
                return True
        except Exception:
            pass

    # Check firejail
    firejail_path = shutil.which("firejail")
    if firejail_path:
        try:
            res = subprocess.run(
                [firejail_path, "--version"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=3,
            )
            if res.returncode == 0:
                return True
        except Exception:
            pass

    return False


def write_posix_script(path: Path, content: str) -> None:
    """
    Writes a POSIX shell script ensuring strict Unix '\\n' (LF) line endings,
    even when running on Windows, and attempts to set executable permissions (0o755).
    """
    # Normalize any CRLF or CR line endings strictly to LF
    content_lf = content.replace("\r\n", "\n").replace("\r", "\n")
    if not content_lf.endswith("\n"):
        content_lf += "\n"

    path = Path(path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)

    # Force newline='\n' to prevent Windows runtime from converting \n to \r\n
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(content_lf)

    try:
        current_mode = os.stat(path).st_mode
        os.chmod(path, current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except Exception:
        pass


class ProtonHelper:
    """
    Manages Steam Deck and Linux Proton runtime containment.
    Discovers game binaries, Goldberg emulators, and AppIDs, then generates
    air-gapped POSIX launch scripts with Wine DLL overrides.
    """

    EXCLUDED_EXE_KEYWORDS = {
        "unins", "crash", "dxsetup", "vcredist", "dotnet",
        "setup", "redist", "prereq", "touchup", "installer",
        "helper", "update", "patcher"
    }

    def __init__(self, target_dir: Union[str, Path]):
        self.target_dir = Path(target_dir).resolve()
        safe_name = "".join(c if c.isalnum() else "_" for c in self.target_dir.name)
        self.game_name = safe_name or "Game"

    def discover_executable(self) -> Optional[Path]:
        """
        Discovers the primary game executable in the target directory.
        Prioritizes root directory, then common game subdirectories (bin/x64, bin, Binaries/Win64),
        filtering out uninstallers, crash reporters, and redistributables.
        """
        candidates: List[Path] = []

        # 1. Search root directory
        for p in self.target_dir.glob("*.exe"):
            if not self._is_excluded_exe(p):
                candidates.append(p)

        # 2. Check common game subdirectory layouts if no root executable found
        if not candidates:
            subdirs = [
                "bin/x64", "bin/Win64", "bin",
                "Binaries/Win64", "Binaries/Win32", "x64", "Win64"
            ]
            for sub in subdirs:
                subdir_path = self.target_dir / sub
                if subdir_path.is_dir():
                    for p in subdir_path.glob("*.exe"):
                        if not self._is_excluded_exe(p):
                            candidates.append(p)
                    if candidates:
                        break

        # 3. Fallback: Recursive search across entire target directory
        if not candidates:
            for p in self.target_dir.rglob("*.exe"):
                if not self._is_excluded_exe(p):
                    candidates.append(p)

        if not candidates:
            return None

        # Sort by file size descending (the main game executable is typically largest)
        candidates.sort(key=lambda x: x.stat().st_size if x.exists() else 0, reverse=True)
        return candidates[0]

    def _is_excluded_exe(self, exe_path: Path) -> bool:
        """Determines if an executable is an uninstaller, setup tool, or auxiliary helper."""
        name_lower = exe_path.name.lower()
        path_str = str(exe_path).lower()

        # Exclude quarantine, gamecleaner cache, and tools
        if ".gamecleaner" in path_str or ".quarantine" in path_str or "__pycache__" in path_str:
            return True

        for kw in self.EXCLUDED_EXE_KEYWORDS:
            if kw in name_lower:
                return True

        return False

    def discover_emulators(self) -> List[str]:
        """
        Detects installed Goldberg / Steam emulator DLLs in the game folder.
        Returns list of emulator filenames found (e.g. ['steam_api64.dll', 'steam_api.dll']).
        """
        found = set()
        for dll_name in ("steam_api64.dll", "steam_api.dll"):
            if list(self.target_dir.rglob(dll_name)):
                found.add(dll_name)
        return sorted(list(found))

    def discover_appid(self) -> Optional[str]:
        """
        Discovers the Steam AppID from steam_appid.txt, steam_settings,
        or repack configuration INI files.
        """
        # 1. Root or direct steam_appid.txt
        root_txt = self.target_dir / "steam_appid.txt"
        if root_txt.exists():
            content = root_txt.read_text(encoding="utf-8", errors="ignore").strip()
            if content.isdigit():
                return content

        # 2. steam_settings/steam_appid.txt
        settings_txt = self.target_dir / "steam_settings" / "steam_appid.txt"
        if settings_txt.exists():
            content = settings_txt.read_text(encoding="utf-8", errors="ignore").strip()
            if content.isdigit():
                return content

        # 3. Search in any subdirectory for steam_appid.txt
        for p in self.target_dir.rglob("steam_appid.txt"):
            if ".quarantine" in str(p):
                continue
            try:
                content = p.read_text(encoding="utf-8", errors="ignore").strip()
                if content.isdigit():
                    return content
            except Exception:
                continue

        # 4. Search in repack INI files (steam_emu.ini, flt.ini, valve.ini, etc.)
        for ini_path in self.target_dir.rglob("*.ini"):
            if ".quarantine" in str(ini_path):
                continue
            try:
                text = ini_path.read_text(encoding="utf-8", errors="ignore")
                match = re.search(r"^\s*(?:AppId|appid)\s*=\s*(\d+)", text, re.MULTILINE | re.IGNORECASE)
                if match:
                    return match.group(1).strip()
            except Exception:
                continue

        return None

    def get_dll_overrides(self) -> str:
        """
        Returns the WINEDLLOVERRIDES string.
        Ensures Wine/Proton loads local Goldberg DLLs rather than Wine stubs.
        Format: 'steam_api=n,b;steam_api64=n,b'
        """
        # Default override covers both 32-bit and 64-bit Steamworks DLLs
        return "steam_api=n,b;steam_api64=n,b"

    def generate_run_script(
        self,
        executable: Optional[Path] = None,
        appid: Optional[str] = None,
        overrides: Optional[str] = None,
        script_name: str = "run_proton.sh",
    ) -> Path:
        """
        Generates 'run_proton.sh' in the target game directory.
        Includes WINEDLLOVERRIDES, network namespace isolation checks (unshare -n / firejail),
        and automatic Proton / Wine detection.
        """
        exe_path = executable or self.discover_executable()
        if not exe_path:
            # Fallback placeholder if no exe found
            exe_path = self.target_dir / f"{self.game_name}.exe"

        # Calculate relative path from target_dir to executable
        try:
            rel_exe = exe_path.relative_to(self.target_dir).as_posix()
        except ValueError:
            rel_exe = exe_path.name

        chosen_appid = appid or self.discover_appid() or "480"
        chosen_overrides = overrides or self.get_dll_overrides()
        script_path = self.target_dir / script_name

        script_content = f"""#!/usr/bin/env bash
# ==============================================================================
# GameCleaner Isolated Proton Runner for Steam Deck / Linux
# Auto-generated by GameCleaner ProtonHelper
# Target Game: {self.game_name}
# AppID: {chosen_appid}
# Executable: {rel_exe}
# ==============================================================================

set -e

# Resolve game directory (where this script resides)
SCRIPT_DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"
cd "$SCRIPT_DIR"

# 1. Wine DLL Overrides (Forces local Goldberg Steam emulator native DLLs)
export WINEDLLOVERRIDES="{chosen_overrides}"

# 2. Steam & Proton Environment Configuration
export STEAM_COMPAT_CLIENT_INSTALL_PATH="${{STEAM_COMPAT_CLIENT_INSTALL_PATH:-$HOME/.steam/root}}"
export STEAM_COMPAT_DATA_PATH="${{STEAM_COMPAT_DATA_PATH:-$SCRIPT_DIR/.proton_prefix}}"
mkdir -p "$STEAM_COMPAT_DATA_PATH"

# Set Steam AppID for runtime Steamworks API hooks
export SteamAppId="{chosen_appid}"
export SteamGameId="{chosen_appid}"

# 3. Network Isolation Check & Containment (Air-Gap)
# Checks for Linux network namespace (unshare -n) or Firejail sandbox
NET_CMD=""
AIRGAP_SUPPORTED=0

if command -v unshare >/dev/null 2>&1 && unshare -n true >/dev/null 2>&1; then
    NET_CMD="unshare -n"
    AIRGAP_SUPPORTED=1
elif command -v firejail >/dev/null 2>&1; then
    NET_CMD="firejail --noprofile --net=none"
    AIRGAP_SUPPORTED=1
fi

# Allow user to toggle air-gap: AIRGAP=0 ./run_proton.sh to allow network
ALLOW_AIRGAP="${{AIRGAP:-1}}"
if [ "$ALLOW_AIRGAP" = "1" ] && [ -n "$NET_CMD" ]; then
    echo "[GameCleaner] Network air-gap isolation active: $NET_CMD"
    ISOLATION_WRAPPER="$NET_CMD"
else
    if [ "$AIRGAP_SUPPORTED" = "0" ]; then
        echo "[GameCleaner] Notice: unshare -n or firejail not available; running without network namespace isolation."
    else
        echo "[GameCleaner] Air-gap disabled by AIRGAP=0 environment variable."
    fi
    ISOLATION_WRAPPER=""
fi

# 4. Locate Proton or Wine Binary
PROTON_BIN=""
if [ -n "$PROTON" ] && [ -x "$PROTON" ]; then
    PROTON_BIN="$PROTON"
elif [ -n "$STEAM_PROTON" ] && [ -x "$STEAM_PROTON/proton" ]; then
    PROTON_BIN="$STEAM_PROTON/proton"
else
    # Common SteamOS / Linux Proton locations
    CANDIDATES=(
        "$HOME/.local/share/Steam/steamapps/common/Proton - Experimental/proton"
        "$HOME/.steam/root/steamapps/common/Proton - Experimental/proton"
        "$HOME/.local/share/Steam/steamapps/common/Proton 9.0/proton"
        "$HOME/.local/share/Steam/steamapps/common/Proton 8.0/proton"
        "$HOME/.steam/steam/steamapps/common/Proton - Experimental/proton"
    )
    # Check GE-Proton in compatibilitytools.d
    for ge in "$HOME/.steam/root/compatibilitytools.d"/*/proton "$HOME/.local/share/Steam/compatibilitytools.d"/*/proton; do
        if [ -x "$ge" ]; then
            CANDIDATES+=("$ge")
        fi
    done

    for cand in "${{CANDIDATES[@]}}"; do
        if [ -x "$cand" ]; then
            PROTON_BIN="$cand"
            break
        fi
    done
fi

TARGET_EXE="$SCRIPT_DIR/{rel_exe}"
EXE_DIR="$(dirname "$TARGET_EXE")"

echo "[GameCleaner] Launching: $TARGET_EXE"
echo "[GameCleaner] WINEDLLOVERRIDES=$WINEDLLOVERRIDES"
echo "[GameCleaner] SteamAppId=$SteamAppId"

cd "$EXE_DIR"

if [ -n "$PROTON_BIN" ]; then
    echo "[GameCleaner] Using Proton: $PROTON_BIN"
    exec $ISOLATION_WRAPPER "$PROTON_BIN" run "$TARGET_EXE" "$@"
elif command -v wine >/dev/null 2>&1; then
    echo "[GameCleaner] Notice: Proton not found; falling back to system Wine."
    exec $ISOLATION_WRAPPER wine "$TARGET_EXE" "$@"
else
    echo "[GameCleaner] Error: Neither Proton nor Wine was detected on this system."
    echo "Please set PROTON=/path/to/proton before running this script."
    exit 1
fi
"""
        write_posix_script(script_path, script_content)
        return script_path

    def generate_steamdeck_setup(
        self,
        executable: Optional[Path] = None,
        appid: Optional[str] = None,
        script_name: str = "setup_steamdeck.sh",
    ) -> Path:
        """
        Generates 'setup_steamdeck.sh' to configure Steam Deck Desktop and Gaming Mode:
        - Sets executable permissions
        - Initializes Proton prefix and Goldberg save directories
        - Generates Desktop Mode .desktop application shortcut
        - Displays Gaming Mode Non-Steam game instructions
        """
        chosen_appid = appid or self.discover_appid() or "480"
        script_path = self.target_dir / script_name

        setup_content = f"""#!/usr/bin/env bash
# ==============================================================================
# GameCleaner Steam Deck Configuration Helper
# Prepares desktop mode and gaming mode integration for: {self.game_name}
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== GameCleaner Steam Deck Setup: {self.game_name} ==="

# 1. Set execution permissions on runner
if [ -f "$SCRIPT_DIR/run_proton.sh" ]; then
    chmod +x "$SCRIPT_DIR/run_proton.sh"
    echo "[OK] Marked run_proton.sh as executable"
fi

# 2. Setup isolated proton prefix directory
mkdir -p "$SCRIPT_DIR/.proton_prefix"
echo "[OK] Initialized Proton prefix at: $SCRIPT_DIR/.proton_prefix"

# 3. Setup Goldberg Linux save game folder
GOLDBERG_SAVES="$HOME/.local/share/Goldberg SteamEmu Saves/{chosen_appid}"
mkdir -p "$GOLDBERG_SAVES"
echo "[OK] Configured Goldberg save directory: $GOLDBERG_SAVES"

# 4. Create Desktop Shortcut for Steam Deck Desktop Mode
DESKTOP_DIR="$HOME/Desktop"
APPLICATIONS_DIR="$HOME/.local/share/applications"
mkdir -p "$APPLICATIONS_DIR"

DESKTOP_ENTRY="[Desktop Entry]
Name={self.game_name} (GameCleaner)
Comment=Isolated Proton Launcher with DLL overrides and network containment
Exec=\\"$SCRIPT_DIR/run_proton.sh\\"
Path=$SCRIPT_DIR
Terminal=false
Type=Application
Categories=Game;
"

echo "$DESKTOP_ENTRY" > "$APPLICATIONS_DIR/{self.game_name}.desktop"
chmod +x "$APPLICATIONS_DIR/{self.game_name}.desktop"

if [ -d "$DESKTOP_DIR" ]; then
    echo "$DESKTOP_ENTRY" > "$DESKTOP_DIR/{self.game_name}.desktop"
    chmod +x "$DESKTOP_DIR/{self.game_name}.desktop"
    echo "[OK] Created Desktop shortcut at $DESKTOP_DIR/{self.game_name}.desktop"
fi

echo ""
echo "=== Setup Complete! ==="
echo "To add to Steam Gaming Mode:"
echo " 1. Open Steam in Desktop Mode."
echo " 2. Click 'Games' -> 'Add a Non-Steam Game to My Library...'"
echo " 3. Browse and select: $SCRIPT_DIR/run_proton.sh"
echo " 4. (Optional) In Steam Properties -> Launch Options, leave empty or customize."
echo " 5. Return to Gaming Mode and launch '{self.game_name}'!"
"""
        write_posix_script(script_path, setup_content)
        return script_path

    def generate_all(self) -> ProtonScriptResult:
        """
        Executes discovery, generates both run_proton.sh and setup_steamdeck.sh,
        and returns a structured ProtonScriptResult dataclass.
        """
        exe = self.discover_executable()
        exe_name = exe.name if exe else f"{self.game_name}.exe"
        try:
            rel_exe = exe.relative_to(self.target_dir).as_posix() if exe else exe_name
        except ValueError:
            rel_exe = exe_name

        appid = self.discover_appid()
        overrides = self.get_dll_overrides()

        run_script = self.generate_run_script(executable=exe, appid=appid, overrides=overrides)
        setup_script = self.generate_steamdeck_setup(executable=exe, appid=appid)
        net_iso = is_network_isolation_supported()

        return ProtonScriptResult(
            script_path=run_script,
            overrides=overrides,
            executable_name=exe_name,
            network_isolation_supported=net_iso,
            setup_script_path=setup_script,
            appid=appid,
            relative_exe_path=rel_exe,
        )
