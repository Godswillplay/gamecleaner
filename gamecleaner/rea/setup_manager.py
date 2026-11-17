"""
Hands-free installer and environment manager for REA and Ghidra.
"""
from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
import subprocess
from typing import Callable, Dict, Optional, Tuple
import urllib.request
import zipfile


@dataclass
class EnvironmentStatus:
    java_installed: bool
    java_version: Optional[str]
    node_installed: bool
    node_version: Optional[str]
    npm_installed: bool
    rea_installed: bool
    rea_version: Optional[str]
    ghidra_installed: bool
    ghidra_path: Optional[Path]


class REASetupManager:
    """Manages zero-configuration, automated setup of Ghidra and REA."""

    GHIDRA_LATEST_API = "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest"

    def __init__(self, tools_dir: Optional[Path] = None):
        if tools_dir:
            self.tools_dir = Path(tools_dir).resolve()
        else:
            self.tools_dir = Path(__file__).resolve().parent.parent.parent / "tools"
        self.ghidra_dir = self.tools_dir / "ghidra"

    def check_environment(self) -> EnvironmentStatus:
        """Audits the local system for Java, Node, npm, REA, and Ghidra."""
        # 1. Java check
        java_ok = False
        java_ver = None
        try:
            p = subprocess.run(["java", "-version"], capture_output=True, text=True, timeout=5)
            output = p.stderr or p.stdout
            if "version" in output:
                java_ok = True
                java_ver = output.splitlines()[0].strip()
        except Exception:
            pass

        # 2. Node check
        node_ok = False
        node_ver = None
        try:
            p = subprocess.run(["node", "-v"], capture_output=True, text=True, timeout=5)
            if p.returncode == 0:
                node_ok = True
                node_ver = p.stdout.strip()
        except Exception:
            pass

        # 3. npm check
        npm_cmd = "npm.cmd" if os.name == "nt" else "npm"
        npm_ok = False
        try:
            p = subprocess.run([npm_cmd, "-v"], capture_output=True, text=True, timeout=5)
            if p.returncode == 0:
                npm_ok = True
        except Exception:
            pass

        # 4. REA check
        rea_ok = False
        rea_ver = None
        for cmd in ["rea", "rea-agents"]:
            cmd_name = f"{cmd}.cmd" if os.name == "nt" else cmd
            try:
                p = subprocess.run([cmd_name, "--version"], capture_output=True, text=True, timeout=5)
                if p.returncode == 0 and p.stdout.strip():
                    rea_ok = True
                    rea_ver = p.stdout.strip()
                    break
            except Exception:
                continue

        # 5. Ghidra check
        ghidra_path = self.locate_ghidra()
        ghidra_ok = ghidra_path is not None

        return EnvironmentStatus(
            java_installed=java_ok,
            java_version=java_ver,
            node_installed=node_ok,
            node_version=node_ver,
            npm_installed=npm_ok,
            rea_installed=rea_ok,
            rea_version=rea_ver,
            ghidra_installed=ghidra_ok,
            ghidra_path=ghidra_path,
        )

    def locate_ghidra(self) -> Optional[Path]:
        """Locates analyzeHeadless.bat in env vars or local tools directory."""
        # Check GHIDRA_INSTALL_DIR
        env_dir = os.environ.get("GHIDRA_INSTALL_DIR") or os.environ.get("GHIDRA_PATH")
        if env_dir:
            p = Path(env_dir)
            if self._is_valid_ghidra_dir(p):
                return p

        # Check local tools/ghidra
        if self.ghidra_dir.exists():
            if self._is_valid_ghidra_dir(self.ghidra_dir):
                return self.ghidra_dir
            # Search one level subfolder (e.g. ghidra_12.2_PUBLIC)
            for sub in self.ghidra_dir.iterdir():
                if sub.is_dir() and self._is_valid_ghidra_dir(sub):
                    return sub

        # Check PATH
        which_headless = shutil.which("analyzeHeadless.bat") or shutil.which("analyzeHeadless")
        if which_headless:
            candidate = Path(which_headless).parent.parent
            if self._is_valid_ghidra_dir(candidate):
                return candidate

        return None

    def _is_valid_ghidra_dir(self, dir_path: Path) -> bool:
        headless_bat = dir_path / "support" / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
        return headless_bat.exists()

    def install_rea_globally(self) -> Tuple[bool, str]:
        """Installs rea-agents globally via npm."""
        npm_cmd = "npm.cmd" if os.name == "nt" else "npm"
        try:
            proc = subprocess.run(
                [npm_cmd, "install", "-g", "rea-agents"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if proc.returncode == 0:
                return True, "Successfully installed rea-agents globally via npm."
            else:
                return False, f"npm install failed: {proc.stderr or proc.stdout}"
        except Exception as e:
            return False, f"Failed to execute npm: {e}"

    def install_ghidra_portable(
        self,
        progress_hook: Optional[Callable[[int, int], None]] = None,
    ) -> Tuple[bool, str, Optional[Path]]:
        """
        Downloads the latest official portable Ghidra release from GitHub and unzips it
        into the local tools/ghidra directory without requiring any manual user setup.
        """
        self.tools_dir.mkdir(parents=True, exist_ok=True)
        self.ghidra_dir.mkdir(parents=True, exist_ok=True)

        # Step 1: Query GitHub API for latest release asset
        req = urllib.request.Request(
            self.GHIDRA_LATEST_API,
            headers={"User-Agent": "GameCleaner-Setup"},
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            return False, f"Could not query GitHub releases for Ghidra: {e}", None

        download_url = None
        asset_name = None
        for a in data.get("assets", []):
            if "PUBLIC" in a.get("name", "") and a.get("name", "").endswith(".zip"):
                download_url = a["browser_download_url"]
                asset_name = a["name"]
                break

        if not download_url:
            return False, "Could not find a public pre-built Ghidra zip asset in latest release.", None

        # Step 2: Download zip
        zip_path = self.tools_dir / asset_name
        try:
            def _reporthook(block_num, block_size, total_size):
                if progress_hook:
                    progress_hook(block_num * block_size, total_size)

            urllib.request.urlretrieve(download_url, str(zip_path), reporthook=_reporthook)
        except Exception as e:
            return False, f"Failed to download Ghidra release zip: {e}", None

        # Step 3: Extract zip
        try:
            with zipfile.ZipFile(str(zip_path), "r") as z:
                z.extractall(str(self.ghidra_dir))
            zip_path.unlink()  # remove zip to save space
        except Exception as e:
            return False, f"Failed to extract Ghidra zip archive: {e}", None

        # Step 4: Validate extraction
        installed_path = self.locate_ghidra()
        if installed_path:
            os.environ["GHIDRA_INSTALL_DIR"] = str(installed_path)
            return True, f"Ghidra portable successfully installed at {installed_path}", installed_path
        else:
            return False, "Extracted Ghidra, but analyzeHeadless was not located.", None
