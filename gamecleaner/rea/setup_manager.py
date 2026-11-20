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
import urllib.error
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
            repo_tools = Path(__file__).resolve().parent.parent.parent / "tools"
            try:
                # If running from local source checkout and writable, use local tools dir
                if repo_tools.exists() or os.access(repo_tools.parent, os.W_OK):
                    self.tools_dir = repo_tools
                else:
                    self.tools_dir = Path.home() / ".gamecleaner" / "tools"
            except Exception:
                self.tools_dir = Path.home() / ".gamecleaner" / "tools"
        self.ghidra_dir = self.tools_dir / "ghidra"

    def check_environment(self) -> EnvironmentStatus:
        """Audits the local system for Java, Node, npm, REA, and Ghidra."""
        # 1. Java check
        java_ok = False
        java_ver = None

        java_binaries = ["java"]
        # Fallback candidate search on Windows
        if os.name == "nt":
            for env_var in ["JAVA_HOME", "JDK_HOME"]:
                val = os.environ.get(env_var)
                if val:
                    candidate = Path(val) / "bin" / "java.exe"
                    if candidate.exists():
                        java_binaries.append(str(candidate))

            # Common install locations
            for root_dir in [r"C:\Program Files\Java", r"C:\Program Files\Eclipse Adoptium", r"C:\Program Files\Microsoft"]:
                p = Path(root_dir)
                if p.exists():
                    for j_exe in p.glob("**/bin/java.exe"):
                        java_binaries.append(str(j_exe))

        for j_cmd in java_binaries:
            try:
                p = subprocess.run([j_cmd, "-version"], capture_output=True, text=True, timeout=5)
                output = p.stderr or p.stdout
                if "version" in output:
                    java_ok = True
                    java_ver = output.splitlines()[0].strip()
                    # If found via non-standard path, propagate to PATH
                    if j_cmd != "java":
                        j_bin = str(Path(j_cmd).parent)
                        if j_bin not in os.environ.get("PATH", ""):
                            os.environ["PATH"] = f"{j_bin};{os.environ.get('PATH', '')}"
                        if "JAVA_HOME" not in os.environ:
                            os.environ["JAVA_HOME"] = str(Path(j_cmd).parent.parent)
                    break
            except Exception:
                continue

        # 2. Node check
        node_ok = False
        node_ver = None
        node_binaries = ["node"]
        if os.name == "nt":
            for n_path in [r"C:\Program Files\nodejs\node.exe", r"C:\Program Files (x86)\nodejs\node.exe"]:
                if Path(n_path).exists():
                    node_binaries.append(n_path)

        for n_cmd in node_binaries:
            try:
                p = subprocess.run([n_cmd, "-v"], capture_output=True, text=True, timeout=5)
                if p.returncode == 0:
                    node_ok = True
                    node_ver = p.stdout.strip()
                    if n_cmd != "node":
                        n_dir = str(Path(n_cmd).parent)
                        if n_dir not in os.environ.get("PATH", ""):
                            os.environ["PATH"] = f"{n_dir};{os.environ.get('PATH', '')}"
                    break
            except Exception:
                continue

        # 3. npm check
        npm_ok = False
        npm_binaries = ["npm.cmd" if os.name == "nt" else "npm"]
        if os.name == "nt":
            for n_path in [r"C:\Program Files\nodejs\npm.cmd"]:
                if Path(n_path).exists():
                    npm_binaries.append(n_path)

        for npm_cmd in npm_binaries:
            try:
                p = subprocess.run([npm_cmd, "-v"], capture_output=True, text=True, timeout=5)
                if p.returncode == 0:
                    npm_ok = True
                    break
            except Exception:
                continue

        # 4. REA check
        rea_ok = False
        rea_ver = None
        rea_commands = ["rea", "rea-agents"]
        rea_binaries = []
        for cmd in rea_commands:
            rea_binaries.append(f"{cmd}.cmd" if os.name == "nt" else cmd)

        if os.name == "nt":
            appdata = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
            npm_global = Path(appdata) / "npm"
            for cmd in rea_commands:
                cand = npm_global / f"{cmd}.cmd"
                if cand.exists():
                    rea_binaries.append(str(cand))

        for cmd_name in rea_binaries:
            try:
                p = subprocess.run([cmd_name, "--version"], capture_output=True, text=True, timeout=5)
                if p.returncode == 0 and p.stdout.strip():
                    rea_ok = True
                    rea_ver = p.stdout.strip()
                    # Propagate directory to PATH if needed
                    cmd_dir = str(Path(cmd_name).parent)
                    if os.path.isabs(cmd_name) and cmd_dir not in os.environ.get("PATH", ""):
                        os.environ["PATH"] = f"{cmd_dir};{os.environ.get('PATH', '')}"
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
            # Search subfolders recursively for analyzeHeadless
            pattern = "**/support/analyzeHeadless.bat" if os.name == "nt" else "**/support/analyzeHeadless"
            for headless in self.ghidra_dir.glob(pattern):
                candidate = headless.parent.parent
                if self._is_valid_ghidra_dir(candidate):
                    return candidate

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
        except urllib.error.HTTPError as e:
            if e.code == 403:
                return False, "GitHub API rate limit exceeded (HTTP 403). Set GHIDRA_INSTALL_DIR to use existing Ghidra.", None
            return False, f"GitHub API error (HTTP {e.code}): {e}", None
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
