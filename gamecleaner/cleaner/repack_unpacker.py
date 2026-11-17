"""
Pre-Install Repack & Installer Unpacker.
Safely extracts game archives and Inno Setup / NSIS repacks (FitGirl, DODI, GOG, etc.)
directly to disk without executing the untrusted setup.exe, with an option to auto-clean during installation.
"""
from dataclasses import dataclass, field
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import List, Optional
import urllib.request
import zipfile


@dataclass
class UnpackResult:
    installer_path: str
    output_dir: str
    extractor_used: str
    success: bool
    extracted_files_count: int
    error_message: Optional[str] = None
    cleaned_after_unpack: bool = False
    pipeline_report: Optional[dict] = None


class RepackUnpacker:
    """Safely extracts game files from repack installers and archives without running untrusted code."""

    INNOEXTRACT_URL = "https://github.com/dscharrer/innoextract/releases/download/1.9/innoextract-1.9-windows.zip"

    def __init__(self, tools_dir: Optional[Path] = None):
        self.tools_dir = tools_dir or (Path.home() / ".gamecleaner" / "bin")
        self.tools_dir.mkdir(parents=True, exist_ok=True)
        self.innoextract_exe = self.tools_dir / "innoextract.exe"

    def ensure_innoextract(self) -> Optional[Path]:
        """Ensures innoextract is available (checks PATH, then local tools directory, then downloads)."""
        # Check system PATH
        system_inno = shutil.which("innoextract")
        if system_inno:
            return Path(system_inno)

        # Check local tools directory
        if self.innoextract_exe.exists():
            return self.innoextract_exe

        # Attempt download of official portable innoextract
        try:
            zip_dest = self.tools_dir / "innoextract.zip"
            urllib.request.urlretrieve(self.INNOEXTRACT_URL, zip_dest)
            with zipfile.ZipFile(zip_dest, "r") as zf:
                for member in zf.namelist():
                    if member.endswith("innoextract.exe"):
                        with zf.open(member) as src, open(self.innoextract_exe, "wb") as dst:
                            shutil.copyfileobj(src, dst)
                        break
            if zip_dest.exists():
                zip_dest.unlink()

            if self.innoextract_exe.exists():
                return self.innoextract_exe
        except Exception:
            pass

        return None

    def is_inno_setup(self, file_path: Path) -> bool:
        """Heuristic check to determine if an executable is an Inno Setup installer."""
        try:
            with open(file_path, "rb") as f:
                header = f.read(204800)  # Read first 200KB
                return b"Inno Setup" in header or b"Inno Setup Setup Data" in header
        except Exception:
            return False

    def unpack(
        self,
        installer_path: Path,
        output_dir: Path,
        auto_clean: bool = True,
    ) -> UnpackResult:
        """
        Safely unpacks the installer or archive to output_dir without running executable code.
        If auto_clean=True, runs GameCleanerPipeline to sanitize, replace emulators, and isolate.
        """
        installer = Path(installer_path).resolve()
        out = Path(output_dir).resolve()
        out.mkdir(parents=True, exist_ok=True)

        if not installer.exists():
            return UnpackResult(
                installer_path=str(installer),
                output_dir=str(out),
                extractor_used="none",
                success=False,
                extracted_files_count=0,
                error_message=f"File not found: {installer}",
            )

        suffix = installer.suffix.lower()
        extractor_used = "unknown"
        success = False
        error_msg = None

        # 1. Inno Setup Check
        if suffix == ".exe" and self.is_inno_setup(installer):
            inno_bin = self.ensure_innoextract()
            if inno_bin:
                extractor_used = "innoextract"
                try:
                    cmd = [str(inno_bin), "-e", "-d", str(out), str(installer)]
                    res = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                    if res.returncode == 0:
                        success = True
                    else:
                        error_msg = res.stderr or res.stdout
                except Exception as e:
                    error_msg = str(e)
            else:
                error_msg = "Inno Setup detected, but innoextract is not installed."

        # 2. Native ZIP Archive Extraction
        if not success and (suffix == ".zip" or zipfile.is_zipfile(installer)):
            try:
                with zipfile.ZipFile(installer, "r") as zf:
                    zf.extractall(out)
                extractor_used = "zipfile"
                success = True
            except Exception as e:
                error_msg = str(e)

        # 3. Archive / SFX Extraction via tar.exe or 7z
        if not success:
            seven_zip = shutil.which("7z") or shutil.which("7za")
            if seven_zip:
                extractor_used = "7z"
                try:
                    cmd = [seven_zip, "x", str(installer), f"-o{out}", "-y"]
                    res = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                    if res.returncode == 0:
                        success = True
                    else:
                        error_msg = res.stderr or res.stdout
                except Exception as e:
                    error_msg = str(e)

        # 4. Built-in Windows tar.exe (supports .tar, .7z, .iso, etc.)
        if not success:
            tar_bin = shutil.which("tar.exe") or "tar.exe"
            extractor_used = "tar.exe"
            try:
                cmd = [tar_bin, "-xf", str(installer), "-C", str(out)]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if res.returncode == 0:
                    success = True
                else:
                    error_msg = res.stderr or res.stdout
            except Exception as e:
                error_msg = str(e)

        # Count extracted files
        count = 0
        if success:
            for root, _, files in os.walk(out):
                count += len(files)

        # Option during installation: Auto-clean extracted files immediately
        pipeline_report_dict = None
        cleaned_after_unpack = False

        if success and auto_clean and count > 0:
            try:
                from gamecleaner.pipeline import GameCleanerPipeline
                pipeline = GameCleanerPipeline(out)
                report = pipeline.run_full_pipeline()
                from dataclasses import asdict
                pipeline_report_dict = asdict(report)
                cleaned_after_unpack = True
            except Exception as e:
                error_msg = f"Extraction succeeded, but auto-clean failed: {e}"

        return UnpackResult(
            installer_path=str(installer),
            output_dir=str(out),
            extractor_used=extractor_used,
            success=success,
            extracted_files_count=count,
            error_message=error_msg,
            cleaned_after_unpack=cleaned_after_unpack,
            pipeline_report=pipeline_report_dict,
        )
