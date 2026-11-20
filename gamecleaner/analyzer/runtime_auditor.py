"""
Game Dependency & Runtime Auditor: Detects required DirectX, Visual C++, and OpenAL runtimes.
Checks host system presence and locates bundled redistributables in game repacks.
"""
from dataclasses import dataclass, field
import os
from pathlib import Path
from typing import Dict, List, Optional, Set

try:
    import pefile
except ImportError:
    pefile = None


DEPENDENCY_PACKAGES: Dict[str, Dict[str, str]] = {
    # VC++ 2015-2022
    "msvcp140.dll": {"package": "Visual C++ 2015-2022 Redistributable", "installer_hint": "vc_redist"},
    "vcruntime140.dll": {"package": "Visual C++ 2015-2022 Redistributable", "installer_hint": "vc_redist"},
    "vcruntime140_1.dll": {"package": "Visual C++ 2015-2022 Redistributable", "installer_hint": "vc_redist"},
    "msvcp140_1.dll": {"package": "Visual C++ 2015-2022 Redistributable", "installer_hint": "vc_redist"},
    "msvcp140_2.dll": {"package": "Visual C++ 2015-2022 Redistributable", "installer_hint": "vc_redist"},
    "msvcp140_codecvt_ids.dll": {"package": "Visual C++ 2015-2022 Redistributable", "installer_hint": "vc_redist"},
    # VC++ 2013
    "msvcp120.dll": {"package": "Visual C++ 2013 Redistributable", "installer_hint": "vcredist_2013"},
    "msvcr120.dll": {"package": "Visual C++ 2013 Redistributable", "installer_hint": "vcredist_2013"},
    # VC++ 2012
    "msvcp110.dll": {"package": "Visual C++ 2012 Redistributable", "installer_hint": "vcredist_2012"},
    "msvcr110.dll": {"package": "Visual C++ 2012 Redistributable", "installer_hint": "vcredist_2012"},
    # VC++ 2010
    "msvcp100.dll": {"package": "Visual C++ 2010 Redistributable", "installer_hint": "vcredist_2010"},
    "msvcr100.dll": {"package": "Visual C++ 2010 Redistributable", "installer_hint": "vcredist_2010"},
    # DirectX June 2010
    "d3dx9_43.dll": {"package": "DirectX End-User Runtimes (June 2010)", "installer_hint": "dxsetup"},
    "d3dx9_42.dll": {"package": "DirectX End-User Runtimes (June 2010)", "installer_hint": "dxsetup"},
    "d3dx10_43.dll": {"package": "DirectX End-User Runtimes (June 2010)", "installer_hint": "dxsetup"},
    "d3dx11_43.dll": {"package": "DirectX End-User Runtimes (June 2010)", "installer_hint": "dxsetup"},
    "d3dcompiler_43.dll": {"package": "DirectX End-User Runtimes (June 2010)", "installer_hint": "dxsetup"},
    "d3dcompiler_47.dll": {"package": "DirectX End-User Runtimes (June 2010)", "installer_hint": "dxsetup"},
    "xinput1_3.dll": {"package": "DirectX End-User Runtimes (June 2010)", "installer_hint": "dxsetup"},
    "xactengine3_7.dll": {"package": "DirectX End-User Runtimes (June 2010)", "installer_hint": "dxsetup"},
    # OpenAL
    "openal32.dll": {"package": "OpenAL Audio Engine", "installer_hint": "oalinst"},
}


@dataclass
class MissingDependency:
    dll_name: str
    required_by: str
    package_name: str
    installer_path: Optional[str] = None
    install_command: Optional[str] = None


@dataclass
class DiscoveredRedist:
    name: str
    file_path: str
    recommended_silent_args: str


@dataclass
class RuntimeAuditReport:
    game_dir: str
    scanned_binaries_count: int
    required_dlls: List[str]
    missing_dependencies: List[MissingDependency]
    discovered_redists: List[DiscoveredRedist]
    is_ready_to_play: bool


class RuntimeAuditor:
    """Audits game binaries for required runtime libraries and detects local redistributables."""

    def __init__(self, game_dir: Path):
        self.game_dir = Path(game_dir)
        self.system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        self.system32 = self.system_root / "System32"
        self.syswow64 = self.system_root / "SysWOW64"

    def _is_dll_present_on_host(self, dll_name: str, is_64bit: bool = True) -> bool:
        """Checks if a DLL is present in Windows System32, SysWOW64, or inside the game folder."""
        # 1. Check game folder locally
        for f in self.game_dir.rglob("*.dll"):
            if f.name.lower() == dll_name.lower():
                return True

        # 2. Check Windows System directories
        if is_64bit:
            if (self.system32 / dll_name).exists():
                return True
        else:
            if (self.syswow64 / dll_name).exists() or (self.system32 / dll_name).exists():
                return True

        return False

    def discover_redists(self) -> List[DiscoveredRedist]:
        """Finds bundled redistributable installers in repack subfolders."""
        redists: List[DiscoveredRedist] = []
        if not self.game_dir.exists():
            return redists

        common_subdirs = ["_commonredist", "_redist", "redist", "support", "install", "dependencies"]

        for root, _, files in os.walk(self.game_dir):
            r_path = Path(root)
            r_name = r_path.name.lower()
            in_redist_dir = any(sub in str(r_path).lower() for sub in common_subdirs)

            for f in files:
                f_lower = f.lower()
                f_path = r_path / f

                if f_lower.endswith(".exe"):
                    if "dxsetup" in f_lower:
                        redists.append(DiscoveredRedist(
                            name="DirectX End-User Runtimes",
                            file_path=str(f_path),
                            recommended_silent_args="/silent",
                        ))
                    elif "vc_redist" in f_lower or "vcredist" in f_lower:
                        redists.append(DiscoveredRedist(
                            name="Visual C++ Redistributable",
                            file_path=str(f_path),
                            recommended_silent_args="/quiet /norestart",
                        ))
                    elif "oalinst" in f_lower:
                        redists.append(DiscoveredRedist(
                            name="OpenAL Installer",
                            file_path=str(f_path),
                            recommended_silent_args="/s",
                        ))
                    elif in_redist_dir and ("setup" in f_lower or "redist" in f_lower or "install" in f_lower):
                        redists.append(DiscoveredRedist(
                            name=f"Redistributable ({f})",
                            file_path=str(f_path),
                            recommended_silent_args="/quiet /norestart",
                        ))
                elif f_lower.endswith(".msi") and in_redist_dir:
                    redists.append(DiscoveredRedist(
                        name=f"MSI Package ({f})",
                        file_path=str(f_path),
                        recommended_silent_args="/quiet /qn /norestart",
                    ))

        # Deduplicate by file path
        unique_redists = {}
        for r in redists:
            unique_redists[r.file_path] = r

        return list(unique_redists.values())

    def audit(self) -> RuntimeAuditReport:
        """Extracts imports from all game binaries and checks for missing runtimes."""
        if not self.game_dir.exists():
            return RuntimeAuditReport(
                game_dir=str(self.game_dir),
                scanned_binaries_count=0,
                required_dlls=[],
                missing_dependencies=[],
                discovered_redists=[],
                is_ready_to_play=True,
            )

        discovered_redists = self.discover_redists()
        redist_map: Dict[str, DiscoveredRedist] = {}
        for dr in discovered_redists:
            dr_lower = dr.file_path.lower()
            if "dxsetup" in dr_lower:
                redist_map["dxsetup"] = dr
            elif "vc_redist" in dr_lower or "vcredist" in dr_lower:
                redist_map["vc_redist"] = dr
            elif "oalinst" in dr_lower:
                redist_map["oalinst"] = dr

        scanned_binaries: List[Path] = []
        for root, _, files in os.walk(self.game_dir):
            r_path = Path(root)
            if ".gamecleaner" in str(r_path) or ".quarantine" in str(r_path):
                continue
            for f in files:
                if f.lower().endswith((".exe", ".dll")):
                    scanned_binaries.append(r_path / f)

        all_required_dlls: Set[str] = set()
        missing_deps: Dict[str, MissingDependency] = {}

        for b_path in scanned_binaries:
            if not pefile:
                continue

            try:
                pe = pefile.PE(str(b_path), fast_load=True)
                pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
                is_64bit = pe.FILE_HEADER.Machine == 0x8664

                if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        if not entry.dll:
                            continue
                        dll_name = entry.dll.decode("utf-8", errors="ignore").lower()
                        if dll_name in DEPENDENCY_PACKAGES:
                            all_required_dlls.add(dll_name)
                            if not self._is_dll_present_on_host(dll_name, is_64bit):
                                if dll_name not in missing_deps:
                                    pkg_info = DEPENDENCY_PACKAGES[dll_name]
                                    installer_hint = pkg_info["installer_hint"]
                                    matched_installer = redist_map.get(installer_hint)

                                    inst_path = matched_installer.file_path if matched_installer else None
                                    cmd = None
                                    if matched_installer:
                                        cmd = f'"{matched_installer.file_path}" {matched_installer.recommended_silent_args}'

                                    missing_deps[dll_name] = MissingDependency(
                                        dll_name=dll_name,
                                        required_by=b_path.name,
                                        package_name=pkg_info["package"],
                                        installer_path=inst_path,
                                        install_command=cmd,
                                    )
                pe.close()
            except Exception:
                continue

        return RuntimeAuditReport(
            game_dir=str(self.game_dir),
            scanned_binaries_count=len(scanned_binaries),
            required_dlls=sorted(list(all_required_dlls)),
            missing_dependencies=list(missing_deps.values()),
            discovered_redists=discovered_redists,
            is_ready_to_play=len(missing_deps) == 0,
        )
