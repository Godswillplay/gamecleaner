"""
DLL Sideloading & Proxy Hijack Auditor: Detects DLL search-order hijacking and proxy DLLs in game directories.
Distinguishes between legitimate game mod loaders (ReShade, BepInEx, SpecialK) and malicious proxy droppers.
"""
from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import re
from typing import Dict, List, Optional, Set

try:
    import pefile
except ImportError:
    pefile = None

from gamecleaner.analyzer.threat_rules import ThreatCategory, ThreatSeverity


# Windows system DLLs that should normally reside in System32, frequently hijacked in game folders
KNOWN_SIDELOAD_TARGETS = {
    "version.dll",
    "winhttp.dll",
    "winmm.dll",
    "d3d11.dll",
    "dxgi.dll",
    "dwmapi.dll",
    "cryptbase.dll",
    "dbghelp.dll",
    "uxtheme.dll",
    "msvcp140.dll",
    "vcruntime140.dll",
    "xinput1_3.dll",
    "xinput1_4.dll",
    "dsound.dll",
    "opengl32.dll",
    "userenv.dll",
    "wtsapi32.dll",
    "msimg32.dll",
    "midimap.dll",
    "dinput8.dll",
}

# Signatures and string markers of known legitimate game modding frameworks
KNOWN_MOD_SIGNATURES: Dict[str, List[str]] = {
    "ReShade": ["reshade", "crosire", "reshade.me", "effectruntime"],
    "SpecialK": ["special k", "kaldaien", "specialk64", "specialk32"],
    "BepInEx": ["bepinex", "doorstop", "mono-2.0", "unitycrashhandler"],
    "MelonLoader": ["melonloader", "melonbootstrap"],
    "UE4SS": ["ue4ss", "unreal engine scripting system", "modloader"],
    "Script Extender (xSE)": ["skse", "nvse", "f4se", "obse", "silverlock"],
    "DXVK": ["dxvk", "doitsujin", "vulkan-1.dll"],
}

# Suspicious export forwarding or API patterns in proxy DLLs
SUSPICIOUS_PROXY_APIS = {
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtCreateThreadEx",
    "InternetOpenA",
    "InternetOpenW",
    "HttpOpenRequestA",
    "HttpOpenRequestW",
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    "GetKeyboardState",
    "GetAsyncKeyState",
    "SetWindowsHookExA",
    "SetWindowsHookExW",
}


@dataclass
class SideloadFinding:
    file_path: str
    dll_name: str
    target_exe: Optional[str] = None
    is_legitimate_mod: bool = False
    mod_framework: Optional[str] = None
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    threat_category: ThreatCategory = ThreatCategory.INJECTION
    description: str = ""
    suspicious_indicators: List[str] = field(default_factory=list)
    sha256: str = ""


class SideloadAuditor:
    """Audits game folders for DLL search order hijacking and proxy DLLs."""

    def __init__(self, root_dir: Path):
        self.root_dir = Path(root_dir)

    def scan_file(self, dll_path: Path, nearby_exes: List[Path]) -> Optional[SideloadFinding]:
        """Inspects a single DLL to determine if it is a sideloaded system DLL or mod loader."""
        dll_name = dll_path.name.lower()
        if dll_name not in KNOWN_SIDELOAD_TARGETS:
            return None

        # Calculate sha256
        sha256 = ""
        try:
            content = dll_path.read_bytes()
            sha256 = hashlib.sha256(content).hexdigest()
        except Exception:
            content = b""

        content_lower = content.lower() if content else b""

        # Check associated target EXE in same folder
        target_exe_name = nearby_exes[0].name if nearby_exes else None

        indicators: List[str] = []
        if pefile and content:
            try:
                pe = pefile.PE(data=content, fast_load=True)
                pe.parse_data_directories(
                    directories=[
                        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
                    ]
                )
                if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        for imp in entry.imports:
                            if imp.name:
                                func_name = imp.name.decode("utf-8", errors="ignore")
                                if func_name in SUSPICIOUS_PROXY_APIS:
                                    indicators.append(f"Suspicious API import: {func_name}")
                pe.close()
            except Exception:
                pass

        # Fallback inspection for suspicious APIs in raw bytes if PE imports directory wasn't parsed
        if not indicators and content:
            for api in SUSPICIOUS_PROXY_APIS:
                if api.encode("utf-8") in content:
                    indicators.append(f"Suspicious API import: {api}")

        # Use ModCompatibilityAuditor to evaluate genuine mod vs malware impersonation
        try:
            from gamecleaner.analyzer.mod_compat import ModCompatibilityAuditor, ModFrameworkType
            mod_auditor = ModCompatibilityAuditor(self.root_dir)
            mod_detection = mod_auditor.inspect_dll(dll_path, nearby_exes)
        except Exception:
            mod_detection = None

        if mod_detection:
            if mod_detection.is_malware_impersonation:
                return SideloadFinding(
                    file_path=str(dll_path),
                    dll_name=dll_path.name,
                    target_exe=target_exe_name,
                    is_legitimate_mod=False,
                    mod_framework=mod_detection.framework.value,
                    severity=mod_detection.severity,
                    threat_category=mod_detection.threat_category,
                    description=(
                        f"Hostile DLL Search-Order Hijack / Malware Masquerading: '{dll_path.name}' mimics "
                        f"{mod_detection.framework.value} but exhibits hostile payload capabilities: {', '.join(mod_detection.hostile_indicators[:2])}"
                    ),
                    suspicious_indicators=mod_detection.hostile_indicators,
                    sha256=sha256,
                )
            elif mod_detection.is_genuine:
                return SideloadFinding(
                    file_path=str(dll_path),
                    dll_name=dll_path.name,
                    target_exe=target_exe_name,
                    is_legitimate_mod=True,
                    mod_framework=mod_detection.framework.value,
                    severity=ThreatSeverity.LOW,
                    threat_category=ThreatCategory.HACKTOOL_CRACK,
                    description=f"Legitimate game enhancement/mod framework detected: {mod_detection.framework.value} (Proxying {dll_path.name})",
                    suspicious_indicators=indicators,
                    sha256=sha256,
                )

        # Fallback check for known mod framework signatures
        matched_framework = None
        for framework, signatures in KNOWN_MOD_SIGNATURES.items():
            for sig in signatures:
                if sig.encode("utf-8") in content_lower:
                    matched_framework = framework
                    break
            if matched_framework:
                break

        if matched_framework:
            return SideloadFinding(
                file_path=str(dll_path),
                dll_name=dll_path.name,
                target_exe=target_exe_name,
                is_legitimate_mod=True,
                mod_framework=matched_framework,
                severity=ThreatSeverity.LOW,
                threat_category=ThreatCategory.HACKTOOL_CRACK,
                description=f"Legitimate game enhancement/mod framework detected: {matched_framework} (Proxying {dll_path.name})",
                suspicious_indicators=indicators,
                sha256=sha256,
            )

        # Unidentified system DLL proxy in application root
        if indicators:
            severity = ThreatSeverity.HIGH
            threat_cat = ThreatCategory.INJECTION
            desc = (
                f"Suspicious DLL Search-Order Hijack: System DLL '{dll_path.name}' placed next to {target_exe_name or 'game executable'} "
                f"with hostile capabilities: {', '.join(indicators[:3])}"
            )
        else:
            severity = ThreatSeverity.MEDIUM
            threat_cat = ThreatCategory.INJECTION
            desc = (
                f"Potential DLL Search-Order Hijack: Standard Windows library '{dll_path.name}' exists locally in game folder. "
                "May be a custom game hook, crack proxy, or sideloaded loader."
            )

        return SideloadFinding(
            file_path=str(dll_path),
            dll_name=dll_path.name,
            target_exe=target_exe_name,
            is_legitimate_mod=False,
            mod_framework=None,
            severity=severity,
            threat_category=threat_cat,
            description=desc,
            suspicious_indicators=indicators,
            sha256=sha256,
        )

    def audit(self) -> List[SideloadFinding]:
        """Scans the directory tree for all sideloaded system DLLs."""
        if not self.root_dir.exists():
            return []

        findings: List[SideloadFinding] = []

        # Find folders with EXEs
        folder_exes: Dict[Path, List[Path]] = {}
        for root, _, files in os.walk(self.root_dir):
            r_path = Path(root)
            if ".gamecleaner" in str(r_path) or ".quarantine" in str(r_path):
                continue
            exes = [r_path / f for f in files if f.lower().endswith(".exe")]
            if exes:
                folder_exes[r_path] = exes

        for root, _, files in os.walk(self.root_dir):
            r_path = Path(root)
            if ".gamecleaner" in str(r_path) or ".quarantine" in str(r_path):
                continue

            dlls = [r_path / f for f in files if f.lower().endswith(".dll")]
            nearby_exes = folder_exes.get(r_path, [])
            if not nearby_exes and r_path.parent in folder_exes:
                nearby_exes = folder_exes[r_path.parent]

            for dll in dlls:
                res = self.scan_file(dll, nearby_exes)
                if res:
                    findings.append(res)

        return findings
