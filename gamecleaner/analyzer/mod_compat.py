"""
Mod Compatibility & Framework Auditor: Detects, validates, and audits popular PC game mod frameworks:
- ReShade (Direct3D/OpenGL shader injector)
- Special K (DirectX/Vulkan render injector & frame pacer)
- Script Extenders (SKSE64, F4SE, OBSE, NVSE)
- BepInEx / Unity Doorstop (Unity Mono/IL2CPP plugin framework)
- ASI Loaders & Plugins (dinput8, dsound, Ultimate ASI Loader)

Audits for mod conflict chains (e.g. ReShade proxying through Special K or vice-versa),
validates genuine user mods, and catches malware masquerading as mod loaders.
"""
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import pefile
except ImportError:
    pefile = None

from gamecleaner.analyzer.threat_rules import ThreatCategory, ThreatSeverity


class ModFrameworkType(Enum):
    RESHADE = "ReShade"
    SPECIAL_K = "Special K"
    SCRIPT_EXTENDER = "Script Extender"
    BEPINEX = "BepInEx"
    ASI_LOADER = "ASI Loader"
    UNKNOWN_MOD = "Unknown Mod Framework"


# Suspicious APIs indicating hostile malware capabilities rather than genuine graphics mods
SUSPICIOUS_MALWARE_APIS = {
    # Process injection / memory manipulation
    "VirtualAllocEx": "Remote process memory allocation (Injection)",
    "WriteProcessMemory": "Cross-process memory writing (Process Hollowing)",
    "CreateRemoteThread": "Remote thread execution (Code Injection)",
    "NtCreateThreadEx": "Low-level remote thread creation (Stealth Injection)",
    # Infostealer / credential theft
    "CryptUnprotectData": "Decryption of protected user secrets & browser cookies",
    "VaultOpenVault": "Windows Vault password extraction",
    "CredEnumerateA": "Windows Credential Manager harvesting",
    "CredEnumerateW": "Windows Credential Manager harvesting",
    # Hidden network beacons / downloaders
    "InternetOpenA": "Outbound HTTP connection initialized",
    "InternetOpenW": "Outbound HTTP connection initialized",
    "URLDownloadToFileA": "Silent executable payload downloader",
    "URLDownloadToFileW": "Silent executable payload downloader",
    # Surveillance
    "SetWindowsHookExA": "Global system keylogger/hook",
    "SetWindowsHookExW": "Global system keylogger/hook",
}


@dataclass
class ModChainLink:
    """Represents a proxy loading chain between mod frameworks."""
    source_dll: str
    target_dll: str
    chain_type: str
    is_target_present: bool
    status: str  # HEALTHY, BROKEN_TARGET_MISSING, CIRCULAR
    config_file: Optional[str] = None


@dataclass
class ModConflict:
    """Represents a conflict or misconfiguration in mod setup."""
    conflict_type: str  # SLOT_CONTENTION, BROKEN_CHAIN, ARCH_MISMATCH, CIRCULAR_CHAIN
    description: str
    involved_files: List[Path] = field(default_factory=list)
    resolution_advice: str = ""


@dataclass
class ModDetection:
    """Detailed finding of a mod framework detection and authenticity evaluation."""
    framework: ModFrameworkType
    name: str
    file_path: Path
    relative_path: str
    is_genuine: bool = False
    is_malware_impersonation: bool = False
    confidence: float = 0.0  # 0.0 to 1.0
    architecture: str = "x64"
    companion_files: List[Path] = field(default_factory=list)
    companion_directories: List[Path] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    hostile_indicators: List[str] = field(default_factory=list)
    sha256: str = ""
    severity: ThreatSeverity = ThreatSeverity.LOW
    threat_category: ThreatCategory = ThreatCategory.BENIGN

    def to_dict(self) -> Dict[str, Any]:
        return {
            "framework": self.framework.value,
            "name": self.name,
            "file_path": str(self.file_path),
            "relative_path": self.relative_path,
            "is_genuine": self.is_genuine,
            "is_malware_impersonation": self.is_malware_impersonation,
            "confidence": round(self.confidence, 2),
            "architecture": self.architecture,
            "companion_files": [str(c) for c in self.companion_files],
            "companion_directories": [str(d) for d in self.companion_directories],
            "indicators": self.indicators,
            "hostile_indicators": self.hostile_indicators,
            "sha256": self.sha256,
            "severity": self.severity.value,
            "threat_category": self.threat_category.value,
        }


@dataclass
class ModAuditReport:
    """Consolidated audit of game modifications, authenticity, and conflicts."""
    game_dir: Path
    detected_mods: List[ModDetection] = field(default_factory=list)
    conflicts: List[ModConflict] = field(default_factory=list)
    chains: List[ModChainLink] = field(default_factory=list)
    genuine_mods_count: int = 0
    impersonation_threats_count: int = 0
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "game_dir": str(self.game_dir),
            "detected_mods": [m.to_dict() for m in self.detected_mods],
            "conflicts": [
                {
                    "conflict_type": c.conflict_type,
                    "description": c.description,
                    "involved_files": [str(p) for p in c.involved_files],
                    "resolution_advice": c.resolution_advice,
                }
                for c in self.conflicts
            ],
            "chains": [
                {
                    "source_dll": ch.source_dll,
                    "target_dll": ch.target_dll,
                    "chain_type": ch.chain_type,
                    "is_target_present": ch.is_target_present,
                    "status": ch.status,
                    "config_file": ch.config_file,
                }
                for ch in self.chains
            ],
            "genuine_mods_count": self.genuine_mods_count,
            "impersonation_threats_count": self.impersonation_threats_count,
            "summary": self.summary,
        }


class ModCompatibilityAuditor:
    """
    Analyzes game folders for genuine mod frameworks, evaluates their security
    and authenticity, audits proxy chains, and detects malware impersonation.
    """

    KNOWN_MOD_HOOK_NAMES = {
        "dxgi.dll",
        "d3d11.dll",
        "d3d9.dll",
        "d3d12.dll",
        "opengl32.dll",
        "dinput8.dll",
        "dsound.dll",
        "winhttp.dll",
        "version.dll",
        "specialk64.dll",
        "specialk32.dll",
        "specialk.dll",
        "reshade64.dll",
        "reshade32.dll",
    }

    FRAMEWORK_SIGNATURES: Dict[ModFrameworkType, List[bytes]] = {
        ModFrameworkType.RESHADE: [
            b"reshade", b"crosire", b"reshade.me", b"effectruntime",
            b"reshade-shaders", b"reshadepreset",
        ],
        ModFrameworkType.SPECIAL_K: [
            b"special k", b"kaldaien", b"specialk64", b"specialk32",
            b"specialk.dll", b"special k - ", b"specialk.ini",
        ],
        ModFrameworkType.SCRIPT_EXTENDER: [
            b"skse", b"nvse", b"f4se", b"obse", b"silverlock",
            b"ianpatt", b"behippo", b"skseplugin", b"f4seplugin",
        ],
        ModFrameworkType.BEPINEX: [
            b"bepinex", b"doorstop", b"unitydoorstop", b"0harmony",
            b"bepinex.core", b"bepinex.preloader",
        ],
        ModFrameworkType.ASI_LOADER: [
            b"ultimate asi loader", b"thirteenag", b"silentpatch",
            b"dinput8 wrapper", b"asi loader",
        ],
    }

    def __init__(self, game_dir: Path):
        self.game_dir = Path(game_dir).resolve()

    def _detect_pe_arch(self, path: Path) -> str:
        """Reads PE header machine type directly."""
        try:
            with open(path, "rb") as f:
                mz = f.read(2)
                if mz == b"MZ":
                    f.seek(0x3C)
                    pe_offset = int.from_bytes(f.read(4), "little")
                    f.seek(pe_offset + 4)
                    machine = int.from_bytes(f.read(2), "little")
                    if machine == 0x8664:
                        return "x64"
                    elif machine == 0x014C:
                        return "x86"
        except Exception:
            pass
        return "x64" if "64" in path.name.lower() else "x86"

    def _inspect_pe_imports(self, data: bytes) -> List[str]:
        """Extracts imports to detect suspicious / hostile APIs."""
        hostile_imports = []
        if pefile and data.startswith(b"MZ"):
            try:
                pe = pefile.PE(data=data, fast_load=True)
                pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
                if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        for imp in entry.imports:
                            if imp.name:
                                func_name = imp.name.decode("utf-8", errors="ignore")
                                if func_name in SUSPICIOUS_MALWARE_APIS:
                                    hostile_imports.append(f"{func_name}: {SUSPICIOUS_MALWARE_APIS[func_name]}")
                pe.close()
            except Exception:
                pass

        # Fallback raw byte inspection for suspicious APIs if PE import table wasn't populated
        if not hostile_imports:
            for api_name, desc in SUSPICIOUS_MALWARE_APIS.items():
                if api_name.encode("utf-8") in data:
                    hostile_imports.append(f"{api_name}: {desc}")

        return hostile_imports

    def inspect_dll(self, dll_path: Path, nearby_exes: Optional[List[Path]] = None) -> Optional[ModDetection]:
        """
        Inspects a single DLL to determine if it belongs to a mod framework,
        whether it is genuine or malware masquerading as a mod.
        """
        dll_name_lower = dll_path.name.lower()
        if dll_name_lower not in self.KNOWN_MOD_HOOK_NAMES and not dll_name_lower.endswith(".asi"):
            # Check if it has a script extender naming pattern (e.g. skse64_1_*.dll)
            if not any(dll_name_lower.startswith(prefix) for prefix in ("skse", "f4se", "obse", "nvse")):
                return None

        # Read binary data
        try:
            content = dll_path.read_bytes()
            sha256 = hashlib.sha256(content).hexdigest()
        except Exception:
            return None

        content_lower = content.lower()
        arch = self._detect_pe_arch(dll_path)
        folder = dll_path.parent

        # 1. Discover Companion Files & Directories
        companion_files: List[Path] = []
        companion_dirs: List[Path] = []

        # ReShade companions
        for rf in ["ReShade.ini", "reshade.ini", "ReShadeGUI.ini", "ReShadePreset.ini", "ReShade.fx"]:
            probe = folder / rf
            if probe.exists():
                companion_files.append(probe)
        for rd in ["reshade-shaders", "Shaders", "Textures"]:
            probe = folder / rd
            if probe.exists() and probe.is_dir():
                companion_dirs.append(probe)

        # Special K companions
        for sf in ["SpecialK.ini", "specialk.ini", "dxgi.ini", "d3d11.ini"]:
            probe = folder / sf
            if probe.exists() and probe not in companion_files:
                companion_files.append(probe)
        for sd in ["SpecialK", "SK_Res"]:
            probe = folder / sd
            if probe.exists() and probe.is_dir():
                companion_dirs.append(probe)

        # BepInEx companions
        for bf in ["doorstop_config.ini", "doorstop_version.ini"]:
            probe = folder / bf
            if probe.exists():
                companion_files.append(probe)
        bep_dir = folder / "BepInEx"
        if bep_dir.exists() and bep_dir.is_dir():
            companion_dirs.append(bep_dir)
            if (bep_dir / "core" / "BepInEx.Core.dll").exists():
                companion_files.append(bep_dir / "core" / "BepInEx.Core.dll")

        # ASI Loader companions
        for af in ["dinput8.ini"]:
            probe = folder / af
            if probe.exists():
                companion_files.append(probe)
        for ad in ["scripts", "plugins"]:
            probe = folder / ad
            if probe.exists() and probe.is_dir():
                companion_dirs.append(probe)
                for asi_file in probe.glob("*.asi"):
                    companion_files.append(asi_file)

        # Script Extender companions
        for se_exe in ["skse64_loader.exe", "skse_loader.exe", "f4se_loader.exe", "obse_loader.exe", "nvse_loader.exe"]:
            probe = folder / se_exe
            if probe.exists():
                companion_files.append(probe)
        for data_sub in ["Data/SKSE", "Data/F4SE", "Data/OBSE", "Data/NVSE"]:
            probe = folder / data_sub
            if probe.exists() and probe.is_dir():
                companion_dirs.append(probe)

        # 2. Check for Framework Signatures in Binary
        matched_framework: Optional[ModFrameworkType] = None
        matched_sigs: List[str] = []

        for fw, sigs in self.FRAMEWORK_SIGNATURES.items():
            for sig in sigs:
                if sig in content_lower:
                    matched_framework = fw
                    matched_sigs.append(sig.decode("utf-8", errors="ignore"))

        # Fallback framework detection based on companions or naming
        if not matched_framework:
            if "reshade" in dll_name_lower or any("reshade" in c.name.lower() for c in companion_files + companion_dirs):
                matched_framework = ModFrameworkType.RESHADE
            elif "specialk" in dll_name_lower or (folder / "SpecialK.ini").exists() or (folder / "dxgi.ini").exists():
                matched_framework = ModFrameworkType.SPECIAL_K
            elif (folder / "doorstop_config.ini").exists() or (folder / "BepInEx").exists():
                matched_framework = ModFrameworkType.BEPINEX
            elif dll_name_lower.endswith(".asi") or (folder / "scripts").exists() or (folder / "dinput8.ini").exists():
                matched_framework = ModFrameworkType.ASI_LOADER
            elif any(dll_name_lower.startswith(p) for p in ("skse", "f4se", "obse", "nvse")):
                matched_framework = ModFrameworkType.SCRIPT_EXTENDER
            elif dll_name_lower in ("dxgi.dll", "d3d11.dll", "opengl32.dll", "d3d9.dll", "d3d12.dll"):
                # Commonly impersonated graphics hooks (ReShade / Special K)
                matched_framework = ModFrameworkType.RESHADE
            elif dll_name_lower in ("winhttp.dll", "version.dll"):
                matched_framework = ModFrameworkType.BEPINEX
            elif dll_name_lower in ("dinput8.dll", "dsound.dll"):
                matched_framework = ModFrameworkType.ASI_LOADER

        # If still no framework matched, check if it's a known hook file with no mod evidence
        if not matched_framework:
            return None

        # 3. Security Inspection: Check for Hostile APIs
        hostile_apis = self._inspect_pe_imports(content)

        # 4. Authenticity & Confidence Evaluation
        confidence = 0.0
        indicators: List[str] = []

        if matched_sigs:
            confidence += 0.5
            indicators.append(f"Authentic binary signatures detected: {', '.join(matched_sigs[:3])}")

        if companion_files or companion_dirs:
            confidence += 0.4
            comp_names = [c.name for c in companion_files[:2]] + [d.name for d in companion_dirs[:2]]
            indicators.append(f"Matching companion configurations/assets found: {', '.join(comp_names)}")

        # Check export table for genuine graphics or loader exports
        has_valid_exports = False
        if pefile and content.startswith(b"MZ"):
            try:
                pe = pefile.PE(data=content, fast_load=False)
                if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                    exp_names = [e.name.decode("utf-8", errors="ignore").lower() for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name]
                    if matched_framework in (ModFrameworkType.RESHADE, ModFrameworkType.SPECIAL_K):
                        if any(x in exp_names for x in ("createdxgifactory", "d3d11createdevice", "directinput8create")):
                            has_valid_exports = True
                    elif matched_framework == ModFrameworkType.SCRIPT_EXTENDER:
                        if any("plugin" in x for x in exp_names):
                            has_valid_exports = True
                pe.close()
            except Exception:
                pass

        if has_valid_exports:
            confidence += 0.2
            indicators.append("Verified standard graphics/loader exports in export table.")

        confidence = min(1.0, confidence)

        # 5. Malware Impersonation Determination
        is_malware = False
        if hostile_apis:
            # If hostile APIs are present and confidence in legitimate mod is weak or contains dangerous injection
            has_injection = any("Injection" in ha for ha in hostile_apis)
            has_stealer = any("secrets" in ha or "password" in ha for ha in hostile_apis)
            if has_stealer or (has_injection and confidence < 0.6):
                is_malware = True
            elif has_injection and not (matched_framework in (ModFrameworkType.SPECIAL_K, ModFrameworkType.BEPINEX)):
                # ReShade should not perform remote process injection
                is_malware = True

        # If zero authentic signatures, zero companions, but hostile APIs exist -> definite malware
        if not matched_sigs and not companion_files and not companion_dirs and hostile_apis:
            is_malware = True

        if is_malware:
            severity = ThreatSeverity.CRITICAL if any("password" in h or "secrets" in h for h in hostile_apis) else ThreatSeverity.HIGH
            category = ThreatCategory.INJECTION
            is_genuine = False
        else:
            is_genuine = confidence >= 0.4
            severity = ThreatSeverity.LOW if is_genuine else ThreatSeverity.MEDIUM
            category = ThreatCategory.HACKTOOL_CRACK if is_genuine else ThreatCategory.INJECTION

        rel_path = str(dll_path.relative_to(self.game_dir)) if self.game_dir in dll_path.parents else dll_path.name

        return ModDetection(
            framework=matched_framework,
            name=f"{matched_framework.value} ({dll_path.name})",
            file_path=dll_path,
            relative_path=rel_path,
            is_genuine=is_genuine,
            is_malware_impersonation=is_malware,
            confidence=confidence,
            architecture=arch,
            companion_files=companion_files,
            companion_directories=companion_dirs,
            indicators=indicators,
            hostile_indicators=hostile_apis,
            sha256=sha256,
            severity=severity,
            threat_category=category,
        )

    def audit_chains(self) -> List[ModChainLink]:
        """
        Audits proxy loading chains (e.g. Special K proxying ReShade or ReShade proxying original DLLs).
        """
        chains: List[ModChainLink] = []

        # 1. Inspect Special K configs: dxgi.ini, SpecialK.ini, d3d11.ini
        for ini_name in ["dxgi.ini", "SpecialK.ini", "d3d11.ini"]:
            for ini_path in self.game_dir.rglob(ini_name):
                if ".gamecleaner" in str(ini_path):
                    continue
                try:
                    content = ini_path.read_text(encoding="utf-8", errors="ignore")
                    # Search for [Import.ReShade] or [Import.*]
                    import_pattern = re.compile(
                        r"""\[Import\.([^\]]+)\][^\[]*?Filename\s*=\s*([^\r\n;]+)""",
                        re.IGNORECASE | re.DOTALL,
                    )
                    for match in import_pattern.finditer(content):
                        role = match.group(1).strip()
                        target_filename = match.group(2).strip().strip('"').strip("'")
                        target_path = ini_path.parent / target_filename
                        is_present = target_path.exists()
                        status = "HEALTHY" if is_present else "BROKEN_TARGET_MISSING"

                        # Check circular chain
                        if target_filename.lower() == ini_path.stem.lower() + ".dll":
                            status = "CIRCULAR"

                        chains.append(ModChainLink(
                            source_dll=f"{ini_path.stem}.dll",
                            target_dll=target_filename,
                            chain_type=f"SpecialK_Import_{role}",
                            is_target_present=is_present,
                            status=status,
                            config_file=str(ini_path.name),
                        ))
                except Exception:
                    continue

        # 2. Inspect BepInEx Unity Doorstop configs: doorstop_config.ini
        for door_ini in self.game_dir.rglob("doorstop_config.ini"):
            if ".gamecleaner" in str(door_ini):
                continue
            try:
                content = door_ini.read_text(encoding="utf-8", errors="ignore")
                target_match = re.search(r"""targetAssembly\s*=\s*([^\r\n;]+)""", content, re.IGNORECASE)
                enabled_match = re.search(r"""enabled\s*=\s*(true|1)""", content, re.IGNORECASE)
                if target_match and enabled_match:
                    target_assembly = target_match.group(1).strip()
                    target_path = (door_ini.parent / target_assembly).resolve()
                    is_present = target_path.exists()
                    chains.append(ModChainLink(
                        source_dll="winhttp.dll",
                        target_dll=target_assembly,
                        chain_type="UnityDoorstop_Assembly",
                        is_target_present=is_present,
                        status="HEALTHY" if is_present else "BROKEN_TARGET_MISSING",
                        config_file=str(door_ini.name),
                    ))
            except Exception:
                continue

        # 3. Inspect ReShade proxy configurations
        for reshade_ini in self.game_dir.rglob("ReShade.ini"):
            if ".gamecleaner" in str(reshade_ini):
                continue
            try:
                content = reshade_ini.read_text(encoding="utf-8", errors="ignore")
                proxy_match = re.search(r"""(?:TargetName|ProxyLibrary)\s*=\s*([^\r\n;]+)""", content, re.IGNORECASE)
                if proxy_match:
                    target_lib = proxy_match.group(1).strip()
                    is_present = (reshade_ini.parent / target_lib).exists()
                    chains.append(ModChainLink(
                        source_dll="ReShade",
                        target_dll=target_lib,
                        chain_type="ReShade_Proxy",
                        is_target_present=is_present,
                        status="HEALTHY" if is_present else "BROKEN_TARGET_MISSING",
                        config_file=str(reshade_ini.name),
                    ))
            except Exception:
                continue

        return chains

    def find_conflicts(
        self,
        detected_mods: List[ModDetection],
        chains: List[ModChainLink],
    ) -> List[ModConflict]:
        """
        Audits for mod collision / contention, broken proxy chains, or architectural mismatches.
        """
        conflicts: List[ModConflict] = []

        # 1. Check for Broken Proxy Chains
        for ch in chains:
            if ch.status == "BROKEN_TARGET_MISSING":
                conflicts.append(ModConflict(
                    conflict_type="BROKEN_CHAIN",
                    description=(
                        f"Proxy load chain broken: '{ch.source_dll}' is configured via {ch.config_file} "
                        f"to load '{ch.target_dll}', but '{ch.target_dll}' was not found on disk."
                    ),
                    involved_files=[self.game_dir / ch.source_dll],
                    resolution_advice=f"Place the required library '{ch.target_dll}' in the game folder or remove the chain import in {ch.config_file}.",
                ))
            elif ch.status == "CIRCULAR":
                conflicts.append(ModConflict(
                    conflict_type="CIRCULAR_CHAIN",
                    description=f"Circular DLL proxy loop detected: '{ch.source_dll}' imports itself as '{ch.target_dll}'. This causes infinite recursion crashes.",
                    involved_files=[self.game_dir / ch.source_dll],
                    resolution_advice=f"Fix the chain import in {ch.config_file} to point to the actual target library (e.g. ReShade64.dll).",
                ))

        # 2. Check for Slot Contention (Collision on dxgi.dll / d3d11.dll)
        # Group mods by directory
        dir_mods: Dict[Path, List[ModDetection]] = {}
        for m in detected_mods:
            dir_mods.setdefault(m.file_path.parent, []).append(m)

        for d_path, mods in dir_mods.items():
            # If both ReShade and Special K are present in the same directory claiming the same hook
            hook_names = [m.file_path.name.lower() for m in mods]
            has_reshade = any(m.framework == ModFrameworkType.RESHADE for m in mods)
            has_specialk = any(m.framework == ModFrameworkType.SPECIAL_K for m in mods)

            if has_reshade and has_specialk:
                # Check if a healthy chain links them
                is_chained = any(
                    ch.status == "HEALTHY" and (
                        "reshade" in ch.target_dll.lower() or "specialk" in ch.target_dll.lower()
                    )
                    for ch in chains
                )
                if not is_chained:
                    conflicts.append(ModConflict(
                        conflict_type="SLOT_CONTENTION",
                        description=(
                            "ReShade and Special K both coexist in the same directory without a configured proxy chain. "
                            "DirectX hooks will collide or crash during render initialization."
                        ),
                        involved_files=[m.file_path for m in mods if m.framework in (ModFrameworkType.RESHADE, ModFrameworkType.SPECIAL_K)],
                        resolution_advice=(
                            "Configure Special K to load ReShade: rename ReShade to 'ReShade64.dll' and add "
                            "[Import.ReShade] Architecture=x64 Filename=ReShade64.dll to dxgi.ini."
                        ),
                    ))

        return conflicts

    def audit(self) -> ModAuditReport:
        """
        Executes a complete mod compatibility and authenticity audit on the target game directory.
        """
        report = ModAuditReport(game_dir=self.game_dir)
        if not self.game_dir.exists():
            report.summary = f"Directory not found: {self.game_dir}"
            return report

        # Discover all DLLs in game directory
        for p in self.game_dir.rglob("*.dll"):
            if ".gamecleaner" in str(p) or ".quarantine" in str(p):
                continue
            detection = self.inspect_dll(p)
            if detection:
                report.detected_mods.append(detection)
                if detection.is_genuine and not detection.is_malware_impersonation:
                    report.genuine_mods_count += 1
                elif detection.is_malware_impersonation:
                    report.impersonation_threats_count += 1

        # Also inspect script extender loaders (*.exe)
        for se_exe in self.game_dir.glob("*_loader.exe"):
            stem_lower = se_exe.stem.lower()
            if any(stem_lower.startswith(p) for p in ("skse", "f4se", "obse", "nvse")):
                report.detected_mods.append(ModDetection(
                    framework=ModFrameworkType.SCRIPT_EXTENDER,
                    name=f"Script Extender Loader ({se_exe.name})",
                    file_path=se_exe,
                    relative_path=str(se_exe.relative_to(self.game_dir)),
                    is_genuine=True,
                    is_malware_impersonation=False,
                    confidence=1.0,
                    architecture="x64" if "64" in stem_lower else "x86",
                    indicators=["Official Script Extender loader binary."],
                    severity=ThreatSeverity.LOW,
                    threat_category=ThreatCategory.BENIGN,
                ))
                report.genuine_mods_count += 1

        # Audit Chains and Conflicts
        report.chains = self.audit_chains()
        report.conflicts = self.find_conflicts(report.detected_mods, report.chains)

        # Build summary
        summary_lines = []
        if report.detected_mods:
            summary_lines.append(f"Detected {len(report.detected_mods)} mod components ({report.genuine_mods_count} genuine, {report.impersonation_threats_count} hostile impersonations).")
        else:
            summary_lines.append("No game mod frameworks detected.")

        if report.chains:
            healthy_c = sum(1 for c in report.chains if c.status == "HEALTHY")
            summary_lines.append(f"Proxy chains: {len(report.chains)} total ({healthy_c} healthy).")

        if report.conflicts:
            summary_lines.append(f"Mod conflicts: {len(report.conflicts)} issues requiring remediation.")

        report.summary = " ".join(summary_lines)
        return report
