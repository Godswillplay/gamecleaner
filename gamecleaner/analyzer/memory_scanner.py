"""
Runtime Memory Scanner & Loaded Module Auditor.
Inspects running game process memory and loaded dynamic link libraries (DLLs) via psutil
and Windows Win32 API ctypes. Audits for:
- Unauthorized DLL injections from %TEMP%, %APPDATA%, and Downloads
- Unsigned and suspicious DLLs mapped into process address space
- Malicious injection hooks (e.g. detour hooks on WinSock send/recv, crypto miners)
- Sideloaded DLL verification (e.g. version.dll / dxgi.dll in game dir vs malicious injection)
Produces structured MemoryAuditReport dossiers. Cross-platform safe and fully mockable.
"""
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Set, Tuple, Union

try:
    import psutil
except ImportError:
    psutil = None  # type: ignore

try:
    import pefile
except ImportError:
    pefile = None  # type: ignore

from gamecleaner.analyzer.threat_rules import ThreatCategory, ThreatSeverity
from gamecleaner.analyzer.pe_scanner import check_authenticode_signature
from gamecleaner.analyzer.sideload_auditor import KNOWN_SIDELOAD_TARGETS, KNOWN_MOD_SIGNATURES


# Known WinSock API names frequently targeted by malicious network detour hooks
WINSOCK_HOOK_APIS: Set[str] = {
    "send",
    "recv",
    "wsasend",
    "wsarecv",
    "wsasendto",
    "wsarecvfrom",
    "connect",
    "wsaconnect",
    "bind",
}

# Known hook and detour library naming signatures
HOOK_LIBRARY_PATTERNS: Set[str] = {
    "detours",
    "minhook",
    "easyhook",
    "ws2_32_hook",
    "wsock_hook",
    "sockspy",
    "sockhook",
    "net_hook",
    "apihook",
    "inlinehook",
    "proxy_hook",
    "winsock_hook",
    "ws2detour",
}

# Cryptocurrency miner signatures in loaded modules
CRYPTO_MINER_KEYWORDS: Set[str] = {
    "xmrig",
    "stratum",
    "cryptonight",
    "minergate",
    "c3pool",
    "ethermine",
    "libmicrohttpd",
    "cpuminer",
    "monero",
    "nicehash",
    "nanopool",
    "xmrpool",
    "hashvault",
    "2miners",
    "crypto-pool",
}


@dataclass
class ModuleInfo:
    """Represents a module (DLL/EXE) mapped into process address space."""

    name: str
    path: str = ""
    base_address: Optional[int] = None
    size: Optional[int] = None
    is_signed: Optional[bool] = None
    signature_status: str = "Unknown"
    sha256: Optional[str] = None
    hook_indicators: List[str] = field(default_factory=list)
    is_system_module: bool = False
    is_in_game_dir: bool = False
    is_in_untrusted_dir: bool = False
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "path": self.path,
            "base_address": hex(self.base_address) if self.base_address is not None else None,
            "size": self.size,
            "is_signed": self.is_signed,
            "signature_status": self.signature_status,
            "sha256": self.sha256,
            "hook_indicators": self.hook_indicators,
            "is_system_module": self.is_system_module,
            "is_in_game_dir": self.is_in_game_dir,
            "is_in_untrusted_dir": self.is_in_untrusted_dir,
            "description": self.description,
        }


@dataclass
class SuspiciousModule:
    """Represents a suspicious or malicious module detected in memory."""

    name: str
    path: str
    threat_category: str
    severity: str
    reasons: List[str]
    signature_status: str = "Unknown"
    base_address: Optional[str] = None
    sha256: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "path": self.path,
            "threat_category": self.threat_category,
            "severity": self.severity,
            "reasons": self.reasons,
            "signature_status": self.signature_status,
            "base_address": self.base_address,
            "sha256": self.sha256,
        }


@dataclass
class MemoryAuditReport:
    """Structured memory security audit report for a running game process."""

    pid: int
    process_name: str
    modules_scanned: int
    suspicious_modules: List[SuspiciousModule]
    threat_level: str
    recommendations: List[str]
    game_dir: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def is_safe(self) -> bool:
        """Returns True if threat level is CLEAN or LOW and no suspicious modules detected."""
        return self.threat_level in (ThreatSeverity.CLEAN.value, ThreatSeverity.LOW.value) and len(self.suspicious_modules) == 0

    @property
    def has_critical_threat(self) -> bool:
        """Returns True if CRITICAL severity threats (e.g. miners or malicious detours) are detected."""
        return self.threat_level == ThreatSeverity.CRITICAL.value

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pid": self.pid,
            "process_name": self.process_name,
            "modules_scanned": self.modules_scanned,
            "suspicious_modules": [m.to_dict() for m in self.suspicious_modules],
            "threat_level": self.threat_level,
            "recommendations": self.recommendations,
            "game_dir": self.game_dir,
            "timestamp": self.timestamp,
            "is_safe": self.is_safe,
            "has_critical_threat": self.has_critical_threat,
        }

    def summary_markdown(self) -> str:
        """Formats the audit report as GitHub-style Markdown."""
        lines = [
            f"# Memory Security Audit Report: {self.process_name} (PID: {self.pid})",
            f"**Audit Timestamp:** {self.timestamp}  ",
            f"**Modules Scanned:** {self.modules_scanned}  ",
            f"**Overall Threat Level:** `{self.threat_level}`  ",
            f"**Verdict:** {'SAFE' if self.is_safe else 'ALERT - THREATS DETECTED'}\n",
        ]

        if self.suspicious_modules:
            lines.append("## Suspicious Loaded Modules\n")
            lines.append("| Module Name | Severity | Category | Reasons | Path |")
            lines.append("| :--- | :---: | :---: | :--- | :--- |")
            for sm in self.suspicious_modules:
                reasons_str = "; ".join(sm.reasons)
                lines.append(f"| `{sm.name}` | **{sm.severity}** | {sm.threat_category} | {reasons_str} | `{sm.path}` |")
            lines.append("")

        lines.append("## Security Recommendations\n")
        for rec in self.recommendations:
            lines.append(f"- {rec}")

        return "\n".join(lines)


class MemoryScanner:
    """
    Audits the memory space and mapped modules of running game processes.
    Cross-platform safe, resilient, and mockable.
    """

    def __init__(self, game_dir: Optional[Union[str, Path]] = None) -> None:
        self.game_dir = Path(game_dir).resolve() if game_dir else None

        # Resolve standard Windows system directories
        system_root_env = os.environ.get("SystemRoot", r"C:\Windows")
        self.system_root = Path(system_root_env).resolve()
        self.system32 = (self.system_root / "System32").resolve()
        self.syswow64 = (self.system_root / "SysWOW64").resolve()
        self.winsxs = (self.system_root / "WinSxS").resolve()
        self.systemapps = (self.system_root / "SystemApps").resolve()

        # Resolve untrusted user directories
        self.untrusted_dirs: List[Tuple[str, Path]] = []
        temp_dir = os.environ.get("TEMP") or os.environ.get("TMP")
        if temp_dir:
            self.untrusted_dirs.append(("TEMP", Path(temp_dir).resolve()))

        appdata = os.environ.get("APPDATA")
        if appdata:
            self.untrusted_dirs.append(("APPDATA", Path(appdata).resolve()))

        localappdata = os.environ.get("LOCALAPPDATA")
        if localappdata:
            self.untrusted_dirs.append(("LOCALAPPDATA", Path(localappdata).resolve()))

        user_home = Path.home().resolve()
        downloads_dir = user_home / "Downloads"
        if downloads_dir.exists():
            self.untrusted_dirs.append(("DOWNLOADS", downloads_dir))

    def is_windows_system_path(self, path: Union[str, Path]) -> bool:
        """Determines if a given DLL path resides within a trusted Windows system directory."""
        if not path:
            return False

        # Exclude Windows\Temp explicitly
        p_str = str(path).replace("/", "\\").lower()
        if "\\windows\\temp\\" in p_str:
            return False

        try:
            norm_path = Path(path).resolve()
            for sys_dir in (self.system32, self.syswow64, self.winsxs, self.systemapps):
                if sys_dir == norm_path or sys_dir in norm_path.parents:
                    return True
        except Exception:
            pass

        # String fallback for cross-platform/synthetic paths
        if "\\windows\\system32\\" in p_str or "\\windows\\syswow64\\" in p_str or "\\windows\\winsxs\\" in p_str or "\\windows\\systemapps\\" in p_str:
            return True
        return False

    def is_inside_game_dir(self, path: Union[str, Path], game_dir: Optional[Path] = None) -> bool:
        """Checks if a path is inside the game folder."""
        target_dir = game_dir or self.game_dir
        if not target_dir or not path:
            return False
        try:
            p_res = Path(path).resolve()
            g_res = target_dir.resolve()
            return p_res == g_res or g_res in p_res.parents
        except Exception:
            return False

    def check_untrusted_location(
        self,
        path: Union[str, Path],
        game_dir: Optional[Path] = None,
    ) -> Tuple[bool, str]:
        """
        Detects if a module is loaded from an unauthorized user directory
        such as %TEMP%, %APPDATA%, %LOCALAPPDATA%, or Downloads.
        """
        if not path:
            return False, ""

        # If file is explicitly part of the declared game_dir, do not treat game_dir root as untrusted
        if self.is_inside_game_dir(path, game_dir):
            return False, ""

        try:
            p_res = Path(path).resolve()
            for label, udir in self.untrusted_dirs:
                if udir == p_res or udir in p_res.parents:
                    return True, label
        except Exception:
            pass

        # String regex check (handles synthetic test paths and cross-platform paths)
        p_str = str(path).replace("/", "\\").lower()
        if "\\appdata\\local\\temp\\" in p_str or "\\temp\\" in p_str or "\\tmp\\" in p_str:
            return True, "TEMP"
        if "\\appdata\\roaming\\" in p_str:
            return True, "APPDATA"
        if "\\appdata\\local\\" in p_str:
            return True, "LOCALAPPDATA"
        if "\\downloads\\" in p_str:
            return True, "DOWNLOADS"

        return False, ""

    def check_signature(self, file_path: str) -> str:
        """
        Cryptographically verifies the Authenticode signature of a DLL on disk.
        Returns 'Valid', 'NotSigned', 'HashMismatch', 'NotTrusted', or 'Unknown'.
        """
        if not file_path or not os.path.exists(file_path):
            return "Unknown"
        try:
            return check_authenticode_signature(Path(file_path))
        except Exception:
            return "Unknown"

    def check_malicious_hooks(
        self,
        module: ModuleInfo,
    ) -> Tuple[bool, List[str], str, str]:
        """
        Checks for known malicious injection hooks:
        - Detour hooks into WinSock send/recv
        - Cryptocurrency miners
        Returns: (is_malicious, reasons, threat_category, threat_severity)
        """
        # Trusted Windows system binaries (in System32/SysWOW64) are not malicious detours
        if self.is_windows_system_path(module.path):
            return False, [], ThreatCategory.BENIGN.value, ThreatSeverity.CLEAN.value

        reasons: List[str] = []
        name_lower = module.name.lower()
        path_lower = module.path.lower()

        # 1. Check for Cryptocurrency Mining DLLs
        for kw in CRYPTO_MINER_KEYWORDS:
            if kw in name_lower or kw in path_lower or any(kw in ind.lower() for ind in module.hook_indicators):
                reasons.append(f"Loaded module matches known cryptocurrency miner signature: '{kw}'")
                return True, reasons, ThreatCategory.COINMINER.value, ThreatSeverity.CRITICAL.value

        # 2. Check for Known Hook / Detour Libraries
        for pattern in HOOK_LIBRARY_PATTERNS:
            if pattern in name_lower or any(pattern in ind.lower() for ind in module.hook_indicators):
                reasons.append(f"Detour / memory injection hook library detected: '{module.name}' (signature: '{pattern}')")

        # 3. Check for WinSock Socket Detour Hooks (send/recv/WSASend/WSARecv)
        is_sock_hook = False
        for ind in module.hook_indicators:
            ind_lower = ind.lower()
            if any(api in ind_lower for api in WINSOCK_HOOK_APIS):
                reasons.append(f"WinSock socket hook pattern detected: '{ind}'")
                is_sock_hook = True

        # Check export/import heuristics if file is accessible on disk and pefile available
        if pefile and module.path and os.path.exists(module.path):
            try:
                pe = pefile.PE(module.path, fast_load=True)
                pe.parse_data_directories(directories=[
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                ])
                # Check exports for hook trampolines or detour prefixes
                if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                        exp_name = exp.name.decode(errors="ignore").lower() if exp.name else ""
                        if any(hk in exp_name for hk in ("detour", "hook", "trampoline", "minhook")):
                            reasons.append(f"Module exports inline hook symbol: '{exp_name}'")
                        if exp_name in WINSOCK_HOOK_APIS:
                            reasons.append(f"Module proxies/hooks WinSock API export: '{exp_name}'")
                            is_sock_hook = True

                # Check imports for detour APIs
                if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                    for imp_desc in pe.DIRECTORY_ENTRY_IMPORT:
                        dll_name = imp_desc.dll.decode(errors="ignore").lower() if imp_desc.dll else ""
                        if dll_name in ("ws2_32.dll", "wsock32.dll"):
                            for imp in imp_desc.imports:
                                imp_name = imp.name.decode(errors="ignore").lower() if imp.name else ""
                                if imp_name in ("send", "recv", "wsasend", "wsarecv", "connect"):
                                    # If also named like a hook or in untrusted location
                                    if any(p in name_lower for p in HOOK_LIBRARY_PATTERNS):
                                        reasons.append(f"Hooks WinSock '{imp_name}' in external DLL '{module.name}'")
                                        is_sock_hook = True
            except Exception:
                pass

        if reasons:
            cat = ThreatCategory.INJECTION.value if not is_sock_hook else ThreatCategory.INJECTION.value
            return True, reasons, cat, ThreatSeverity.CRITICAL.value

        return False, [], ThreatCategory.BENIGN.value, ThreatSeverity.CLEAN.value

    def check_sideload_status(
        self,
        module: ModuleInfo,
        game_dir: Optional[Path] = None,
    ) -> Tuple[bool, List[str], str, str]:
        """
        Audits sideload-prone Windows system DLLs (version.dll, dxgi.dll, winhttp.dll, etc.).
        - If loaded from System32/SysWOW64 -> Clean legitimate Windows system DLL.
        - If loaded from game_dir -> Check if known mod loader (ReShade/BepInEx/SpecialK) vs unknown proxy.
        - If loaded from outside System32 and outside game_dir -> Severe unauthorized sideload injection.
        """
        name_lower = module.name.lower()
        if name_lower not in KNOWN_SIDELOAD_TARGETS:
            return False, [], ThreatCategory.BENIGN.value, ThreatSeverity.CLEAN.value

        target_game_dir = game_dir or self.game_dir

        # 1. Legitimate Windows system directory
        if self.is_windows_system_path(module.path):
            return False, [], ThreatCategory.BENIGN.value, ThreatSeverity.CLEAN.value

        # 2. Inside Game Folder
        if self.is_inside_game_dir(module.path, target_game_dir):
            # Check for legitimate mod frameworks
            framework_detected = None
            for framework, sigs in KNOWN_MOD_SIGNATURES.items():
                if any(s in module.path.lower() or s in module.description.lower() for s in sigs):
                    framework_detected = framework
                    break

            if framework_detected:
                return (
                    False,
                    [f"Legitimate game mod framework proxy: {framework_detected} ({module.name})"],
                    ThreatCategory.BENIGN.value,
                    ThreatSeverity.LOW.value,
                )
            else:
                return (
                    True,
                    [f"Sideloaded DLL proxy in game directory: '{module.name}' (Custom hook or crack loader)"],
                    ThreatCategory.HACKTOOL_CRACK.value,
                    ThreatSeverity.MEDIUM.value,
                )

        # 3. Neither System32 nor Game Directory: Hostile sideload injection!
        reasons = [
            f"Unauthorized DLL search-order hijacking: '{module.name}' loaded from third-party path '{module.path}' outside game and system directories"
        ]
        return True, reasons, ThreatCategory.INJECTION.value, ThreatSeverity.CRITICAL.value

    def get_loaded_modules_win32(self, pid: int) -> List[ModuleInfo]:
        """
        Enumerates loaded modules of a process via Windows Win32 API ctypes
        using CreateToolhelp32Snapshot, Module32FirstW, and Module32NextW.
        """
        modules: List[ModuleInfo] = []
        if os.name != "nt":
            return modules

        import ctypes
        from ctypes import wintypes

        TH32CS_SNAPMODULE = 0x00000008
        TH32CS_SNAPMODULE32 = 0x00000010
        INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

        class MODULEENTRY32W(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("th32ModuleID", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("GlblcntUsage", wintypes.DWORD),
                ("ProccntUsage", wintypes.DWORD),
                ("modBaseAddr", ctypes.c_void_p),
                ("modBaseSize", wintypes.DWORD),
                ("hModule", wintypes.HMODULE),
                ("szModule", wintypes.WCHAR * 256),
                ("szExePath", wintypes.WCHAR * 260),
            ]

        kernel32 = ctypes.windll.kernel32
        h_snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
        if h_snapshot == INVALID_HANDLE_VALUE:
            return modules

        try:
            entry = MODULEENTRY32W()
            entry.dwSize = ctypes.sizeof(MODULEENTRY32W)

            if kernel32.Module32FirstW(h_snapshot, ctypes.byref(entry)):
                while True:
                    mod_name = str(entry.szModule)
                    mod_path = str(entry.szExePath)
                    mod_base = entry.modBaseAddr
                    mod_size = entry.modBaseSize

                    modules.append(
                        ModuleInfo(
                            name=mod_name,
                            path=mod_path,
                            base_address=mod_base,
                            size=mod_size,
                        )
                    )

                    if not kernel32.Module32NextW(h_snapshot, ctypes.byref(entry)):
                        break
        finally:
            kernel32.CloseHandle(h_snapshot)

        return modules

    def get_loaded_modules_psutil(self, pid: int) -> List[ModuleInfo]:
        """
        Enumerates mapped memory files and DLLs of a process using psutil.
        """
        modules: List[ModuleInfo] = []
        if not psutil:
            return modules

        try:
            proc = psutil.Process(pid)
            # Memory maps return mapped libraries and binary sections
            maps = proc.memory_maps(grouped=False)
            seen_paths: Set[str] = set()

            for m in maps:
                path = m.path
                if not path or path in seen_paths:
                    continue
                seen_paths.add(path)
                p = Path(path)
                if p.suffix.lower() in (".dll", ".exe", ".pyd", ".so"):
                    modules.append(
                        ModuleInfo(
                            name=p.name,
                            path=str(p),
                            size=getattr(m, "rss", None),
                        )
                    )
        except Exception:
            pass

        return modules

    def get_loaded_modules(self, pid: int) -> List[ModuleInfo]:
        """
        Queries loaded modules for process PID using Win32 API with psutil fallback.
        """
        modules: List[ModuleInfo] = []
        if os.name == "nt":
            try:
                modules = self.get_loaded_modules_win32(pid)
            except Exception:
                modules = []

        if not modules:
            modules = self.get_loaded_modules_psutil(pid)

        return modules

    def scan_modules(
        self,
        modules: List[Union[ModuleInfo, Dict[str, Any]]],
        pid: int = 0,
        process_name: str = "UnknownProcess.exe",
        game_dir: Optional[Union[str, Path]] = None,
    ) -> MemoryAuditReport:
        """
        Performs memory security audit on a list of modules.
        Completely deterministic and mockable for cross-platform unit testing.
        """
        effective_game_dir = Path(game_dir).resolve() if game_dir else self.game_dir
        suspicious_list: List[SuspiciousModule] = []
        max_severity = ThreatSeverity.CLEAN

        normalized_modules: List[ModuleInfo] = []
        for m in modules:
            if isinstance(m, dict):
                norm = ModuleInfo(
                    name=m.get("name", ""),
                    path=m.get("path", ""),
                    base_address=m.get("base_address"),
                    size=m.get("size"),
                    is_signed=m.get("is_signed"),
                    signature_status=m.get("signature_status", "Unknown"),
                    sha256=m.get("sha256"),
                    hook_indicators=m.get("hook_indicators", []),
                    description=m.get("description", ""),
                )
            else:
                norm = m
            normalized_modules.append(norm)

        for mod in normalized_modules:
            reasons: List[str] = []
            mod_threat_category = ThreatCategory.BENIGN.value
            mod_severity = ThreatSeverity.CLEAN

            # 1. Update basic status flags
            is_sys = self.is_windows_system_path(mod.path)
            mod.is_system_module = is_sys
            mod.is_in_game_dir = self.is_inside_game_dir(mod.path, effective_game_dir)

            # Check untrusted user directories (%TEMP%, %APPDATA%, Downloads)
            is_untrusted, untrusted_type = self.check_untrusted_location(mod.path, effective_game_dir)
            mod.is_in_untrusted_dir = is_untrusted

            # 2. Check for Malicious Hooks / Crypto Miners
            is_hook, hook_reasons, hook_cat, hook_sev = self.check_malicious_hooks(mod)
            if is_hook:
                reasons.extend(hook_reasons)
                mod_threat_category = hook_cat
                mod_severity = ThreatSeverity(hook_sev)

            # 3. Check for Unauthorized DLL Injection from %TEMP% / %APPDATA% / Downloads
            if is_untrusted:
                reasons.append(
                    f"Unauthorized DLL injection: loaded from untrusted user directory ({untrusted_type}): '{mod.path}'"
                )
                if mod_severity == ThreatSeverity.CLEAN:
                    mod_threat_category = ThreatCategory.INJECTION.value
                    mod_severity = ThreatSeverity.HIGH

            # 4. Check Sideloaded DLL Verification (version.dll, dxgi.dll, etc.)
            is_sideload, sideload_reasons, sideload_cat, sideload_sev = self.check_sideload_status(mod, effective_game_dir)
            if is_sideload:
                reasons.extend(sideload_reasons)
                if ThreatSeverity(sideload_sev).value == ThreatSeverity.CRITICAL.value or mod_severity == ThreatSeverity.CLEAN:
                    mod_threat_category = sideload_cat
                    mod_severity = ThreatSeverity(sideload_sev)

            # 5. Check Signature Status for Non-System Modules
            sig_status = mod.signature_status
            if sig_status == "Unknown" and mod.path and os.path.exists(mod.path):
                sig_status = self.check_signature(mod.path)
                mod.signature_status = sig_status

            if not is_sys and not mod.is_in_game_dir:
                # External module loaded into process
                if sig_status in ("NotSigned", "HashMismatch", "NotTrusted"):
                    reasons.append(
                        f"Unsigned / untrusted external DLL mapped into address space (signature: {sig_status})"
                    )
                    if mod_severity in (ThreatSeverity.CLEAN, ThreatSeverity.LOW):
                        mod_threat_category = ThreatCategory.INJECTION.value
                        mod_severity = ThreatSeverity.HIGH

            # If any threat reasons were flagged, register as suspicious module
            if reasons and mod_severity != ThreatSeverity.CLEAN:
                # Update report-wide maximum severity
                if self._severity_rank(mod_severity) > self._severity_rank(max_severity):
                    max_severity = ThreatSeverity(mod_severity) if not isinstance(mod_severity, ThreatSeverity) else mod_severity

                suspicious_list.append(
                    SuspiciousModule(
                        name=mod.name,
                        path=mod.path,
                        threat_category=mod_threat_category,
                        severity=mod_severity.value,
                        reasons=reasons,
                        signature_status=sig_status,
                        base_address=hex(mod.base_address) if mod.base_address is not None else None,
                        sha256=mod.sha256,
                    )
                )

        # Generate contextual recommendations
        recommendations = self._generate_recommendations(
            pid=pid,
            process_name=process_name,
            threat_level=max_severity,
            suspicious_modules=suspicious_list,
        )

        return MemoryAuditReport(
            pid=pid,
            process_name=process_name,
            modules_scanned=len(normalized_modules),
            suspicious_modules=suspicious_list,
            threat_level=max_severity.value,
            recommendations=recommendations,
            game_dir=str(effective_game_dir) if effective_game_dir else None,
        )

    def scan_process(
        self,
        pid: int,
        game_dir: Optional[Union[str, Path]] = None,
    ) -> MemoryAuditReport:
        """
        Performs live memory audit of a running process given its PID.
        Gracefully handles process termination or permission denials.
        """
        process_name = f"PID_{pid}"
        if psutil:
            try:
                proc = psutil.Process(pid)
                process_name = proc.name()
            except Exception:
                pass

        modules = self.get_loaded_modules(pid)
        return self.scan_modules(
            modules=modules,
            pid=pid,
            process_name=process_name,
            game_dir=game_dir,
        )

    def find_game_processes(self, game_name_or_dir: Optional[Union[str, Path]] = None) -> List[Dict[str, Any]]:
        """
        Discovers running game processes matching a name, executable path, or directory.
        """
        matches: List[Dict[str, Any]] = []
        if not psutil:
            return matches

        match_str = str(game_name_or_dir).lower() if game_name_or_dir else ""

        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                p_name = (proc.info.get("name") or "").lower()
                p_exe = (proc.info.get("exe") or "").lower()

                if match_str:
                    if match_str in p_name or match_str in p_exe:
                        matches.append(proc.info)
                else:
                    matches.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return matches

    @staticmethod
    def _severity_rank(sev: Union[ThreatSeverity, str]) -> int:
        val = sev.value if isinstance(sev, ThreatSeverity) else str(sev).upper()
        ranks = {
            "CLEAN": 0,
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }
        return ranks.get(val, 0)

    def _generate_recommendations(
        self,
        pid: int,
        process_name: str,
        threat_level: ThreatSeverity,
        suspicious_modules: List[SuspiciousModule],
    ) -> List[str]:
        recommendations: List[str] = []

        if threat_level == ThreatSeverity.CRITICAL:
            recommendations.append(
                f"IMMEDIATE ACTION REQUIRED: Terminate hostile game process '{process_name}' (PID: {pid})."
            )
            recommendations.append(
                "Isolate discovered injected DLL binaries and move them into .gamecleaner_quarantine/."
            )
            recommendations.append(
                "Apply Windows Firewall outbound isolation script to prevent C2 network exfiltration."
            )
            recommendations.append(
                "Enable Windows Exploit Protection Process Shield (DisallowChildProcessCreation) to block sub-process droppers."
            )
        elif threat_level == ThreatSeverity.HIGH:
            recommendations.append(
                f"Investigate unauthorized DLL injections mapped into '{process_name}' (PID: {pid})."
            )
            recommendations.append(
                "Audit unsigned binaries loaded from %TEMP%, %APPDATA%, or Downloads directories."
            )
            recommendations.append(
                "Verify whether these external DLLs were injected by third-party cheats or hostile malware."
            )
        elif threat_level == ThreatSeverity.MEDIUM:
            recommendations.append(
                "Review sideloaded proxy DLLs inside the game folder (e.g. version.dll / dxgi.dll)."
            )
            recommendations.append(
                "If not an intentional mod loader (ReShade/BepInEx), replace with clean Goldberg emulator."
            )
        else:
            recommendations.append(
                f"Memory space of '{process_name}' (PID: {pid}) appears clean. No malicious hooks or unauthorized injections detected."
            )

        return recommendations
