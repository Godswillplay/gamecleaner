"""
Game Crash Forensics & Event Log Diagnostics:
Inspects Windows Event Log (Application Error ID 1000, Windows Error Reporting ID 1001)
and Windows Error Reporting (.wer) crash dumps to diagnose game process failures.
Correlates crashes with common game repack failure causes:
- Missing Visual C++ or DirectX runtime DLLs
- Incompatible, missing, or corrupted Steam / EOS / Uplay emulator DLLs
- SteamStub DRM (.bind section) not unpacked
- Sideloaded DLL proxy crash or mod conflict
- Inbound Windows Firewall socket blocking on private network
- Architecture mismatch (32-bit vs 64-bit)
- Unsupported CPU instructions (AVX/SSE)
"""
from dataclasses import dataclass, field
from enum import Enum
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional, Set, Tuple, Union

try:
    import pefile
except ImportError:
    pefile = None

from gamecleaner.analyzer.steam_stub import SteamStubDetector


class CrashCauseCategory(str, Enum):
    MISSING_RUNTIME = "MISSING_RUNTIME"
    EMULATOR_INCOMPATIBILITY = "EMULATOR_INCOMPATIBILITY"
    STEAM_STUB_PACKED = "STEAM_STUB_PACKED"
    SIDELOAD_CONFLICT = "SIDELOAD_CONFLICT"
    FIREWALL_SOCKET_BLOCK = "FIREWALL_SOCKET_BLOCK"
    ARCH_MISMATCH = "ARCH_MISMATCH"
    ILLEGAL_INSTRUCTION = "ILLEGAL_INSTRUCTION"
    CPP_UNHANDLED_EXCEPTION = "CPP_UNHANDLED_EXCEPTION"
    ACCESS_VIOLATION_GENERAL = "ACCESS_VIOLATION_GENERAL"
    UNKNOWN = "UNKNOWN"


# Mapping of NTSTATUS / Win32 exception codes to human-readable names and explanations
KNOWN_EXCEPTIONS: Dict[str, Tuple[str, str]] = {
    "0xc0000005": (
        "STATUS_ACCESS_VIOLATION",
        "Access Violation: The process attempted to read or write memory at an unmapped, protected, or null address.",
    ),
    "0xc0000139": (
        "STATUS_ENTRYPOINT_NOT_FOUND",
        "Entry Point Not Found: A dynamic link library was loaded, but a referenced export function or ordinal was missing.",
    ),
    "0xc0000135": (
        "STATUS_DLL_NOT_FOUND",
        "DLL Not Found: A dependent dynamic link library required by the executable could not be located in the search path.",
    ),
    "0xc000001d": (
        "STATUS_ILLEGAL_INSTRUCTION",
        "Illegal Instruction: The processor attempted to execute an invalid or unsupported machine instruction (e.g. AVX/SSE4 on unsupported CPU or corrupted binary).",
    ),
    "0xc000007b": (
        "STATUS_INVALID_IMAGE_FORMAT",
        "Invalid Image Format: 32-bit (x86) and 64-bit (x64) architecture mismatch between executable and loaded DLLs, or corrupted PE binary header.",
    ),
    "0xc00000fd": (
        "STATUS_STACK_OVERFLOW",
        "Stack Overflow: The thread exhausted its reserved stack space, typically caused by infinite recursion or excessive stack allocations.",
    ),
    "0x80000003": (
        "STATUS_BREAKPOINT",
        "Breakpoint Trap: A software breakpoint (INT 3) or anti-debug verification trap was triggered.",
    ),
    "0xc0000008": (
        "STATUS_INVALID_HANDLE",
        "Invalid Handle: An operation was attempted using an invalid or already closed system handle.",
    ),
    "0xc0000409": (
        "STATUS_STACK_BUFFER_OVERRUN",
        "Stack Buffer Overrun: Security cookie check (/GS) failed or CRT abort() invoked to prevent control flow hijack.",
    ),
    "0xc0000025": (
        "STATUS_NONCONTINUABLE_EXCEPTION",
        "Non-continuable Exception: Code attempted to resume execution after a non-continuable exception occurred.",
    ),
    "0xe06d7363": (
        "STATUS_CPP_EXCEPTION",
        "Microsoft C++ Exception: An unhandled C++ exception was thrown and not caught by an active handler.",
    ),
    "0xc0000094": (
        "STATUS_INTEGER_DIVIDE_BY_ZERO",
        "Integer Divide by Zero: An arithmetic division by zero occurred.",
    ),
    "0xc0000096": (
        "STATUS_PRIVILEGED_INSTRUCTION",
        "Privileged Instruction: Process attempted to execute a ring-0 privileged CPU instruction from ring-3 user mode.",
    ),
}

# Known emulator DLLs
EMULATOR_MODULES: Set[str] = {
    "steam_api.dll",
    "steam_api64.dll",
    "steamclient.dll",
    "steamclient64.dll",
    "eossdk-win64-shipping.dll",
    "eossdk-win32-shipping.dll",
    "uplay_r1_loader64.dll",
    "uplay_r1_loader.dll",
    "emp.dll",
    "codex64.dll",
    "cream_api.dll",
    "goldberg.dll",
    "flt.dll",
    "rld.dll",
    "unarc.dll",
}

# Known runtime DLLs
RUNTIME_MODULES: Set[str] = {
    "vcruntime140.dll",
    "vcruntime140_1.dll",
    "msvcp140.dll",
    "msvcp140_1.dll",
    "msvcp140_2.dll",
    "msvcp140_codecvt_ids.dll",
    "msvcp120.dll",
    "msvcr120.dll",
    "msvcp110.dll",
    "msvcr110.dll",
    "msvcp100.dll",
    "msvcr100.dll",
    "d3dx9_42.dll",
    "d3dx9_43.dll",
    "d3dx10_43.dll",
    "d3dx11_43.dll",
    "d3dcompiler_43.dll",
    "d3dcompiler_47.dll",
    "xinput1_3.dll",
    "xinput1_4.dll",
    "xactengine3_7.dll",
    "openal32.dll",
    "mfc140u.dll",
}

# Known sideload / proxy DLLs
PROXY_MODULES: Set[str] = {
    "version.dll",
    "winhttp.dll",
    "dxgi.dll",
    "d3d11.dll",
    "d3d9.dll",
    "dwmapi.dll",
    "dinput8.dll",
    "reshade64.dll",
    "reshade32.dll",
    "binkw32.dll",
    "bink2w64.dll",
    "cryptbase.dll",
    "winmm.dll",
    "userenv.dll",
    "wtsapi32.dll",
}

# Windows networking socket DLLs
SOCKET_MODULES: Set[str] = {
    "ws2_32.dll",
    "wsock32.dll",
    "mswsock.dll",
}

# Windows core OS system DLLs
SYSTEM_MODULES: Set[str] = {
    "ntdll.dll",
    "kernel32.dll",
    "kernelbase.dll",
    "user32.dll",
    "gdi32.dll",
    "shell32.dll",
    "ole32.dll",
    "rpcrt4.dll",
    "comctl32.dll",
    "advapi32.dll",
    "imm32.dll",
}


def normalize_exception_code(val: Any) -> str:
    """Normalizes an exception code from integer, signed integer, or hex string into '0xXXXXXXXX' format."""
    if val is None:
        return "0x00000000"

    # If it's already an integer
    if isinstance(val, int):
        # Convert signed 32-bit negative (e.g. -1073741819) to unsigned hex
        unsigned = val & 0xFFFFFFFF
        return f"0x{unsigned:08x}"

    val_str = str(val).strip().lower()

    # If it matches hex notation
    if val_str.startswith("0x"):
        val_clean = val_str[2:]
        try:
            num = int(val_clean, 16)
            return f"0x{num:08x}"
        except ValueError:
            return val_str

    # Hex without prefix (e.g. 'c0000005')
    if len(val_str) == 8 and all(c in "0123456789abcdef" for c in val_str):
        return f"0x{val_str}"

    # Signed/unsigned decimal string (e.g. '-1073741819' or '3221225477')
    try:
        num = int(val_str)
        unsigned = num & 0xFFFFFFFF
        return f"0x{unsigned:08x}"
    except ValueError:
        pass

    # Fallback
    return val_str


@dataclass
class RemediationStep:
    """Actionable remediation step to fix the identified crash cause."""

    title: str
    description: str
    command: Optional[str] = None
    priority: int = 1  # 1 is highest priority
    automated: bool = True


@dataclass
class FaultingModule:
    """Metadata regarding the library or binary where the fatal fault occurred."""

    name: str
    path: Optional[str] = None
    version: Optional[str] = None
    is_system_dll: bool = False
    is_game_binary: bool = False
    is_emulator: bool = False
    is_runtime: bool = False
    is_proxy: bool = False

    @classmethod
    def classify(
        cls,
        name: str,
        path: Optional[str] = None,
        version: Optional[str] = None,
        app_name: Optional[str] = None,
    ) -> "FaultingModule":
        clean_name = Path(name).name.lower()
        clean_app = Path(app_name).name.lower() if app_name else ""

        is_game_binary = (
            clean_name == clean_app or clean_name.endswith(".exe")
        )
        is_emulator = clean_name in EMULATOR_MODULES
        is_runtime = clean_name in RUNTIME_MODULES
        is_proxy = clean_name in PROXY_MODULES
        is_system = clean_name in SYSTEM_MODULES or clean_name in SOCKET_MODULES

        return cls(
            name=name,
            path=path,
            version=version,
            is_system_dll=is_system,
            is_game_binary=is_game_binary,
            is_emulator=is_emulator,
            is_runtime=is_runtime,
            is_proxy=is_proxy,
        )


@dataclass
class CrashReport:
    """Structured diagnostic crash analysis report."""

    application_name: str
    faulting_module: FaultingModule
    exception_code: str
    exception_name: str
    exception_description: str
    fault_offset: str
    timestamp: str
    event_id: int
    source: str  # "EventLog", "WER", "Mock", "RawText"
    root_cause_category: str
    root_cause_description: str
    confidence: str  # "HIGH", "MEDIUM", "LOW"
    remediation_steps: List[RemediationStep] = field(default_factory=list)
    application_path: Optional[str] = None
    process_id: Optional[int] = None
    raw_details: Dict[str, Any] = field(default_factory=dict)


class CrashForensics:
    """
    Forensic analyzer for Windows Event Log (1000/1001) and WER crash dumps.
    Correlates game crash signatures with known repack and emulation failure causes.
    """

    def __init__(self, game_dir: Optional[Union[str, Path]] = None):
        self.game_dir = Path(game_dir) if game_dir else None

    # -------------------------------------------------------------------------
    # Correlation & Root Cause Analysis
    # -------------------------------------------------------------------------

    def correlate_root_cause(
        self,
        application_name: str,
        faulting_mod: FaultingModule,
        exception_code: str,
        fault_offset: str = "0x0",
        app_path: Optional[str] = None,
        raw_message: str = "",
        game_dir: Optional[Union[str, Path]] = None,
    ) -> Tuple[str, str, str, List[RemediationStep]]:
        """
        Determines the root cause of a crash and generates actionable remediation steps.
        Returns: (category, description, confidence, remediation_steps)
        """
        target_dir = Path(game_dir) if game_dir else self.game_dir
        clean_code = normalize_exception_code(exception_code)
        mod_name = Path(faulting_mod.name).name.lower()
        app_base = Path(application_name).name.lower()

        remediation_steps: List[RemediationStep] = []

        # 1. ARCHITECTURE MISMATCH (0xc000007b)
        if clean_code == "0xc000007b":
            cat = CrashCauseCategory.ARCH_MISMATCH.value
            desc = (
                "Architecture Mismatch (STATUS_INVALID_IMAGE_FORMAT): A 64-bit executable attempted "
                "to load a 32-bit DLL (or vice versa), or a critical runtime DLL is corrupted."
            )
            remediation_steps.append(
                RemediationStep(
                    title="Reinstall Visual C++ & DirectX All-In-One Runtimes",
                    description="Run dependency installer to restore matching 32-bit and 64-bit redistributable libraries.",
                    command=f'python -m gamecleaner.cli deps "{target_dir or "."}" --install' if target_dir else "python -m gamecleaner.cli deps . --install",
                    priority=1,
                )
            )
            remediation_steps.append(
                RemediationStep(
                    title="Audit Binary Architecture (Bitness)",
                    description="Ensure any manually replaced crack DLL (e.g. steam_api64.dll vs steam_api.dll) matches the executable bitness.",
                    command=f'python -m gamecleaner.cli replace-emu "{target_dir or "."}"' if target_dir else None,
                    priority=2,
                )
            )
            return cat, desc, "HIGH", remediation_steps

        # 2. MISSING RUNTIME (0xc0000135 or faulting module is a runtime DLL)
        if clean_code == "0xc0000135" or faulting_mod.is_runtime or mod_name in RUNTIME_MODULES:
            cat = CrashCauseCategory.MISSING_RUNTIME.value
            desc = (
                f"Missing or Incompatible Runtime Library: Crash occurred in or referencing '{faulting_mod.name}'. "
                "The game requires specific Microsoft Visual C++ or DirectX End-User runtimes."
            )
            remediation_steps.append(
                RemediationStep(
                    title="Silent Install Bundled Repack Runtimes",
                    description=f"Automatically detect and install silent redist packages (_CommonRedist/redist) required for '{mod_name}'.",
                    command=f'python -m gamecleaner.cli deps "{target_dir or "."}" --install' if target_dir else "python -m gamecleaner.cli deps . --install",
                    priority=1,
                )
            )
            remediation_steps.append(
                RemediationStep(
                    title="Install Visual C++ 2015-2022 All-in-One",
                    description="Download and install Microsoft Visual C++ 2015-2022 Redistributable (x86 and x64) from official Microsoft servers.",
                    command=None,
                    priority=2,
                    automated=False,
                )
            )
            return cat, desc, "HIGH", remediation_steps

        # 3. STEAM / EOS / UPLAY EMULATOR INCOMPATIBILITY OR CORRUPT CRACK
        if faulting_mod.is_emulator or mod_name in EMULATOR_MODULES:
            cat = CrashCauseCategory.EMULATOR_INCOMPATIBILITY.value
            if clean_code == "0xc0000139":
                desc = (
                    f"Emulator Entry Point Not Found: '{faulting_mod.name}' does not implement an export function "
                    "expected by the game's Steamworks/EOS SDK version (outdated crack emulator)."
                )
            elif clean_code == "0xc0000005":
                desc = (
                    f"Scene Crack / Emulator Memory Violation: '{faulting_mod.name}' crashed during initialization. "
                    "Commonly caused by missing 'steam_appid.txt', unhandled scene DRM hooks, or corrupted crack DLL."
                )
            else:
                desc = (
                    f"Crash in Game Emulator DLL '{faulting_mod.name}' with exception {clean_code}."
                )

            remediation_steps.append(
                RemediationStep(
                    title="Replace with Clean Open-Source Goldberg Emulator",
                    description="Swap the untrusted or outdated crack DLL with GameCleaner's verified Goldberg Steam emulator and auto-generate steam_appid.txt.",
                    command=f'python -m gamecleaner.cli replace-emu "{target_dir or "."}"' if target_dir else "python -m gamecleaner.cli replace-emu .",
                    priority=1,
                )
            )
            remediation_steps.append(
                RemediationStep(
                    title="Full Security & Emulator Pipeline",
                    description="Run full sanitization pipeline to mirror emulators to subdirectories (bin/x64/) and generate steam_interfaces.txt.",
                    command=f'python -m gamecleaner.cli clean-all "{target_dir or "."}"' if target_dir else "python -m gamecleaner.cli clean-all .",
                    priority=2,
                )
            )
            return cat, desc, "HIGH", remediation_steps

        # 4. STEAM STUB (.bind SECTION) NOT UNPACKED
        # When SteamStub is active, the game typically crashes with 0xc0000005 or 0x80000003
        # in the main game executable or ntdll right at launch, because the wrapper expects the Steam client.
        is_game_or_ntdll = faulting_mod.is_game_binary or mod_name in ("ntdll.dll", "kernelbase.dll")
        is_stub_candidate = is_game_or_ntdll and clean_code in ("0xc0000005", "0x80000003")

        # If game_dir or app_path is available, directly inspect binary for .bind section
        if is_stub_candidate and (app_path or target_dir):
            candidate_bin = None
            if app_path and Path(app_path).exists() and Path(app_path).is_file():
                candidate_bin = Path(app_path)
            elif target_dir and target_dir.exists():
                for exe in target_dir.rglob("*.exe"):
                    if exe.name.lower() == app_base:
                        candidate_bin = exe
                        break

            if candidate_bin and candidate_bin.exists():
                detector = SteamStubDetector(candidate_bin)
                stub_res = detector.scan()
                if stub_res.is_wrapped:
                    cat = CrashCauseCategory.STEAM_STUB_PACKED.value
                    desc = (
                        f"SteamStub DRM Wrapper Detected: '{candidate_bin.name}' contains an encrypted "
                        f"SteamStub section ('{stub_res.section_name}'). When launched with Goldberg emulator, "
                        "the encrypted entry point fails to unpack, triggering an immediate access violation."
                    )
                    remediation_steps.append(
                        RemediationStep(
                            title="Unpack SteamStub DRM with Steamless",
                            description=f"Unpack '{candidate_bin.name}' using Steamless CLI to strip the encrypted .bind stub and restore original entry point.",
                            command=f'python -m gamecleaner.cli steamless "{candidate_bin}"',
                            priority=1,
                        )
                    )
                    return cat, desc, "HIGH", remediation_steps

        # 5. SIDELOADED DLL PROXY CRASH OR MOD CONFLICT
        if faulting_mod.is_proxy or mod_name in PROXY_MODULES:
            cat = CrashCauseCategory.SIDELOAD_CONFLICT.value
            desc = (
                f"Sideloaded DLL Proxy Conflict: Crash occurred inside '{faulting_mod.name}'. "
                "A local graphics mod (ReShade/DXVK) or proxy DLL in the game directory failed to hook APIs or collided with the display driver."
            )
            remediation_steps.append(
                RemediationStep(
                    title="Audit Local Sideloaded DLLs",
                    description=f"Inspect '{mod_name}' and other local DLLs in the game folder to verify Authenticode signatures or proxy hooks.",
                    command=f'python -m gamecleaner.cli sideload "{target_dir or "."}"' if target_dir else "python -m gamecleaner.cli sideload .",
                    priority=1,
                )
            )
            remediation_steps.append(
                RemediationStep(
                    title="Temporarily Disable Proxy / Mod DLL",
                    description=f"Rename '{mod_name}' to '{mod_name}.disabled' to verify if the vanilla game launches cleanly.",
                    command=None,
                    priority=2,
                    automated=False,
                )
            )
            return cat, desc, "HIGH", remediation_steps

        # 6. INBOUND FIREWALL SOCKET BLOCKING ON PRIVATE NETWORK
        # Co-op / LAN games crashing in ws2_32.dll or aborting on socket bind
        if mod_name in SOCKET_MODULES or "bind" in raw_message.lower() or "socket" in raw_message.lower():
            cat = CrashCauseCategory.FIREWALL_SOCKET_BLOCK.value
            desc = (
                "Windows Firewall Socket Trap: Crash occurred during network socket binding. "
                "Windows Firewall created an Inbound Block rule (user clicked 'Cancel' on network prompt), "
                "causing listen()/bind() to fail fatally on game startup."
            )
            remediation_steps.append(
                RemediationStep(
                    title="Remediate Firewall Inbound Socket Block",
                    description="Remove restrictive inbound blocking rules and generate clean firewall rules for the game.",
                    command=f'python -m gamecleaner.cli run "{target_dir or "."}"' if target_dir else None,
                    priority=1,
                )
            )
            remediation_steps.append(
                RemediationStep(
                    title="Run Firewall Remediation Script as Admin",
                    description="Execute Fix_Firewall_And_Run.bat or Remove-NetFirewallRule in PowerShell.",
                    command=f'powershell -Command "Remove-NetFirewallRule -DisplayName \'{application_name}\'"',
                    priority=2,
                    automated=False,
                )
            )
            return cat, desc, "HIGH", remediation_steps

        # 7. ILLEGAL INSTRUCTION (0xc000001d)
        if clean_code == "0xc000001d":
            cat = CrashCauseCategory.ILLEGAL_INSTRUCTION.value
            desc = (
                "Illegal CPU Instruction (STATUS_ILLEGAL_INSTRUCTION): The executable attempted to run CPU instructions "
                "(such as AVX, AVX2, or SSE4.2) that are unsupported by the host processor, or the binary was corrupted."
            )
            remediation_steps.append(
                RemediationStep(
                    title="Verify Repack File Integrity",
                    description="Verify SHA-256 hashes of game binaries to rule out incomplete archive decompression or disk corruption.",
                    command=f'python -m gamecleaner.cli verify "{target_dir or "."}"' if target_dir else "python -m gamecleaner.cli verify .",
                    priority=1,
                )
            )
            return cat, desc, "MEDIUM", remediation_steps

        # 8. C++ UNHANDLED EXCEPTION (0xe06d7363)
        if clean_code == "0xe06d7363":
            cat = CrashCauseCategory.CPP_UNHANDLED_EXCEPTION.value
            desc = (
                "Unhandled Microsoft C++ Exception: The game or engine threw a runtime exception that was not caught. "
                "Often caused by missing config files, missing audio devices, or corrupt save data."
            )
            remediation_steps.append(
                RemediationStep(
                    title="Audit Missing Runtime Dependencies",
                    description="Verify Visual C++ runtimes are fully installed.",
                    command=f'python -m gamecleaner.cli deps "{target_dir or "."}" --install' if target_dir else None,
                    priority=1,
                )
            )
            return cat, desc, "MEDIUM", remediation_steps

        # 9. GENERAL ACCESS VIOLATION (0xc0000005)
        if clean_code == "0xc0000005":
            cat = CrashCauseCategory.ACCESS_VIOLATION_GENERAL.value
            desc = (
                f"Memory Access Violation: Fatal crash in '{faulting_mod.name}' at offset {fault_offset}. "
                "Process attempted to dereference a null pointer or access protected memory."
            )
            remediation_steps.append(
                RemediationStep(
                    title="Audit Binary & Emulators with GameCleaner",
                    description="Run full sanitization pipeline to eliminate corrupted scene crack hooks and restore clean emulators.",
                    command=f'python -m gamecleaner.cli clean-all "{target_dir or "."}"' if target_dir else "python -m gamecleaner.cli clean-all .",
                    priority=1,
                )
            )
            return cat, desc, "LOW", remediation_steps

        # 10. UNKNOWN / UNCLASSIFIED
        cat = CrashCauseCategory.UNKNOWN.value
        desc = f"Unclassified process crash in '{faulting_mod.name}' with exception code {clean_code} at offset {fault_offset}."
        remediation_steps.append(
            RemediationStep(
                title="Deep PE & Sideload Audit",
                description="Scan all binaries and libraries in the game directory for anomalies.",
                command=f'python -m gamecleaner.cli scan "{target_dir or "."}"' if target_dir else "python -m gamecleaner.cli scan .",
                priority=1,
            )
        )
        return cat, desc, "LOW", remediation_steps

    # -------------------------------------------------------------------------
    # Parsing Event Log (ID 1000 / 1001) Messages
    # -------------------------------------------------------------------------

    def parse_event_message(
        self,
        message: str,
        timestamp: str = "",
        event_id: int = 1000,
        source: str = "EventLog",
    ) -> Optional[CrashReport]:
        """
        Parses the text of a Windows Event ID 1000 ('Application Error') or ID 1001 ('Windows Error Reporting').
        """
        if not message or not isinstance(message, str):
            return None

        # Regex patterns for Event ID 1000 format
        app_match = re.search(r"Faulting application name:\s*([^,\r\n]+)", message, re.IGNORECASE)
        app_ver_match = re.search(r"Faulting application name:[^,\r\n]+,\s*version:\s*([^,\r\n]+)", message, re.IGNORECASE)
        mod_match = re.search(r"Faulting module name:\s*([^,\r\n]+)", message, re.IGNORECASE)
        mod_ver_match = re.search(r"Faulting module name:[^,\r\n]+,\s*version:\s*([^,\r\n]+)", message, re.IGNORECASE)
        code_match = re.search(r"Exception code:\s*([^,\r\n\s]+)", message, re.IGNORECASE)
        offset_match = re.search(r"Fault offset:\s*([^,\r\n\s]+)", message, re.IGNORECASE)
        app_path_match = re.search(r"Faulting application path:\s*([^\r\n]+)", message, re.IGNORECASE)
        mod_path_match = re.search(r"Faulting module path:\s*([^\r\n]+)", message, re.IGNORECASE)
        pid_match = re.search(r"Faulting process id:\s*([^,\r\n\s]+)", message, re.IGNORECASE)

        # Fallback to Event ID 1001 format (P1 = AppName, P4 = ModName, P7 = ExceptionCode, P8 = Offset)
        if not app_match:
            p1_match = re.search(r"P1:\s*([^\r\n]+)", message)
            p4_match = re.search(r"P4:\s*([^\r\n]+)", message)
            p7_match = re.search(r"P7:\s*([^\r\n]+)", message)
            p8_match = re.search(r"P8:\s*([^\r\n]+)", message)

            if p1_match:
                app_name = p1_match.group(1).strip()
                mod_name = p4_match.group(1).strip() if p4_match else app_name
                raw_code = p7_match.group(1).strip() if p7_match else "0xc0000005"
                fault_offset = p8_match.group(1).strip() if p8_match else "0x0"

                norm_code = normalize_exception_code(raw_code)
                exc_info = KNOWN_EXCEPTIONS.get(
                    norm_code,
                    ("UNKNOWN_EXCEPTION", f"Windows Exception Code {norm_code}"),
                )

                fault_mod = FaultingModule.classify(
                    name=mod_name,
                    app_name=app_name,
                )

                cat, desc, conf, steps = self.correlate_root_cause(
                    application_name=app_name,
                    faulting_mod=fault_mod,
                    exception_code=norm_code,
                    fault_offset=fault_offset,
                    raw_message=message,
                )

                return CrashReport(
                    application_name=app_name,
                    faulting_module=fault_mod,
                    exception_code=norm_code,
                    exception_name=exc_info[0],
                    exception_description=exc_info[1],
                    fault_offset=fault_offset,
                    timestamp=timestamp,
                    event_id=event_id,
                    source=source,
                    root_cause_category=cat,
                    root_cause_description=desc,
                    confidence=conf,
                    remediation_steps=steps,
                    raw_details={"raw_message": message},
                )

            return None

        app_name = app_match.group(1).strip()
        mod_name = mod_match.group(1).strip() if mod_match else app_name
        raw_code = code_match.group(1).strip() if code_match else "0xc0000005"
        fault_offset = offset_match.group(1).strip() if offset_match else "0x0"
        app_path = app_path_match.group(1).strip() if app_path_match else None
        mod_path = mod_path_match.group(1).strip() if mod_path_match else None
        mod_version = mod_ver_match.group(1).strip() if mod_ver_match else None

        pid = None
        if pid_match:
            try:
                pid_str = pid_match.group(1).strip()
                pid = int(pid_str, 16) if pid_str.startswith("0x") else int(pid_str)
            except ValueError:
                pass

        norm_code = normalize_exception_code(raw_code)
        exc_info = KNOWN_EXCEPTIONS.get(
            norm_code,
            ("UNKNOWN_EXCEPTION", f"Windows Exception Code {norm_code}"),
        )

        fault_mod = FaultingModule.classify(
            name=mod_name,
            path=mod_path,
            version=mod_version,
            app_name=app_name,
        )

        cat, desc, conf, steps = self.correlate_root_cause(
            application_name=app_name,
            faulting_mod=fault_mod,
            exception_code=norm_code,
            fault_offset=fault_offset,
            app_path=app_path,
            raw_message=message,
        )

        return CrashReport(
            application_name=app_name,
            faulting_module=fault_mod,
            exception_code=norm_code,
            exception_name=exc_info[0],
            exception_description=exc_info[1],
            fault_offset=fault_offset,
            timestamp=timestamp,
            event_id=event_id,
            source=source,
            root_cause_category=cat,
            root_cause_description=desc,
            confidence=conf,
            remediation_steps=steps,
            application_path=app_path,
            process_id=pid,
            raw_details={"raw_message": message},
        )

    # -------------------------------------------------------------------------
    # Parsing WER (.wer) Crash Dumps
    # -------------------------------------------------------------------------

    def parse_wer_content(
        self,
        content: str,
        filename: str = "",
        source: str = "WER",
    ) -> Optional[CrashReport]:
        """Parses the text contents of a Windows Error Reporting (.wer) file."""
        if not content:
            return None

        lines = content.splitlines()
        props: Dict[str, str] = {}
        for line in lines:
            line_str = line.strip()
            if "=" in line_str:
                k, v = line_str.split("=", 1)
                props[k.strip().lower()] = v.strip()

        # Extract signatures
        # Sig[0] = AppName, Sig[3] = ModName, Sig[6] = ExceptionCode, Sig[7] = Offset
        app_name = (
            props.get("sig[0].value")
            or props.get("appname")
            or props.get("targetapp")
            or props.get("p1")
            or ""
        )
        mod_name = (
            props.get("sig[3].value")
            or props.get("modname")
            or props.get("faultmodulename")
            or props.get("p4")
            or app_name
        )
        raw_code = (
            props.get("sig[6].value")
            or props.get("exceptioncode")
            or props.get("p7")
            or "0xc0000005"
        )
        fault_offset = (
            props.get("sig[7].value")
            or props.get("faultoffset")
            or props.get("offset")
            or props.get("p8")
            or "0x0"
        )
        timestamp = props.get("eventtime", "")
        app_path = props.get("ui[2]") or props.get("apppath")

        if not app_name:
            return None

        norm_code = normalize_exception_code(raw_code)
        exc_info = KNOWN_EXCEPTIONS.get(
            norm_code,
            ("UNKNOWN_EXCEPTION", f"Windows Exception Code {norm_code}"),
        )

        fault_mod = FaultingModule.classify(
            name=mod_name,
            path=props.get("modpath"),
            version=props.get("sig[4].value"),
            app_name=app_name,
        )

        cat, desc, conf, steps = self.correlate_root_cause(
            application_name=app_name,
            faulting_mod=fault_mod,
            exception_code=norm_code,
            fault_offset=fault_offset,
            app_path=app_path,
        )

        return CrashReport(
            application_name=app_name,
            faulting_module=fault_mod,
            exception_code=norm_code,
            exception_name=exc_info[0],
            exception_description=exc_info[1],
            fault_offset=fault_offset,
            timestamp=timestamp,
            event_id=1001,
            source=source,
            root_cause_category=cat,
            root_cause_description=desc,
            confidence=conf,
            remediation_steps=steps,
            application_path=app_path,
            raw_details=props,
        )

    def parse_wer_file(self, wer_path: Union[str, Path]) -> Optional[CrashReport]:
        """Reads and parses a .wer file from disk, supporting UTF-16 and UTF-8 encodings."""
        path = Path(wer_path)
        if not path.exists() or not path.is_file():
            return None

        raw_bytes = path.read_bytes()
        # Decode considering common WER encodings (UTF-16 LE with BOM or UTF-8)
        content = ""
        for encoding in ("utf-16", "utf-16-le", "utf-8", "latin-1"):
            try:
                content = raw_bytes.decode(encoding)
                if "Sig[" in content or "EventType=" in content or "Version=" in content:
                    break
            except (UnicodeDecodeError, ValueError):
                continue

        if not content:
            return None

        return self.parse_wer_content(content, filename=path.name, source="WER")

    # -------------------------------------------------------------------------
    # Windows Event Log Query via PowerShell Get-WinEvent
    # -------------------------------------------------------------------------

    def get_event_log_crashes(
        self,
        app_name: Optional[str] = None,
        limit: int = 15,
    ) -> List[CrashReport]:
        """
        Inspects Windows Application Event Log for Event ID 1000 ('Application Error')
        using PowerShell Get-WinEvent. Gracefully returns [] on non-Windows or if no events exist.
        """
        if os.name != "nt":
            return []

        ps_cmd = (
            f"Get-WinEvent -FilterHashtable @{{LogName='Application'; ProviderName='Application Error'; Id=1000}} "
            f"-MaxEvents {limit} -ErrorAction SilentlyContinue | "
            f"Select-Object -Property TimeCreated, Id, Message | ConvertTo-Json -Compress"
        )

        try:
            res = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=12,
            )
            stdout = res.stdout.strip()
            if not stdout:
                return []

            # PowerShell ConvertTo-Json outputs single object as dict, multiple as list
            parsed_data = json.loads(stdout)
            events = [parsed_data] if isinstance(parsed_data, dict) else parsed_data

            reports: List[CrashReport] = []
            for ev in events:
                msg = ev.get("Message", "")
                time_created = str(ev.get("TimeCreated", ""))
                ev_id = ev.get("Id", 1000)

                report = self.parse_event_message(
                    message=msg,
                    timestamp=time_created,
                    event_id=ev_id,
                    source="EventLog",
                )
                if report:
                    if app_name:
                        filter_app = app_name.lower().removesuffix(".exe")
                        curr_app = report.application_name.lower().removesuffix(".exe")
                        if filter_app not in curr_app and curr_app not in filter_app:
                            continue
                    reports.append(report)

            return reports
        except Exception:
            return []

    # -------------------------------------------------------------------------
    # Search & Scan WER Archive Folders
    # -------------------------------------------------------------------------

    def scan_wer_archives(
        self,
        app_name: Optional[str] = None,
        search_dirs: Optional[List[Path]] = None,
    ) -> List[CrashReport]:
        """Scans standard Windows Error Reporting directories for .wer report archives."""
        if search_dirs is None:
            search_dirs = []
            prog_data = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
            local_app = os.environ.get("LOCALAPPDATA", "")

            p1 = Path(prog_data) / "Microsoft" / "Windows" / "WER" / "ReportArchive"
            if p1.exists():
                search_dirs.append(p1)

            if local_app:
                p2 = Path(local_app) / "Microsoft" / "Windows" / "WER" / "ReportArchive"
                if p2.exists():
                    search_dirs.append(p2)
                p3 = Path(local_app) / "CrashDumps"
                if p3.exists():
                    search_dirs.append(p3)

        reports: List[CrashReport] = []
        for sdir in search_dirs:
            if not sdir.exists():
                continue
            for wer_file in sdir.rglob("*.wer"):
                rep = self.parse_wer_file(wer_file)
                if rep:
                    if app_name:
                        filter_app = app_name.lower().removesuffix(".exe")
                        curr_app = rep.application_name.lower().removesuffix(".exe")
                        if filter_app not in curr_app and curr_app not in filter_app:
                            continue
                    reports.append(rep)

        return reports

    def diagnose_crash(
        self,
        game_exe: Optional[Union[str, Path]] = None,
        app_name: Optional[str] = None,
    ) -> List[CrashReport]:
        """Diagnoses recent crashes for an application from Event Log and WER archives."""
        name = app_name or (Path(game_exe).name if game_exe else None)
        if not name and self.game_dir:
            for p in self.game_dir.glob("*.exe"):
                if not p.name.lower().startswith("unins"):
                    name = p.name
                    break

        crashes = self.get_event_log_crashes(app_name=name)
        if not crashes:
            crashes = self.scan_wer_archives(app_name=name)
        return crashes

    # -------------------------------------------------------------------------
    # Offline & Mock Factory Interface
    # -------------------------------------------------------------------------

    def analyze_mock(
        self,
        application_name: str,
        faulting_module: str,
        exception_code: Union[str, int] = "0xc0000005",
        fault_offset: str = "0x00010000",
        app_path: Optional[str] = None,
        game_dir: Optional[Union[str, Path]] = None,
    ) -> CrashReport:
        """
        Creates and correlates a CrashReport directly from parameters.
        Ideal for unit testing, offline diagnosis, and synthetic simulations.
        """
        norm_code = normalize_exception_code(exception_code)
        exc_info = KNOWN_EXCEPTIONS.get(
            norm_code,
            ("UNKNOWN_EXCEPTION", f"Windows Exception Code {norm_code}"),
        )

        fault_mod = FaultingModule.classify(
            name=faulting_module,
            path=None,
            version="1.0.0.0",
            app_name=application_name,
        )

        cat, desc, conf, steps = self.correlate_root_cause(
            application_name=application_name,
            faulting_mod=fault_mod,
            exception_code=norm_code,
            fault_offset=fault_offset,
            app_path=app_path,
            game_dir=game_dir,
        )

        return CrashReport(
            application_name=application_name,
            faulting_module=fault_mod,
            exception_code=norm_code,
            exception_name=exc_info[0],
            exception_description=exc_info[1],
            fault_offset=fault_offset,
            timestamp="MockTimestamp",
            event_id=1000,
            source="Mock",
            root_cause_category=cat,
            root_cause_description=desc,
            confidence=conf,
            remediation_steps=steps,
            application_path=app_path,
        )
