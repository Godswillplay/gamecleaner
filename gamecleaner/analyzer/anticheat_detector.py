"""
Anti-Cheat & DRM Packer Detector:
Scans game folder and binaries for presence of third-party Anti-Cheat solutions and binary packers/DRMs:
- Easy Anti-Cheat (EAC)
- BattlEye (BE)
- Denuvo Anti-Tamper & Anti-Cheat
- Riot Vanguard
- VMProtect
- Themida / WinLicense
- Arxan, SafeDisc (SECDRV.SYS), SecuROM

Reports anti-cheat status: Active, Dormant, Fake/Bypassed, or Vulnerable driver.
Flags whether the anti-cheat driver poses a BYOVD risk or prevents offline emulator play.
"""
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import math
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union

try:
    import pefile
except ImportError:
    pefile = None

from gamecleaner.analyzer.driver_auditor import KNOWN_BYOVD_DRIVERS, lookup_byovd


class AntiCheatStatus(str, Enum):
    ACTIVE = "ACTIVE"
    DORMANT = "DORMANT"
    FAKE_BYPASSED = "FAKE_BYPASSED"
    VULNERABLE_DRIVER = "VULNERABLE_DRIVER"
    STRIPPED = "STRIPPED"
    NONE = "NONE"


class AntiCheatType(str, Enum):
    EASY_ANTI_CHEAT = "EASY_ANTI_CHEAT"
    BATTLE_EYE = "BATTLE_EYE"
    DENUVO = "DENUVO"
    VANGUARD = "VANGUARD"
    VMPROTECT = "VMPROTECT"
    THEMIDA = "THEMIDA"
    ARXAN = "ARXAN"
    SAFEDISC = "SAFEDISC"
    SECUROM = "SECUROM"
    CUSTOM = "CUSTOM"


# Known vulnerable or high-risk driver files
RISKY_ANTI_CHEAT_DRIVERS: Dict[str, Dict[str, str]] = {
    "secdrv.sys": {
        "name": "Macrovision SafeDisc SECDRV.SYS",
        "cve": "CVE-2015-2546 / MS15-097",
        "severity": "CRITICAL",
        "description": "Legacy SafeDisc kernel driver allowing arbitrary ring-0 code execution. Blocked by Windows 10/11.",
    },
    "easyanticheat.sys": {
        "name": "EasyAntiCheat Kernel Driver",
        "cve": "CVE-2022-26168 / Arbitrary Kernel R/W",
        "severity": "HIGH",
        "description": "Kernel-mode anti-cheat driver. Older unpatched versions expose arbitrary physical memory read/write primitives.",
    },
    "bedaisy.sys": {
        "name": "BattlEye BEDaisy Driver",
        "cve": "Kernel Ring-0 Hooking",
        "severity": "HIGH",
        "description": "Kernel-mode driver with deep kernel hooks, frequently abused by rootkits or triggering hypervisor conflicts.",
    },
    "vgk.sys": {
        "name": "Riot Vanguard vgk.sys",
        "cve": "Boot-Start Ring-0 Driver",
        "severity": "HIGH",
        "description": "Ring-0 boot-start driver requiring continuous kernel supervision, preventing offline emulator environments.",
    },
    "denuvo64.sys": {
        "name": "Denuvo Anti-Cheat denuvo64.sys",
        "cve": "Kernel Anti-Cheat Driver",
        "severity": "HIGH",
        "description": "Kernel driver monitoring process integrity and hypervisor registers.",
    },
}

# Signatures for Denuvo detection
DENUVO_STRINGS = [
    b"denuvo",
    b"denuvotm",
    b"denuvo anti-tamper",
    b"denuvo.com",
    b"Denuvo Ticket",
    b"Denuvo_Ticket_",
    b"denuvo64.dll",
    b"denuvo64.sys",
]

# Signatures for VMProtect
VMPROTECT_STRINGS = [
    b"VMProtect begin",
    b"VMProtect end",
    b"VMProtect",
    b".vmp0",
    b".vmp1",
    b".vmp2",
]

# Signatures for Themida / WinLicense
THEMIDA_STRINGS = [
    b"Oreans Technologies",
    b"Themida",
    b"WinLicense",
    b".themida",
    b".winlic",
]

# Signatures for Arxan
ARXAN_STRINGS = [
    b"arxan",
    b"Arxan Technologies",
    b"apphardening",
]

# Known Scene bypass indicators
SCENE_CRACK_MARKERS = [
    "emp.dll",
    "codex64.dll",
    "steam_api64.cdx",
    "empress.txt",
    "flt.dll",
    "rld.dll",
    "skidrow.dll",
]


@dataclass
class AntiCheatFinding:
    """Diagnostic finding for an anti-cheat solution or binary packer."""

    name: str
    anticheat_type: str
    status: str  # AntiCheatStatus
    byovd_risk: bool
    blocks_offline_play: bool
    detected_files: List[str] = field(default_factory=list)
    detected_sections: List[str] = field(default_factory=list)
    detected_signatures: List[str] = field(default_factory=list)
    description: str = ""
    remediation_advice: str = ""
    driver_hash: Optional[str] = None
    severity: str = "HIGH"


@dataclass
class AntiCheatScanReport:
    """Comprehensive summary of anti-cheat and packer scan."""

    game_dir: str
    findings: List[AntiCheatFinding] = field(default_factory=list)
    has_active_anticheat: bool = False
    has_byovd_risk: bool = False
    blocks_offline_emulator: bool = False
    scanned_files_count: int = 0
    summary: str = ""


class AntiCheatDetector:
    """
    Scans a game directory or executable binary for third-party Anti-Cheat systems
    and binary protection/DRM packers.
    """

    def __init__(self, game_dir: Union[str, Path]):
        self.game_dir = Path(game_dir)

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculates Shannon entropy for given byte slice."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        frequencies = [0] * 256
        for b in data:
            frequencies[b] += 1
        for count in frequencies:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 2)

    @staticmethod
    def _get_sha256(path: Path) -> str:
        """Calculates SHA-256 hash of a file."""
        hasher = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return ""

    # -------------------------------------------------------------------------
    # Binary PE & Section Analysis
    # -------------------------------------------------------------------------

    def scan_binary(self, binary_path: Union[str, Path]) -> List[AntiCheatFinding]:
        """
        Inspects a single PE binary for anti-cheat sections (Denuvo, VMProtect, Themida)
        and embedded signature strings.
        """
        path = Path(binary_path)
        if not path.exists() or not path.is_file():
            return []

        findings: List[AntiCheatFinding] = []
        raw_bytes = b""
        try:
            with open(path, "rb") as f:
                # Read up to 8MB for signature and header scanning
                raw_bytes = f.read(8 * 1024 * 1024)
        except Exception:
            return []

        # Check for Scene Crack indicators in game folder
        has_scene_crack = False
        if path.parent.exists():
            for crack_indicator in SCENE_CRACK_MARKERS:
                if (path.parent / crack_indicator).exists():
                    has_scene_crack = True
                    break

        section_names: List[str] = []
        high_entropy_sections: List[str] = []

        if pefile:
            try:
                pe = pefile.PE(str(path), fast_load=True)
                pe.parse_data_directories(
                    directories=[
                        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
                        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                    ]
                )
                for sec in pe.sections:
                    sec_name = sec.Name.decode("latin-1", errors="ignore").rstrip("\x00").lower()
                    section_names.append(sec_name)
                    # Calculate entropy of section if data present
                    sec_data = sec.get_data()
                    if sec_data:
                        ent = self.calculate_entropy(sec_data[:65536])
                        if ent >= 7.2:
                            high_entropy_sections.append(sec_name)
            except Exception:
                pass

        # Fallback raw header section scan if pefile failed or missing
        if not section_names:
            for sname in [".adata", ".vmp0", ".vmp1", ".themida", ".winlic", ".bind", ".secu1", "denuvo"]:
                if sname.encode("latin-1") in raw_bytes[:4096]:
                    section_names.append(sname)

        # 1. DENUVO ANTI-TAMPER / ANTI-CHEAT
        denuvo_matched: List[str] = []
        for s in DENUVO_STRINGS:
            if s.lower() in raw_bytes.lower():
                denuvo_matched.append(s.decode("latin-1", errors="ignore"))

        denuvo_sections = [s for s in section_names if s in (".adata", "denuvo", ".denuvo", "denu")]
        if denuvo_matched or denuvo_sections:
            status = AntiCheatStatus.FAKE_BYPASSED.value if has_scene_crack else AntiCheatStatus.ACTIVE.value
            findings.append(
                AntiCheatFinding(
                    name="Denuvo Anti-Tamper",
                    anticheat_type=AntiCheatType.DENUVO.value,
                    status=status,
                    byovd_risk=False,
                    blocks_offline_play=not has_scene_crack,
                    detected_files=[str(path)],
                    detected_sections=denuvo_sections,
                    detected_signatures=denuvo_matched,
                    description=(
                        "Denuvo Anti-Tamper detected via PE section headers / signature strings. "
                        + ("Active crack emulator detected alongside binary." if has_scene_crack else "Uncracked original binary; requires online token activation.")
                    ),
                    remediation_advice=(
                        "Game is cracked or bypassed; ready for Goldberg emulator."
                        if has_scene_crack
                        else "Denuvo Anti-Tamper prevents offline play unless unpacked with Steamless or pre-cracked."
                    ),
                    severity="HIGH",
                )
            )

        # 2. VMPROTECT
        vmp_matched: List[str] = []
        for s in VMPROTECT_STRINGS:
            if s in raw_bytes:
                vmp_matched.append(s.decode("latin-1", errors="ignore"))
        vmp_sections = [s for s in section_names if s.startswith(".vmp") or s.startswith("vmp")]

        if vmp_matched or vmp_sections:
            findings.append(
                AntiCheatFinding(
                    name="VMProtect",
                    anticheat_type=AntiCheatType.VMPROTECT.value,
                    status=AntiCheatStatus.ACTIVE.value,
                    byovd_risk=False,
                    blocks_offline_play=False,
                    detected_files=[str(path)],
                    detected_sections=vmp_sections,
                    detected_signatures=vmp_matched,
                    description="VMProtect code virtualization detected. Code sections are obfuscated and virtualized.",
                    remediation_advice="VMProtect protects game logic against disassembly. Standard Goldberg emulators operate normally if Steam APIs are not virtualized.",
                    severity="MEDIUM",
                )
            )

        # 3. THEMIDA / WINLICENSE
        themida_matched: List[str] = []
        for s in THEMIDA_STRINGS:
            if s in raw_bytes:
                themida_matched.append(s.decode("latin-1", errors="ignore"))
        themida_sections = [s for s in section_names if s in (".themida", ".winlic", "themida", "winlic")]

        if themida_matched or themida_sections:
            findings.append(
                AntiCheatFinding(
                    name="Themida / WinLicense",
                    anticheat_type=AntiCheatType.THEMIDA.value,
                    status=AntiCheatStatus.ACTIVE.value,
                    byovd_risk=False,
                    blocks_offline_play=False,
                    detected_files=[str(path)],
                    detected_sections=themida_sections,
                    detected_signatures=themida_matched,
                    description="Themida / WinLicense packing detected. Binary employs aggressive anti-debugger and anti-dump routines.",
                    remediation_advice="May block debuggers or tools; does not inherently prevent offline emulator play.",
                    severity="MEDIUM",
                )
            )

        # 4. ARXAN
        arxan_matched: List[str] = []
        for s in ARXAN_STRINGS:
            if s.lower() in raw_bytes.lower():
                arxan_matched.append(s.decode("latin-1", errors="ignore"))
        if arxan_matched:
            findings.append(
                AntiCheatFinding(
                    name="Arxan Anti-Tamper",
                    anticheat_type=AntiCheatType.ARXAN.value,
                    status=AntiCheatStatus.ACTIVE.value,
                    byovd_risk=False,
                    blocks_offline_play=False,
                    detected_files=[str(path)],
                    detected_signatures=arxan_matched,
                    description="Arxan application hardening detected. Binary contains integrity guards.",
                    remediation_advice="Compatible with clean Goldberg emulation in most cases.",
                    severity="LOW",
                )
            )

        return findings

    # -------------------------------------------------------------------------
    # Filesystem & Driver Scan
    # -------------------------------------------------------------------------

    def scan_file_system(self) -> List[AntiCheatFinding]:
        """
        Scans all files and directories in the game folder for anti-cheat binaries,
        drivers (.sys), services, and certificates.
        """
        if not self.game_dir.exists() or not self.game_dir.is_dir():
            return []

        findings: List[AntiCheatFinding] = []

        # Collect all files mapped by lower case name
        all_files: Dict[str, List[Path]] = {}
        for root, _, files in os.walk(self.game_dir):
            for f in files:
                fpath = Path(root) / f
                name_low = f.lower()
                all_files.setdefault(name_low, []).append(fpath)

        # 1. EASY ANTI-CHEAT (EAC)
        eac_driver_files = all_files.get("easyanticheat.sys", []) + all_files.get("easyanticheat_x64.sys", []) + all_files.get("easyanticheat_eos.sys", [])
        eac_setup_files = all_files.get("easyanticheat_setup.exe", []) + all_files.get("easyanticheat_eos_setup.exe", [])
        eac_dll_files = all_files.get("easyanticheat_x64.dll", []) + all_files.get("easyanticheat.dll", []) + all_files.get("easyanticheat_x86.dll", [])

        if eac_driver_files or eac_setup_files or eac_dll_files:
            all_eac = [str(p) for p in (eac_driver_files + eac_setup_files + eac_dll_files)]
            driver_hash = self._get_sha256(eac_driver_files[0]) if eac_driver_files else None

            # Determine status: Fake/Bypassed if DLL is small dummy (< 35KB)
            status = AntiCheatStatus.ACTIVE.value
            is_bypassed = False
            for d in eac_dll_files:
                try:
                    if d.stat().st_size < 35 * 1024:
                        is_bypassed = True
                        break
                except OSError:
                    pass

            if is_bypassed:
                status = AntiCheatStatus.FAKE_BYPASSED.value
            elif eac_driver_files and not eac_dll_files:
                status = AntiCheatStatus.DORMANT.value

            findings.append(
                AntiCheatFinding(
                    name="Easy Anti-Cheat (EAC)",
                    anticheat_type=AntiCheatType.EASY_ANTI_CHEAT.value,
                    status=status,
                    byovd_risk=bool(eac_driver_files),
                    blocks_offline_play=not is_bypassed,
                    detected_files=all_eac,
                    description=(
                        "Easy Anti-Cheat (EAC) suite detected. "
                        + ("Dummy / cracked client DLL found." if is_bypassed else "Full anti-cheat files present.")
                    ),
                    remediation_advice=(
                        "EAC is already bypassed via dummy library."
                        if is_bypassed
                        else "Launch game executable directly bypassing EasyAntiCheat_Setup.exe, or append '-eac_launcher false' to launch parameters."
                    ),
                    driver_hash=driver_hash,
                    severity="HIGH",
                )
            )

        # 2. BATTLEYE
        be_driver_files = all_files.get("bedaisy.sys", [])
        be_service_files = all_files.get("beservice.exe", []) + all_files.get("beservice_x64.exe", [])
        be_dll_files = all_files.get("beclient_x64.dll", []) + all_files.get("beclient.dll", [])

        if be_driver_files or be_service_files or be_dll_files:
            all_be = [str(p) for p in (be_driver_files + be_service_files + be_dll_files)]
            driver_hash = self._get_sha256(be_driver_files[0]) if be_driver_files else None

            status = AntiCheatStatus.ACTIVE.value
            is_bypassed = False
            for d in be_dll_files:
                try:
                    if d.stat().st_size < 35 * 1024:
                        is_bypassed = True
                        break
                except OSError:
                    pass

            if is_bypassed:
                status = AntiCheatStatus.FAKE_BYPASSED.value
            elif not be_service_files and not be_dll_files:
                status = AntiCheatStatus.DORMANT.value

            findings.append(
                AntiCheatFinding(
                    name="BattlEye",
                    anticheat_type=AntiCheatType.BATTLE_EYE.value,
                    status=status,
                    byovd_risk=bool(be_driver_files),
                    blocks_offline_play=not is_bypassed,
                    detected_files=all_be,
                    description=(
                        "BattlEye anti-cheat solution detected. "
                        + ("Dummy BEClient DLL detected." if is_bypassed else "Kernel driver BEDaisy and BEService present.")
                    ),
                    remediation_advice=(
                        "Dummy BEClient DLL already installed; offline launch supported."
                        if is_bypassed
                        else "Launch main executable directly to bypass BEService.exe, or replace BEClient_x64.dll with offline emulator."
                    ),
                    driver_hash=driver_hash,
                    severity="HIGH",
                )
            )

        # 3. RIOT VANGUARD
        vanguard_files = all_files.get("vgk.sys", []) + all_files.get("vgk.dll", []) + all_files.get("vgc.exe", [])
        if vanguard_files:
            vgk_hash = self._get_sha256(vanguard_files[0])
            findings.append(
                AntiCheatFinding(
                    name="Riot Vanguard",
                    anticheat_type=AntiCheatType.VANGUARD.value,
                    status=AntiCheatStatus.ACTIVE.value,
                    byovd_risk=True,
                    blocks_offline_play=True,
                    detected_files=[str(p) for p in vanguard_files],
                    description="Riot Vanguard kernel driver (vgk.sys) detected. Ring-0 boot-start driver.",
                    remediation_advice="Riot Vanguard is strictly incompatible with offline emulation and sandboxed play.",
                    driver_hash=vgk_hash,
                    severity="CRITICAL",
                )
            )

        # 4. SAFEDISC (SECDRV.SYS)
        safedisc_files = all_files.get("secdrv.sys", []) + all_files.get("drvmgt.dll", []) + all_files.get("00000001.tmp", [])
        if safedisc_files:
            drv_hash = self._get_sha256(safedisc_files[0])
            findings.append(
                AntiCheatFinding(
                    name="SafeDisc (SECDRV.SYS)",
                    anticheat_type=AntiCheatType.SAFEDISC.value,
                    status=AntiCheatStatus.VULNERABLE_DRIVER.value,
                    byovd_risk=True,
                    blocks_offline_play=True,
                    detected_files=[str(p) for p in safedisc_files],
                    description="Macrovision SafeDisc driver SECDRV.SYS detected. Known critical privilege escalation vector (MS15-097).",
                    remediation_advice="SECDRV.SYS is blocked by Windows 10/11. The game must be patched with a No-CD cracked executable to run.",
                    driver_hash=drv_hash,
                    severity="CRITICAL",
                )
            )

        # 5. SECUROM
        securom_files = all_files.get("paul.dll", []) + all_files.get("secuexp.dat", []) + all_files.get("secur32.dll", [])
        if securom_files:
            findings.append(
                AntiCheatFinding(
                    name="SecuROM",
                    anticheat_type=AntiCheatType.SECUROM.value,
                    status=AntiCheatStatus.ACTIVE.value,
                    byovd_risk=False,
                    blocks_offline_play=True,
                    detected_files=[str(p) for p in securom_files],
                    description="Sony DADC SecuROM DRM detected.",
                    remediation_advice="SecuROM disc check blocks launch. Apply a clean fixed executable.",
                    severity="HIGH",
                )
            )

        # 6. DENUVO ANTI-CHEAT KERNEL DRIVER
        denuvo_driver_files = all_files.get("denuvo64.sys", []) + all_files.get("denuvo.sys", [])
        if denuvo_driver_files:
            findings.append(
                AntiCheatFinding(
                    name="Denuvo Anti-Cheat Driver",
                    anticheat_type=AntiCheatType.DENUVO.value,
                    status=AntiCheatStatus.ACTIVE.value,
                    byovd_risk=True,
                    blocks_offline_play=True,
                    detected_files=[str(p) for p in denuvo_driver_files],
                    description="Denuvo Anti-Cheat kernel driver (denuvo64.sys) detected.",
                    remediation_advice="Denuvo Anti-Cheat driver requires active kernel registration and online connection.",
                    driver_hash=self._get_sha256(denuvo_driver_files[0]),
                    severity="HIGH",
                )
            )

        return findings

    # -------------------------------------------------------------------------
    # Comprehensive Full Folder Scan
    # -------------------------------------------------------------------------

    def scan(self) -> AntiCheatScanReport:
        """
        Performs an end-to-end scan of the game directory:
        1. Analyzes directory filesystem and drivers for EAC, BattlEye, Vanguard, SafeDisc, SecuROM.
        2. Inspects executables (.exe) and dynamic libraries (.dll) for Denuvo, VMProtect, Themida, Arxan.
        """
        all_findings: List[AntiCheatFinding] = []
        scanned_count = 0

        # Step 1: Scan file system drivers & services
        fs_findings = self.scan_file_system()
        all_findings.extend(fs_findings)

        # Step 2: Scan PE binaries
        if self.game_dir.exists() and self.game_dir.is_dir():
            for root, _, files in os.walk(self.game_dir):
                for f in files:
                    ext = Path(f).suffix.lower()
                    if ext in (".exe", ".dll"):
                        scanned_count += 1
                        bin_path = Path(root) / f
                        bin_findings = self.scan_binary(bin_path)
                        all_findings.extend(bin_findings)

        has_active = any(
            f.status in (AntiCheatStatus.ACTIVE.value, AntiCheatStatus.VULNERABLE_DRIVER.value)
            for f in all_findings
        )
        has_byovd = any(f.byovd_risk for f in all_findings)
        blocks_offline = any(f.blocks_offline_play for f in all_findings)

        # Summary text
        if not all_findings:
            summary = "No third-party Anti-Cheat solutions or binary packers detected. Game is clean and compatible with offline emulators."
        else:
            names = list({f.name for f in all_findings})
            summary = f"Detected {len(all_findings)} protection signatures ({', '.join(names)}). "
            if has_byovd:
                summary += "WARNING: Kernel drivers with potential BYOVD exploit risks found! "
            if blocks_offline:
                summary += "Action required: Offline play may require launcher bypass or cracked binaries."
            else:
                summary += "Protections appear bypassed or compatible with Goldberg offline emulation."

        return AntiCheatScanReport(
            game_dir=str(self.game_dir),
            findings=all_findings,
            has_active_anticheat=has_active,
            has_byovd_risk=has_byovd,
            blocks_offline_emulator=blocks_offline,
            scanned_files_count=scanned_count,
            summary=summary,
        )
