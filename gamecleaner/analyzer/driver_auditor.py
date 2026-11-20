"""
Kernel Driver (.sys) & BYOVD (Bring Your Own Vulnerable Driver) Auditor.
Audits kernel driver binaries, validates Authenticode / WHQL signatures,
identifies known vulnerable / malicious drivers (LOLDrivers / BYOVD signatures),
and inspects installation scripts (.bat, .cmd, .ps1) for kernel service registration.
"""
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Dict, List, Optional, Set, Union

from gamecleaner.analyzer.pe_scanner import check_authenticode_signature, get_file_hashes


# Built-in database of known vulnerable and abused kernel drivers (LOLDrivers / BYOVD)
KNOWN_BYOVD_DRIVERS: Dict[str, Dict[str, str]] = {
    "gdrv.sys": {
        "name": "Gigabyte gdrv.sys",
        "canonical_name": "gdrv.sys",
        "vendor": "Gigabyte",
        "cve": "CVE-2018-19320 / CVE-2018-19321",
        "description": "Gigabyte elevation driver allowing arbitrary ring-0 physical memory read/write and elevation of privilege (abused by RobbinHood ransomware).",
        "severity": "CRITICAL",
    },
    "mhyprot2.sys": {
        "name": "HoYoverse / Genshin mhyprot2.sys",
        "canonical_name": "mhyprot2.sys",
        "vendor": "HoYoverse / Genshin",
        "cve": "BYOVD EDR Killer",
        "description": "HoYoverse anti-cheat kernel driver abused by ransomware and malware to terminate EDR/AV processes and bypass ring-0 protections.",
        "severity": "CRITICAL",
    },
    "procexp.sys": {
        "name": "Microsoft Sysinternals procexp.sys",
        "canonical_name": "procexp.sys",
        "vendor": "Microsoft Sysinternals",
        "cve": "BYOVD Process Termination",
        "description": "Sysinternals Process Explorer kernel driver abused by threat actors for ring-0 process termination of protected endpoint security software.",
        "severity": "HIGH",
    },
    "procexp152.sys": {
        "name": "Microsoft Sysinternals procexp152.sys",
        "canonical_name": "procexp152.sys",
        "vendor": "Microsoft Sysinternals",
        "cve": "BYOVD Process Termination",
        "description": "Legacy Sysinternals Process Explorer v152 driver abused by malware to terminate endpoint security processes.",
        "severity": "HIGH",
    },
    "rtcore64.sys": {
        "name": "Micro-Star (MSI) rtcore64.sys",
        "canonical_name": "rtcore64.sys",
        "vendor": "Micro-Star (MSI)",
        "cve": "CVE-2019-16098",
        "description": "MSI Afterburner RTCore64 driver exposing unrestricted ring-0 physical/virtual memory and MSR read/write primitives.",
        "severity": "CRITICAL",
    },
    "rtcore32.sys": {
        "name": "Micro-Star (MSI) rtcore32.sys",
        "canonical_name": "rtcore32.sys",
        "vendor": "Micro-Star (MSI)",
        "cve": "CVE-2019-16098",
        "description": "32-bit RTCore driver exposing unrestricted ring-0 physical and kernel memory access primitives.",
        "severity": "CRITICAL",
    },
    "iqvw64e.sys": {
        "name": "Intel iqvw64e.sys",
        "canonical_name": "iqvw64e.sys",
        "vendor": "Intel",
        "cve": "CVE-2015-2291",
        "description": "Intel Network Adapter Diagnostic Driver abused by kdmapper to bypass Driver Signature Enforcement (DSE) and load unsigned kernel code.",
        "severity": "CRITICAL",
    },
    "asiodrv.sys": {
        "name": "ASUS asiodrv.sys",
        "canonical_name": "asiodrv.sys",
        "vendor": "ASUS",
        "cve": "CVE-2018-18537 / ASUS LPE",
        "description": "ASUS ASUSTeK driver exposing ring-0 arbitrary memory and control register access.",
        "severity": "HIGH",
    },
    "dbutil_2_3.sys": {
        "name": "Dell dbutil_2_3.sys",
        "canonical_name": "dbutil_2_3.sys",
        "vendor": "Dell",
        "cve": "CVE-2021-21551",
        "description": "Dell DBUtil firmware update driver allowing local privilege escalation and arbitrary ring-0 read/write access.",
        "severity": "CRITICAL",
    },
    "ene.sys": {
        "name": "ENE Technology ene.sys",
        "canonical_name": "ene.sys",
        "vendor": "ENE Technology",
        "cve": "CVE-2020-12446",
        "description": "ENE Technology RGB driver exposing physical memory and I/O port manipulation.",
        "severity": "HIGH",
    },
}


def lookup_byovd(driver_name: str) -> Optional[Dict[str, str]]:
    """
    Looks up a driver name or stem in the known BYOVD / LOLDrivers database.
    Matches exact filenames (e.g. 'gdrv.sys') or stems without extension (e.g. 'gdrv').
    """
    lower = driver_name.lower().strip()
    if lower in KNOWN_BYOVD_DRIVERS:
        return KNOWN_BYOVD_DRIVERS[lower]

    with_ext = f"{lower}.sys"
    if with_ext in KNOWN_BYOVD_DRIVERS:
        return KNOWN_BYOVD_DRIVERS[with_ext]

    stem = Path(lower).stem
    stem_with_ext = f"{stem}.sys"
    if stem_with_ext in KNOWN_BYOVD_DRIVERS:
        return KNOWN_BYOVD_DRIVERS[stem_with_ext]

    return None


def check_is_microsoft_driver(file_path: Path, is_signed: bool) -> bool:
    """
    Determines whether a driver is signed by Microsoft Corporation.
    Requires a valid Authenticode signature to prevent spoofing.
    """
    if not is_signed:
        return False

    file_resolved = file_path.resolve()

    # 1. On Windows, check SignerCertificate via PowerShell Get-AuthenticodeSignature
    if os.name == "nt":
        try:
            proc = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "param($p) (Get-AuthenticodeSignature -LiteralPath $p).SignerCertificate.Subject",
                    "-p",
                    str(file_resolved),
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            subj = proc.stdout.lower()
            if "microsoft" in subj and (
                "microsoft corporation" in subj
                or "microsoft windows" in subj
                or "microsoft hardware" in subj
                or "whql" in subj
            ):
                return True
        except Exception:
            pass

    # 2. Cross-platform / fallback: inspect PE VersionInfo using pefile
    try:
        import pefile
        pe = pefile.PE(str(file_resolved), fast_load=True)
        if hasattr(pe, "FileInfo"):
            for file_info_list in pe.FileInfo:
                for entry in file_info_list:
                    if hasattr(entry, "StringTable"):
                        for st in entry.StringTable:
                            for key, val in st.entries.items():
                                k = key.decode("utf-8", "ignore").lower()
                                v = val.decode("utf-8", "ignore").lower()
                                if k in ("companyname", "legalcopyright") and "microsoft" in v:
                                    pe.close()
                                    return True
        pe.close()
    except Exception:
        pass

    return False


@dataclass
class DriverFinding:
    """Findings from auditing a kernel driver or driver installation script."""
    file_path: str
    driver_name: str
    sha256: str
    is_signed: bool
    is_microsoft: bool
    is_known_vulnerable_byovd: bool
    byovd_details: Optional[str] = None
    severity: str = "HIGH"
    description: str = ""


class DriverAuditor:
    """
    Scans game directories for .sys kernel drivers and driver registration scripts.
    Identifies unsigned drivers, third-party ring-0 components, and known BYOVD exploits.
    """

    def __init__(self, target_dir: Optional[Union[Path, str]] = None):
        """
        Initializes the DriverAuditor.

        Args:
            target_dir: Optional root directory to audit.
        """
        self.target_dir = Path(target_dir).resolve() if target_dir else None

    def scan_driver_file(self, file_path: Path) -> DriverFinding:
        """
        Performs static security analysis on a single .sys kernel driver binary.

        Args:
            file_path: Path to the .sys file.

        Returns:
            DriverFinding detailing signature status, vendor, and BYOVD risk.
        """
        file_path = Path(file_path).resolve()
        driver_name = file_path.name

        # Calculate SHA-256 hash
        try:
            _, sha256 = get_file_hashes(file_path)
        except Exception:
            try:
                sha256 = hashlib.sha256(file_path.read_bytes()).hexdigest()
            except Exception:
                sha256 = ""

        # Authenticode signature check
        sig_status = check_authenticode_signature(file_path)
        is_signed = (sig_status == "Valid")
        is_microsoft = check_is_microsoft_driver(file_path, is_signed)

        # Check known BYOVD / LOLDrivers database
        byovd_info = lookup_byovd(driver_name)
        if byovd_info:
            return DriverFinding(
                file_path=str(file_path),
                driver_name=driver_name,
                sha256=sha256,
                is_signed=is_signed,
                is_microsoft=is_microsoft,
                is_known_vulnerable_byovd=True,
                byovd_details=byovd_info["description"],
                severity=byovd_info["severity"],
                description=(
                    f"Known vulnerable BYOVD (Bring Your Own Vulnerable Driver) kernel binary: "
                    f"{byovd_info['name']} ({byovd_info['cve']}). "
                    f"Provides arbitrary ring-0 primitives and is weaponized in malware."
                ),
            )

        if not is_signed:
            return DriverFinding(
                file_path=str(file_path),
                driver_name=driver_name,
                sha256=sha256,
                is_signed=False,
                is_microsoft=False,
                is_known_vulnerable_byovd=False,
                byovd_details=None,
                severity="HIGH",
                description=(
                    f"Unsigned kernel driver binary '{driver_name}'. "
                    f"Ring-0 execution without valid cryptographic certificate."
                ),
            )

        if is_microsoft:
            return DriverFinding(
                file_path=str(file_path),
                driver_name=driver_name,
                sha256=sha256,
                is_signed=True,
                is_microsoft=True,
                is_known_vulnerable_byovd=False,
                byovd_details=None,
                severity="LOW",
                description=f"Genuine Microsoft-signed kernel driver '{driver_name}'.",
            )

        # Signed third-party driver (anti-cheat, DRM, or custom hardware driver)
        return DriverFinding(
            file_path=str(file_path),
            driver_name=driver_name,
            sha256=sha256,
            is_signed=True,
            is_microsoft=False,
            is_known_vulnerable_byovd=False,
            byovd_details=None,
            severity="MEDIUM",
            description=(
                f"Third-party signed kernel driver '{driver_name}'. "
                f"Requires ring-0 kernel execution privileges."
            ),
        )

    def scan_script_file(self, script_path: Path) -> List[DriverFinding]:
        """
        Inspects a script (.bat, .cmd, .ps1) for commands creating or starting driver services.

        Args:
            script_path: Path to the script file.

        Returns:
            List of DriverFinding objects for identified driver service actions.
        """
        script_path = Path(script_path).resolve()
        findings: List[DriverFinding] = []

        try:
            content = script_path.read_text(encoding="utf-8", errors="ignore")
            lines = content.splitlines()
        except Exception:
            return findings

        # Calculate script hash fallback
        try:
            script_sha256 = hashlib.sha256(script_path.read_bytes()).hexdigest()
        except Exception:
            script_sha256 = ""

        # Regex patterns for service creation and driver starting
        re_sc_create = re.compile(
            r"""(?:^|\s|&|\|)(?:sc(?:\.exe)?)\s+create\s+(?P<svc>[^\s]+)(?:.*?(?:binPath=\s*["']?(?P<bin>[^"'\r\n]+)["']?))?""",
            re.IGNORECASE,
        )
        re_sc_start = re.compile(
            r"""(?:^|\s|&|\|)(?:sc(?:\.exe)?)\s+start\s+(?P<svc>[^\s]+)""",
            re.IGNORECASE,
        )
        re_ps_new = re.compile(
            r"""New-Service\s+(?:.*?-Name\s+["']?(?P<svc>[^"'\s]+)["']?)?(?:.*?-BinaryPathName\s+["']?(?P<bin>[^"'\r\n]+)["']?)?""",
            re.IGNORECASE,
        )
        re_ps_start = re.compile(
            r"""Start-Service\s+(?:.*?-Name\s+["']?(?P<svc>[^"'\s]+)["']?)?""",
            re.IGNORECASE,
        )
        re_sys_file = re.compile(r"""[\w\-./\\]+\.sys""", re.IGNORECASE)

        seen_drivers: Set[str] = set()

        for idx, line in enumerate(lines, start=1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith("::") or line_stripped.startswith("#"):
                continue

            driver_target: Optional[str] = None
            service_name: Optional[str] = None
            action_type: str = "create"

            # 1. sc create / sc.exe create
            m_create = re_sc_create.search(line)
            if m_create:
                service_name = m_create.group("svc")
                driver_target = m_create.group("bin")
                action_type = "create"

            # 2. PowerShell New-Service
            m_new = re_ps_new.search(line)
            if m_new:
                service_name = m_new.group("svc")
                driver_target = m_new.group("bin")
                action_type = "create"

            # 3. sc start / sc.exe start
            m_start = re_sc_start.search(line)
            if m_start:
                service_name = m_start.group("svc")
                action_type = "start"

            # 4. PowerShell Start-Service
            m_pstart = re_ps_start.search(line)
            if m_pstart:
                service_name = m_pstart.group("svc")
                action_type = "start"

            # If no binPath was parsed directly, check if any .sys file is mentioned on the line
            if not driver_target:
                m_sys = re_sys_file.search(line)
                if m_sys:
                    driver_target = m_sys.group(0)

            # Determine canonical driver / service identifier
            candidate_name = ""
            if driver_target:
                raw_target = driver_target.strip("\"' ")
                cleaned = re.sub(r"%(?:~dp0|cd%?\\?|[a-zA-Z0-9_]+%?\\?)", "", raw_target, flags=re.IGNORECASE)
                cleaned = re.sub(r"\$(?:PSScriptRoot|pwd|env:[a-zA-Z0-9_]+)[\\/]?", "", cleaned, flags=re.IGNORECASE)
                candidate_name = Path(cleaned.strip("\"' /\\")).name
            elif service_name:
                raw_svc = service_name.strip("\"' ")
                cleaned = re.sub(r"%(?:~dp0|cd%?\\?|[a-zA-Z0-9_]+%?\\?)", "", raw_svc, flags=re.IGNORECASE)
                cleaned = re.sub(r"\$(?:PSScriptRoot|pwd|env:[a-zA-Z0-9_]+)[\\/]?", "", cleaned, flags=re.IGNORECASE)
                candidate_name = Path(cleaned.strip("\"' /\\")).name

            if not candidate_name:
                continue

            # Filter out generic service starts if no .sys is involved and name isn't BYOVD
            byovd = lookup_byovd(candidate_name)
            is_sys_file = candidate_name.lower().endswith(".sys") or (driver_target and ".sys" in driver_target.lower())
            if not is_sys_file and not byovd:
                continue

            unique_key = f"{candidate_name.lower()}:{action_type}"
            if unique_key in seen_drivers:
                continue
            seen_drivers.add(unique_key)

            # Check if referenced driver exists on disk in target folder
            target_sys_path: Optional[Path] = None
            if self.target_dir:
                possible_path = self.target_dir / candidate_name
                if possible_path.exists():
                    target_sys_path = possible_path
                else:
                    for found_sys in self.target_dir.rglob("*.sys"):
                        if found_sys.name.lower() == candidate_name.lower():
                            target_sys_path = found_sys
                            break

            file_sha256 = script_sha256
            is_signed = False
            is_microsoft = False

            if target_sys_path and target_sys_path.exists():
                try:
                    _, file_sha256 = get_file_hashes(target_sys_path)
                except Exception:
                    pass
                sig_status = check_authenticode_signature(target_sys_path)
                is_signed = (sig_status == "Valid")
                is_microsoft = check_is_microsoft_driver(target_sys_path, is_signed)

            if byovd:
                finding = DriverFinding(
                    file_path=str(script_path),
                    driver_name=candidate_name,
                    sha256=file_sha256,
                    is_signed=is_signed,
                    is_microsoft=is_microsoft,
                    is_known_vulnerable_byovd=True,
                    byovd_details=byovd["description"],
                    severity="CRITICAL",
                    description=(
                        f"Script '{script_path.name}' (Line {idx}) {action_type}s kernel service "
                        f"for known vulnerable BYOVD driver '{candidate_name}' ({byovd['name']}). "
                        f"Command: {line_stripped}"
                    ),
                )
            else:
                finding = DriverFinding(
                    file_path=str(script_path),
                    driver_name=candidate_name,
                    sha256=file_sha256,
                    is_signed=is_signed,
                    is_microsoft=is_microsoft,
                    is_known_vulnerable_byovd=False,
                    byovd_details=None,
                    severity="HIGH",
                    description=(
                        f"Script '{script_path.name}' (Line {idx}) registers/starts kernel driver service "
                        f"pointing to '{candidate_name}'. Command: {line_stripped}"
                    ),
                )

            findings.append(finding)

        return findings

    def scan_drivers(self, target_dir: Optional[Union[Path, str]] = None) -> List[DriverFinding]:
        """
        Scans all .sys files in the directory.

        Args:
            target_dir: Target directory (defaults to self.target_dir).

        Returns:
            List of DriverFinding objects for all discovered .sys files.
        """
        root = Path(target_dir).resolve() if target_dir else self.target_dir
        if not root or not root.exists():
            return []

        findings: List[DriverFinding] = []
        for path in root.rglob("*.sys"):
            path_str = str(path)
            if ".gamecleaner" in path_str or ".quarantine" in path_str:
                continue
            findings.append(self.scan_driver_file(path))

        return findings

    def scan_scripts(self, target_dir: Optional[Union[Path, str]] = None) -> List[DriverFinding]:
        """
        Scans all scripts (.bat, .cmd, .ps1) in the directory for driver service commands.

        Args:
            target_dir: Target directory (defaults to self.target_dir).

        Returns:
            List of DriverFinding objects for driver service registrations.
        """
        root = Path(target_dir).resolve() if target_dir else self.target_dir
        if not root or not root.exists():
            return []

        script_extensions = {".bat", ".cmd", ".ps1"}
        findings: List[DriverFinding] = []

        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in script_extensions:
                path_str = str(path)
                if ".gamecleaner" in path_str or ".quarantine" in path_str:
                    continue
                findings.extend(self.scan_script_file(path))

        return findings

    def audit(self, target_dir: Optional[Union[Path, str]] = None) -> List[DriverFinding]:
        """
        Performs a complete kernel driver security audit (both .sys files and scripts).

        Args:
            target_dir: Target directory to audit.

        Returns:
            Combined list of DriverFinding results.
        """
        root = Path(target_dir).resolve() if target_dir else self.target_dir
        if not root:
            return []

        all_findings: List[DriverFinding] = []
        all_findings.extend(self.scan_drivers(root))
        all_findings.extend(self.scan_scripts(root))
        return all_findings

    def audit_directory(self, target_dir: Optional[Union[Path, str]] = None) -> List[DriverFinding]:
        """Alias for audit()."""
        return self.audit(target_dir)

    def get_summary(self, findings: List[DriverFinding]) -> Dict[str, Any]:
        """
        Aggregates summary statistics for a set of driver findings.

        Args:
            findings: List of DriverFinding objects.

        Returns:
            Dictionary containing counts and high-level risk assessment.
        """
        total = len(findings)
        critical = sum(1 for f in findings if f.severity == "CRITICAL")
        high = sum(1 for f in findings if f.severity == "HIGH")
        byovd_count = sum(1 for f in findings if f.is_known_vulnerable_byovd)
        unsigned_count = sum(1 for f in findings if not f.is_signed and f.driver_name.lower().endswith(".sys"))

        return {
            "total_findings": total,
            "critical_count": critical,
            "high_count": high,
            "byovd_count": byovd_count,
            "unsigned_count": unsigned_count,
            "has_threats": critical > 0 or high > 0 or byovd_count > 0,
        }
