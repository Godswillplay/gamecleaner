"""
GameCleaner Pipeline: Orchestrates scanning, triage, quarantine, emulator replacement, save migration, AI triage, and containment.
"""
import concurrent.futures
from dataclasses import asdict, dataclass, field
from datetime import datetime
import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Union

from gamecleaner.analyzer import (
    AIDecompilerClassifier,
    PEScanResult,
    PEScanner,
    ScriptScanResult,
    ScriptScanner,
    ThreatSeverity,
    VirusTotalClient,
    VTAnalysisResult,
)
from gamecleaner.analyzer.lnk_scanner import LnkScanResult, LnkScanner
from gamecleaner.analyzer.persistence_auditor import PersistenceAuditor, PersistenceEntry
from gamecleaner.analyzer.runtime_auditor import RuntimeAuditor, RuntimeAuditReport
from gamecleaner.analyzer.sideload_auditor import SideloadAuditor, SideloadFinding
from gamecleaner.analyzer.steam_stub import SteamStubDetector, SteamStubResult
from gamecleaner.analyzer.driver_auditor import DriverAuditor, DriverFinding
from gamecleaner.analyzer.anticheat_detector import AntiCheatDetector, AntiCheatScanReport
from gamecleaner.analyzer.mod_compat import ModCompatibilityAuditor, ModAuditReport
from gamecleaner.analyzer.crash_forensics import CrashForensics, CrashReport
from gamecleaner.cleaner import (
    DRMTarget,
    EmulatorReplacer,
    QuarantineManager,
    SaveGameMigrator,
    IntegrityVerifier,
    IntegrityReport,
    SteamlessUnpacker,
    SteamlessResult,
    EOSReplacer,
    MultiDRMOrchestrator,
    MultiDRMReport,
)
from gamecleaner.containment import (
    FirewallManager,
    SandboxGenerator,
    ProcessShield,
    ShieldResult,
    ProtonHelper,
    ProtonScriptResult,
    is_running_as_admin,
    is_sandbox_supported,
)


@dataclass
class PipelineReport:
    target_dir: str
    scan_timestamp: str
    total_files_scanned: int
    clean_files: int
    suspicious_files: int
    critical_threats: int
    drm_targets_found: int
    quarantined_files: List[str] = field(default_factory=list)
    replaced_emulators: List[str] = field(default_factory=list)
    saves_migrated: Optional[Dict] = None
    ai_triage_reports: List[Dict] = field(default_factory=list)
    persistence_entries_found: int = 0
    persistence_cleaned: List[str] = field(default_factory=list)
    firewall_script_created: Optional[str] = None
    fix_firewall_script_created: Optional[str] = None
    firewall_rules_applied: bool = False
    sandbox_file_created: Optional[str] = None
    sandbox_supported_on_host: bool = False
    sideload_findings: List[Dict] = field(default_factory=list)
    steam_stub_findings: List[Dict] = field(default_factory=list)
    driver_findings: List[Dict] = field(default_factory=list)
    anticheat_findings: List[Dict] = field(default_factory=list)
    mod_findings: List[Dict] = field(default_factory=list)
    multidrm_layers: List[Dict] = field(default_factory=list)
    crash_diagnostics: Optional[Dict] = None
    process_shield_script: Optional[str] = None
    proton_script_created: Optional[str] = None
    steamless_unpacked_files: List[str] = field(default_factory=list)
    missing_runtime_dependencies: List[Dict] = field(default_factory=list)
    discovered_redists: List[Dict] = field(default_factory=list)
    integrity_manifest_created: Optional[str] = None
    file_results: List[Dict] = field(default_factory=list)


class GameCleanerPipeline:
    """End-to-end security orchestrator for cracked and untrusted game directories."""

    def __init__(
        self,
        target_dir: Path,
        vt_api_key: Optional[str] = None,
        auto_quarantine: bool = True,
        auto_replace_emu: bool = True,
        auto_migrate_saves: bool = True,
        auto_firewall: bool = True,
        generate_sandbox: bool = True,
        enable_ai_triage: bool = True,
        auto_verify_integrity: bool = True,
        enable_steamless: bool = True,
    ):
        self.target_dir = Path(target_dir).resolve()
        self.pe_scanner = PEScanner()
        self.script_scanner = ScriptScanner()
        self.lnk_scanner = LnkScanner()
        self.persistence_auditor = PersistenceAuditor(self.target_dir)
        self.sideload_auditor = SideloadAuditor(self.target_dir)
        self.driver_auditor = DriverAuditor(self.target_dir)
        self.anticheat_detector = AntiCheatDetector(self.target_dir)
        self.mod_auditor = ModCompatibilityAuditor(self.target_dir)
        self.crash_forensics = CrashForensics(self.target_dir)
        self.runtime_auditor = RuntimeAuditor(self.target_dir)
        self.integrity_verifier = IntegrityVerifier(self.target_dir)
        self.process_shield = ProcessShield(self.target_dir)
        self.proton_helper = ProtonHelper(self.target_dir)
        self.steamless_unpacker = SteamlessUnpacker(tools_dir=self.target_dir / "tools")
        self.vt_client = VirusTotalClient(api_key=vt_api_key)
        self.quarantine_mgr = QuarantineManager(self.target_dir)
        self.emu_replacer = EmulatorReplacer(self.target_dir)
        self.eos_replacer = EOSReplacer(self.target_dir)
        self.multidrm = MultiDRMOrchestrator(self.target_dir)
        self.save_migrator = SaveGameMigrator(self.target_dir)
        self.ai_classifier = AIDecompilerClassifier()
        self.firewall_mgr = FirewallManager(self.target_dir)
        self.sandbox_gen = SandboxGenerator(self.target_dir)

        self.auto_quarantine = auto_quarantine
        self.auto_replace_emu = auto_replace_emu
        self.auto_migrate_saves = auto_migrate_saves
        self.auto_firewall = auto_firewall
        self.generate_sandbox = generate_sandbox
        self.enable_ai_triage = enable_ai_triage
        self.auto_verify_integrity = auto_verify_integrity
        self.enable_steamless = enable_steamless

    def run_scan_only(self) -> List[Union[PEScanResult, ScriptScanResult, LnkScanResult]]:
        """Scans all PE binaries, scripts, and LNK shortcuts in parallel across CPU cores using fast directory walking."""
        results = []
        pe_extensions = {".exe", ".dll", ".sys", ".scr"}
        script_extensions = {".bat", ".cmd", ".vbs", ".ps1"}
        lnk_extensions = {".lnk"}

        file_list = []

        # Fast directory walking with os.scandir (caches directory entries & avoids stat overhead on asset files)
        def _walk_fast(dir_path: str):
            try:
                with os.scandir(dir_path) as it:
                    for entry in it:
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                if ".gamecleaner" not in entry.name and ".quarantine" not in entry.name:
                                    _walk_fast(entry.path)
                            elif entry.is_file(follow_symlinks=False):
                                ext = os.path.splitext(entry.name)[1].lower()
                                if ext in pe_extensions or ext in script_extensions or ext in lnk_extensions:
                                    file_list.append(Path(entry.path))
                        except Exception:
                            continue
            except (PermissionError, FileNotFoundError):
                pass

        if self.target_dir.is_file():
            ext = self.target_dir.suffix.lower()
            if ext in pe_extensions or ext in script_extensions or ext in lnk_extensions:
                file_list.append(self.target_dir)
        else:
            _walk_fast(str(self.target_dir))

        def _scan_worker(p: Path):
            ext = p.suffix.lower()
            if ext in pe_extensions:
                return self.pe_scanner.scan_file(p)
            elif ext in script_extensions:
                return self.script_scanner.scan_file(p)
            elif ext in lnk_extensions:
                return self.lnk_scanner.scan_file(p)
            return None

        # Execute in parallel with ThreadPoolExecutor
        max_workers = min(32, (os.cpu_count() or 4) * 4)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_file = {executor.submit(_scan_worker, f): f for f in file_list}
            for future in concurrent.futures.as_completed(future_to_file):
                try:
                    res = future.result()
                    if res:
                        results.append(res)
                except Exception:
                    pass

        return results

    def run_full_pipeline(self) -> PipelineReport:
        """Executes full security pipeline: scan -> AI triage -> save migration -> emu replacement -> quarantine -> firewall -> sandbox."""
        report = PipelineReport(
            target_dir=str(self.target_dir),
            scan_timestamp=datetime.now().isoformat(),
            total_files_scanned=0,
            clean_files=0,
            suspicious_files=0,
            critical_threats=0,
            drm_targets_found=0,
            sandbox_supported_on_host=is_sandbox_supported(),
        )

        scan_results = self.run_scan_only()
        report.total_files_scanned = len(scan_results)

        critical_to_quarantine = []

        for res in scan_results:
            # Check VirusTotal if configured and is PE result
            vt_info: Optional[VTAnalysisResult] = None
            if isinstance(res, PEScanResult) and self.vt_client.is_configured and res.sha256:
                vt_info = self.vt_client.lookup_hash(res.sha256)
                if vt_info and vt_info.found and vt_info.is_malware:
                    res.overall_severity = ThreatSeverity.CRITICAL.value
                    res.verdict = f"VT Confirmed Malware: {', '.join(vt_info.detected_families[:2])}"
                    res.recommended_action = "QUARANTINE"

            # Tally threat counts
            if res.overall_severity == ThreatSeverity.CRITICAL.value:
                report.critical_threats += 1
                critical_to_quarantine.append(res)
            elif res.overall_severity in (ThreatSeverity.HIGH.value, ThreatSeverity.MEDIUM.value):
                report.suspicious_files += 1
                if res.recommended_action == "QUARANTINE":
                    critical_to_quarantine.append(res)
            else:
                report.clean_files += 1

            findings_list = [asdict(f) for f in res.findings]
            if isinstance(res, PEScanResult):
                type_str = res.architecture
            elif isinstance(res, ScriptScanResult):
                type_str = f"Script ({res.extension})"
            else:
                type_str = "LNK Shortcut"

            try:
                rel_path = str(res.file_path.relative_to(self.target_dir))
            except ValueError:
                rel_path = res.file_name

            report.file_results.append({
                "file_name": res.file_name,
                "relative_path": rel_path,
                "architecture": type_str,
                "sha256": getattr(res, "sha256", ""),
                "threat_score": res.threat_score,
                "severity": res.overall_severity,
                "verdict": res.verdict,
                "recommended_action": res.recommended_action,
                "findings": findings_list,
                "vt_summary": vt_info.summary if vt_info else None,
            })

        # Step 0: Steam Stub DRM & Deep Triage
        for res in scan_results:
            if isinstance(res, PEScanResult) and res.file_path.suffix.lower() == ".exe":
                try:
                    stub_res = SteamStubDetector(res.file_path).scan()
                    if stub_res.is_wrapped:
                        report.steam_stub_findings.append(asdict(stub_res))
                        # If Steamless CLI is available, automatically unpack SteamStub DRM
                        if self.enable_steamless and self.steamless_unpacker.is_available():
                            unpack_res = self.steamless_unpacker.unpack_binary(res.file_path, backup=True)
                            if unpack_res.success:
                                report.steamless_unpacked_files.append(res.file_name)
                except Exception:
                    pass

        # Step 0a: Audit Kernel Drivers (.sys) and BYOVD Threats
        try:
            drv_findings = self.driver_auditor.audit()
            for df in drv_findings:
                report.driver_findings.append(asdict(df))
                if df.severity in (ThreatSeverity.HIGH, ThreatSeverity.CRITICAL):
                    report.critical_threats += 1
                    critical_to_quarantine.append(res)
        except Exception:
            pass

        # Step 0b: Audit DLL Search-Order Hijacking & Proxy DLLs
        try:
            sideloads = self.sideload_auditor.audit()
            for sl in sideloads:
                report.sideload_findings.append(asdict(sl))
                if sl.severity == ThreatSeverity.HIGH:
                    report.critical_threats += 1
        except Exception:
            pass

        # Step 0c: Audit Required Runtimes & Repack Redists
        try:
            rt_report = self.runtime_auditor.audit()
            for dep in rt_report.missing_dependencies:
                report.missing_runtime_dependencies.append(asdict(dep))
            for rd in rt_report.discovered_redists:
                report.discovered_redists.append(asdict(rd))
        except Exception:
            pass

        # Step 0d: Anti-Cheat & Binary Protector Triage
        try:
            ac_report = self.anticheat_detector.scan()
            for f in ac_report.findings:
                report.anticheat_findings.append(asdict(f))
                if f.is_vulnerable_driver:
                    report.critical_threats += 1
        except Exception:
            pass

        # Step 0e: Mod Frameworks & Proxy Chains Audit
        try:
            mod_report = self.mod_auditor.audit()
            for m in mod_report.detected_mods:
                report.mod_findings.append(asdict(m))
        except Exception:
            pass

        # Step 0f: Crash Forensics Diagnosis (if applicable)
        try:
            crash_rep = self.crash_forensics.diagnose_crash()
            if crash_rep and crash_rep.incidents:
                report.crash_diagnostics = asdict(crash_rep)
        except Exception:
            pass

        # Step 0g: AI-Assisted Decompiler Triage on Top Threats
        if self.enable_ai_triage:
            for item in critical_to_quarantine[:5]:
                if isinstance(item, PEScanResult):
                    try:
                        ai_payload = self.ai_classifier.build_triage_payload(item)
                        report.ai_triage_reports.append(asdict(ai_payload))
                    except Exception:
                        pass

        # Step 1: Clean Emulator Replacement (Runs before quarantine to preserve DRM target hooks)
        drm_targets = self.emu_replacer.find_drm_targets()
        report.drm_targets_found = len(drm_targets)
        handled_drm_paths = set()

        if self.auto_replace_emu and drm_targets:
            for tgt in drm_targets:
                success, msg = self.emu_replacer.replace_with_clean_emulator(tgt)
                if success:
                    report.replaced_emulators.append(tgt.dll_name)
                    handled_drm_paths.add(tgt.full_path.resolve())

        # Step 1a: Multi-DRM Orchestration (Epic EOS & Unified Triage)
        try:
            md_report = self.multidrm.triage()
            for layer in md_report.active_layers:
                report.multidrm_layers.append(asdict(layer))
            if self.auto_replace_emu and md_report.has_eos:
                eos_results = self.eos_replacer.replace_all()
                for er in eos_results:
                    if er.success and er.replacement_applied:
                        report.replaced_emulators.append(er.target.dll_name)
                        handled_drm_paths.add(er.target.full_path.resolve())
        except Exception:
            pass

        # Step 1b: Save Game and SteamID Migration
        if self.auto_migrate_saves:
            try:
                mig_result = self.save_migrator.migrate_saves()
                report.saves_migrated = asdict(mig_result)
            except Exception:
                pass

        # Step 2: Quarantine Hostile Payloads (Excluding already-replaced clean emulators)
        if self.auto_quarantine:
            for item in critical_to_quarantine:
                if item.file_path.resolve() in handled_drm_paths:
                    continue  # Already safely replaced with clean Goldberg emulator
                dest = self.quarantine_mgr.quarantine_file(
                    item.file_path,
                    reason=item.verdict,
                    sha256=getattr(item, "sha256", ""),
                )
                if dest:
                    report.quarantined_files.append(item.file_name)

        # Step 3: Audit & Clean System Persistence (Scheduled Tasks / Registry Run keys)
        persistence_entries = self.persistence_auditor.audit_all()
        report.persistence_entries_found = len(persistence_entries)
        if self.auto_quarantine and persistence_entries:
            for p_entry in persistence_entries:
                if self.persistence_auditor.remove_persistence(p_entry):
                    report.persistence_cleaned.append(f"{p_entry.entry_type}: {p_entry.name}")

        # Step 4: Firewall Isolation Action
        if self.auto_firewall:
            block_ps1, _ = self.firewall_mgr.generate_scripts()
            report.firewall_script_created = str(block_ps1)
            fix_bat = self.firewall_mgr.generate_fix_and_run_script()
            report.fix_firewall_script_created = str(fix_bat)
            if is_running_as_admin():
                fw_results = self.firewall_mgr.apply_firewall_rules()
                report.firewall_rules_applied = any(r.status == "Applied" for r in fw_results)
            else:
                report.firewall_rules_applied = False

        # Step 5: Windows Sandbox Profile & Offline Isolated Launcher
        if self.generate_sandbox:
            wsb_path = self.sandbox_gen.generate_wsb(read_only=True, v_gpu=True, allow_network=False)
            report.sandbox_file_created = str(wsb_path)

        # Step 5b: Windows Exploit Protection Shield Scripts (Child process blocking)
        try:
            shield_script = self.process_shield.generate_shield_script()
            report.process_shield_script = str(shield_script)
        except Exception:
            pass

        # Step 5c: Steam Deck & Linux Proton Compatibility Script
        try:
            proton_res = self.proton_helper.generate_scripts()
            report.proton_script_created = str(proton_res.script_path)
        except Exception:
            pass

        # Step 6: Cryptographic Game Integrity Manifest Generation
        if self.auto_verify_integrity and self.target_dir.is_dir():
            try:
                manifest_p = self.integrity_verifier.create_manifest()
                report.integrity_manifest_created = str(manifest_p)
            except Exception:
                pass

        # Save Report to Disk
        self._write_reports(report)

        return report

    def _write_reports(self, report: PipelineReport):
        """Generates JSON and Markdown reports in target directory."""
        report_dir = self.target_dir if self.target_dir.is_dir() else self.target_dir.parent
        json_path = report_dir / "gamecleaner_report.json"
        md_path = report_dir / "gamecleaner_report.md"

        json_path.write_text(json.dumps(asdict(report), indent=2), encoding="utf-8")

        lines = [
            f"# GameCleaner Security Triage Report",
            f"**Target Directory:** `{report.target_dir}`",
            f"**Timestamp:** `{report.scan_timestamp}`",
            f"",
            f"## Summary",
            f"- **Total Files Scanned:** {report.total_files_scanned}",
            f"- **Clean Binaries:** {report.clean_files}",
            f"- **Suspicious / Cracked:** {report.suspicious_files}",
            f"- **Critical Threats:** {report.critical_threats}",
            f"- **DRM Targets Found:** {report.drm_targets_found}",
            f"- **Quarantined Files:** {len(report.quarantined_files)}",
            f"- **Replaced Emulators:** {len(report.replaced_emulators)}",
            f"- **Persistence Cleaned:** {len(report.persistence_cleaned)}",
            f"- **Firewall Script:** `{report.firewall_script_created}`",
            f"- **Fix & Run Launcher:** `{report.fix_firewall_script_created}`",
            f"- **Sandbox Profile:** `{report.sandbox_file_created}`",
            f"",
        ]

        if report.saves_migrated and report.saves_migrated.get("goldberg_settings_configured"):
            lines.extend([
                f"## Save Game & Identity Migration",
                f"- **AppID Configured:** `{report.saves_migrated.get('app_id')}`",
                f"- **Account Name:** `{report.saves_migrated.get('account_name')}`",
                f"- **Source Saves:** `{report.saves_migrated.get('saves_found_at')}`",
                f"- **Migrated To:** `{report.saves_migrated.get('saves_migrated_to')}`",
                f"- **Files Copied:** {len(report.saves_migrated.get('migrated_files', []))}",
                f"",
            ])

        if report.quarantined_files:
            lines.append("## Quarantined Binaries")
            for q in report.quarantined_files:
                lines.append(f"- `{q}`")
            lines.append("")

        if report.replaced_emulators:
            lines.append("## Replaced Clean Emulators")
            for r in report.replaced_emulators:
                lines.append(f"- `{r}` (Clean Open-Source Goldberg Emulator)")
            lines.append("")

        if report.steam_stub_findings:
            lines.append("## Steam Stub DRM Warnings")
            for stub in report.steam_stub_findings:
                lines.append(f"- **Binary:** `{Path(stub['file_path']).name}` ({stub['stub_version']})")
                lines.append(f"  - *Guidance:* {stub['guidance']}")
            lines.append("")

        if report.sideload_findings:
            lines.append("## DLL Sideloading & Proxy Auditor")
            for sl in report.sideload_findings:
                status_str = "Legitimate Mod Framework" if sl['is_legitimate_mod'] else f"Severity: {sl['severity']}"
                lines.append(f"- **DLL:** `{sl['dll_name']}` ({status_str})")
                lines.append(f"  - *Description:* {sl['description']}")
            lines.append("")

        if report.missing_runtime_dependencies:
            lines.append("## Missing Runtime Dependencies")
            for dep in report.missing_runtime_dependencies:
                lines.append(f"- **Required DLL:** `{dep['dll_name']}` ({dep['package_name']})")
                if dep.get('install_command'):
                    lines.append(f"  - *Install via:* `{dep['install_command']}`")
            lines.append("")

        if report.discovered_redists:
            lines.append("## Bundled Repack Installers")
            for rd in report.discovered_redists:
                lines.append(f"- `{rd['name']}`: `{rd['file_path']}` (Silent args: `{rd['recommended_silent_args']}`)")
            lines.append("")

        if report.driver_findings:
            lines.append("## Kernel Driver & Rootkit Findings")
            for df in report.driver_findings:
                byovd_str = "KNOWN BYOVD EXPLOIT" if df['is_known_vulnerable_byovd'] else "Unsigned/Third-Party Driver"
                lines.append(f"- **Driver:** `{df['driver_name']}` ({byovd_str} - Severity: {df['severity']})")
                lines.append(f"  - *Details:* {df['description']}")
            lines.append("")

        if report.steamless_unpacked_files:
            lines.append("## Steamless DRM Unpacking")
            for sf in report.steamless_unpacked_files:
                lines.append(f"- `{sf}` (SteamStub DRM successfully unpacked & swapped)")
            lines.append("")

        if report.anticheat_findings:
            lines.append("## Anti-Cheat & Binary Protector Triage")
            for ac in report.anticheat_findings:
                lines.append(f"- **Protection:** `{ac['protection_name']}` (Status: {ac['status']})")
                lines.append(f"  - *Details:* {ac['description']}")
            lines.append("")

        if report.mod_findings:
            lines.append("## Game Mod Frameworks & Hooks")
            for mf in report.mod_findings:
                lines.append(f"- **Framework:** `{mf['framework_name']}` (`{mf['root_dll_name']}`)")
            lines.append("")

        if report.multidrm_layers:
            lines.append("## Multi-DRM Layers")
            for ml in report.multidrm_layers:
                lines.append(f"- **Platform:** `{ml['platform']}` (Files: {', '.join(ml['detected_files'])})")
            lines.append("")

        if report.crash_diagnostics:
            lines.append("## Crash Forensics Diagnostics")
            lines.append(f"- **Root Cause:** {report.crash_diagnostics.get('root_cause_diagnosis', 'N/A')}")
            lines.append(f"- **Guidance:** {report.crash_diagnostics.get('remediation_guidance', 'N/A')}")
            lines.append("")

        if report.process_shield_script:
            lines.append(f"## Exploit Protection & Child Process Blocker")
            lines.append(f"- Protection script created: `{report.process_shield_script}`")
            lines.append(f"- Run with PowerShell as Administrator to prevent game from spawning child processes.")
            lines.append("")

        if report.proton_script_created:
            lines.append(f"## Steam Deck & Linux Proton Launcher")
            lines.append(f"- Proton runner generated: `{report.proton_script_created}`")
            lines.append(f"- Includes network namespace isolation and Wine DLL overrides.")
            lines.append("")

        if report.integrity_manifest_created:
            lines.append(f"## Cryptographic Integrity Manifest")
            lines.append(f"- Manifest generated at: `{report.integrity_manifest_created}`")
            lines.append(f"- Run `gamecleaner verify \"{report.target_dir}\"` at any time to verify file integrity.")
            lines.append("")

        if report.ai_triage_reports:
            lines.append("## AI Decompiler Triage Reports")
            for ai in report.ai_triage_reports:
                lines.append(f"### Binary: `{Path(ai['binary_path']).name}`")
                lines.append(f"- **Verdict:** `{ai['offline_heuristic_verdict']}` (Confidence: {ai['offline_confidence']*100:.0f}%)")
                lines.append(f"- **Suspicious APIs:** `{', '.join(ai['suspicious_apis']) or 'None'}`")
                lines.append(f"- **Critical Strings:** `{', '.join(ai['critical_strings'][:3]) or 'None'}`")
                lines.append("")

        lines.extend([
            f"## Containment Recommendations",
            f"1. **Network Isolation:** Run `{report.firewall_script_created}` as Administrator to prevent outbound connections.",
            f"2. **Firewall Fix & Launch:** Run `{report.fix_firewall_script_created}` as Administrator to clean accidental blocks and launch.",
            f"3. **Air-Gapped Sandbox:** Open `{report.sandbox_file_created}` to test the game inside an ephemeral Windows Sandbox without risking your host OS.",
            f"4. **Quarantine Vault:** Quarantined files are isolated in `.gamecleaner_quarantine` with zero execute permissions.",
        ])

        md_path.write_text("\n".join(lines), encoding="utf-8")
