"""
GameCleaner Pipeline: Orchestrates scanning, triage, quarantine, emulator replacement, and containment.
"""
from dataclasses import asdict, dataclass, field
from datetime import datetime
import json
from pathlib import Path
from typing import Dict, List, Optional

from gamecleaner.analyzer import PEScanResult, PEScanner, ThreatSeverity, VirusTotalClient, VTAnalysisResult
from gamecleaner.cleaner import DRMTarget, EmulatorReplacer, QuarantineManager
from gamecleaner.containment import FirewallManager, SandboxGenerator


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
    firewall_script_created: Optional[str] = None
    sandbox_file_created: Optional[str] = None
    file_results: List[Dict] = field(default_factory=list)


class GameCleanerPipeline:
    """End-to-end security orchestrator for cracked and untrusted game directories."""

    def __init__(
        self,
        target_dir: Path,
        vt_api_key: Optional[str] = None,
        auto_quarantine: bool = True,
        auto_replace_emu: bool = True,
        auto_firewall: bool = True,
        generate_sandbox: bool = True,
    ):
        self.target_dir = Path(target_dir).resolve()
        self.scanner = PEScanner()
        self.vt_client = VirusTotalClient(api_key=vt_api_key)
        self.quarantine_mgr = QuarantineManager(self.target_dir)
        self.emu_replacer = EmulatorReplacer(self.target_dir)
        self.firewall_mgr = FirewallManager(self.target_dir)
        self.sandbox_gen = SandboxGenerator(self.target_dir)

        self.auto_quarantine = auto_quarantine
        self.auto_replace_emu = auto_replace_emu
        self.auto_firewall = auto_firewall
        self.generate_sandbox = generate_sandbox

    def run_scan_only(self) -> List[PEScanResult]:
        """Scans all PE binaries in the directory and returns their results."""
        results = []
        extensions = {".exe", ".dll", ".sys", ".scr"}

        for path in self.target_dir.rglob("*"):
            if path.is_file() and path.suffix.lower() in extensions:
                if ".gamecleaner" in str(path) or ".quarantine" in str(path):
                    continue
                try:
                    res = self.scanner.scan_file(path)
                    if res.is_pe or res.findings or res.threat_score > 0:
                        results.append(res)
                except Exception:
                    continue
        return results

    def run_full_pipeline(self) -> PipelineReport:
        """Executes the full triage, clean replacement, quarantine, and containment workflow."""
        scan_results = self.run_scan_only()

        report = PipelineReport(
            target_dir=str(self.target_dir),
            scan_timestamp=datetime.now().isoformat(),
            total_files_scanned=len(scan_results),
            clean_files=0,
            suspicious_files=0,
            critical_threats=0,
            drm_targets_found=0,
        )

        critical_to_quarantine: List[PEScanResult] = []

        for res in scan_results:
            # Query VirusTotal if configured
            vt_info: Optional[VTAnalysisResult] = None
            if self.vt_client.is_configured and res.sha256:
                vt_info = self.vt_client.lookup_hash(res.sha256)
                if vt_info and vt_info.found:
                    if vt_info.is_malware:
                        res.overall_severity = ThreatSeverity.CRITICAL.value
                        res.verdict = f"VT Confirmed Malware: {', '.join(vt_info.detected_families[:2])}"
                        res.recommended_action = "QUARANTINE"

            # Tally counts
            if res.overall_severity == ThreatSeverity.CRITICAL.value:
                report.critical_threats += 1
                critical_to_quarantine.append(res)
            elif res.overall_severity in (ThreatSeverity.HIGH.value, ThreatSeverity.MEDIUM.value):
                report.suspicious_files += 1
            else:
                report.clean_files += 1

            report.file_results.append({
                "file_name": res.file_name,
                "relative_path": str(res.file_path.relative_to(self.target_dir)),
                "architecture": res.architecture,
                "sha256": res.sha256,
                "threat_score": res.threat_score,
                "severity": res.overall_severity,
                "verdict": res.verdict,
                "recommended_action": res.recommended_action,
                "findings": [asdict(f) for f in res.findings],
                "vt_summary": vt_info.summary if vt_info else None,
            })

        # 1. Quarantine Action
        if self.auto_quarantine:
            for item in critical_to_quarantine:
                dest = self.quarantine_mgr.quarantine_file(
                    item.file_path,
                    reason=item.verdict,
                    sha256=item.sha256,
                )
                if dest:
                    report.quarantined_files.append(item.file_name)

        # 2. Clean Emulator Replacement Action
        drm_targets = self.emu_replacer.find_drm_targets()
        report.drm_targets_found = len(drm_targets)
        if self.auto_replace_emu and drm_targets:
            for tgt in drm_targets:
                success, msg = self.emu_replacer.replace_with_clean_emulator(tgt)
                if success:
                    report.replaced_emulators.append(tgt.dll_name)

        # 3. Firewall Isolation Action
        if self.auto_firewall:
            block_ps1, _ = self.firewall_mgr.generate_scripts()
            report.firewall_script_created = str(block_ps1)
            # Try to apply rules directly if running with admin rights
            self.firewall_mgr.apply_firewall_rules()

        # 4. Windows Sandbox Profile Action
        if self.generate_sandbox:
            wsb_path = self.sandbox_gen.generate_wsb(read_only=True, v_gpu=True, allow_network=False)
            report.sandbox_file_created = str(wsb_path)

        # Save Report to Disk
        self._write_reports(report)

        return report

    def _write_reports(self, report: PipelineReport):
        """Generates JSON and Markdown reports in target directory."""
        json_path = self.target_dir / "gamecleaner_report.json"
        md_path = self.target_dir / "gamecleaner_report.md"

        json_path.write_text(json.dumps(asdict(report), indent=2), encoding="utf-8")

        # Generate Markdown summary
        md_lines = [
            f"# GameCleaner Security Audit Report",
            f"**Target Directory:** `{report.target_dir}`  ",
            f"**Audit Time:** `{report.scan_timestamp}`  ",
            "",
            "## Summary of Findings",
            f"- **Total Binaries Scanned:** {report.total_files_scanned}",
            f"- **Clean Binaries:** {report.clean_files}",
            f"- **Suspicious / DRM Hooked Files:** {report.suspicious_files}",
            f"- **Critical Hostile Threats:** {report.critical_threats}",
            f"- **Steam DRM Hooks Found:** {report.drm_targets_found}",
            "",
            "## Actions Taken",
            f"- **Quarantined Malicious Binaries:** {len(report.quarantined_files)} ({', '.join(report.quarantined_files) if report.quarantined_files else 'None'})",
            f"- **Replaced with Clean Open-Source Emulator:** {len(report.replaced_emulators)} ({', '.join(report.replaced_emulators) if report.replaced_emulators else 'None'})",
            f"- **Firewall Script:** `{report.firewall_script_created or 'N/A'}`",
            f"- **Sandbox Profile:** `{report.sandbox_file_created or 'N/A'}`",
            "",
            "## Detailed Binary Triage",
            "| File | Architecture | Severity | Threat Score | Verdict | Recommended Action |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ]

        for item in report.file_results:
            md_lines.append(
                f"| `{item['file_name']}` | {item['architecture']} | {item['severity']} | {item['threat_score']}/100 | {item['verdict']} | `{item['recommended_action']}` |"
            )

        md_path.write_text("\n".join(md_lines), encoding="utf-8")
