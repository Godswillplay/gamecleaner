"""
GameCleaner Web API Controller.
Exposes RESTful endpoints for static PE triage, clean emulators, containment,
save game vault, and real-time network radar.
"""

from dataclasses import asdict
from datetime import datetime, timezone
import os
from pathlib import Path
import shutil
import threading
from typing import Any, Dict, List, Optional, Union
import uuid

from gamecleaner.analyzer import ThreatSeverity
from gamecleaner.analyzer.sideload_auditor import SideloadAuditor
from gamecleaner.cleaner import (
    EmulatorReplacer,
    QuarantineManager,
    RepackUnpacker,
    SaveSyncManager,
    SteamlessUnpacker,
)
from gamecleaner.containment import (
    FirewallManager,
    NetworkMonitor,
    ProcessShield,
    SandboxGenerator,
    is_running_as_admin,
    is_sandbox_supported,
)
from gamecleaner.pipeline import GameCleanerPipeline


class WebAPI:
    """Zero-dependency API controller coordinating GameCleaner backend operations."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8443) -> None:
        self.host = host
        self.port = port
        self.version = "1.0.0"
        self._jobs: Dict[str, Dict[str, Any]] = {}
        self._jobs_lock = threading.Lock()

    # -------------------------------------------------------------------------
    # Asynchronous Job Execution Management
    # -------------------------------------------------------------------------

    def submit_job(self, job_type: str, func, *args, **kwargs) -> str:
        """Executes a long-running task asynchronously in a background worker thread."""
        job_id = str(uuid.uuid4())
        record = {
            "job_id": job_id,
            "type": job_type,
            "status": "running",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "completed_at": None,
            "result": None,
            "error": None,
        }
        with self._jobs_lock:
            self._jobs[job_id] = record

        def _worker():
            try:
                res = func(*args, **kwargs)
                with self._jobs_lock:
                    record["status"] = "completed"
                    record["result"] = res
                    record["completed_at"] = datetime.now(timezone.utc).isoformat()
            except Exception as e:
                with self._jobs_lock:
                    record["status"] = "failed"
                    record["error"] = str(e)
                    record["completed_at"] = datetime.now(timezone.utc).isoformat()

        t = threading.Thread(target=_worker, daemon=True)
        t.start()
        return job_id

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves current execution status and result for a registered job."""
        with self._jobs_lock:
            return self._jobs.get(job_id)

    # -------------------------------------------------------------------------
    # Core API Endpoints
    # -------------------------------------------------------------------------

    def get_status(self) -> Dict[str, Any]:
        """Returns overall system posture, admin status, and toolchain dependencies."""
        repo_root = Path(__file__).resolve().parent.parent.parent
        goldberg_dir = repo_root / "emulators" / "goldberg"
        goldberg_x86 = (goldberg_dir / "steam_api.dll").exists()
        goldberg_x64 = (goldberg_dir / "steam_api64.dll").exists()

        unpacker = RepackUnpacker()
        inno_path = unpacker.innoextract_exe if unpacker.innoextract_exe.exists() else shutil.which("innoextract")
        inno_avail = inno_path is not None and Path(inno_path).exists()

        steamless = SteamlessUnpacker()
        steamless_avail = steamless.is_available()
        steamless_p = steamless.get_steamless_path()

        return {
            "status": "operational",
            "version": self.version,
            "host": self.host,
            "port": self.port,
            "admin": is_running_as_admin(),
            "sandbox_supported": is_sandbox_supported(),
            "quarantine_count": 0,
            "tools": {
                "goldberg": {
                    "available": goldberg_x86 and goldberg_x64,
                    "x86": goldberg_x86,
                    "x64": goldberg_x64,
                    "path": str(goldberg_dir) if goldberg_dir.exists() else None,
                },
                "innoextract": {
                    "available": inno_avail,
                    "path": str(inno_path) if inno_path else None,
                },
                "steamless": {
                    "available": steamless_avail,
                    "path": str(steamless_p) if steamless_p else None,
                },
            },
        }

    def scan(self, target_path: Union[str, Path], async_mode: bool = False) -> Dict[str, Any]:
        """Scans PE binaries and scripts, classifies threat severity, and audits sideloads."""
        target = Path(target_path).resolve()
        if not target.exists():
            raise FileNotFoundError(f"Target path does not exist: {target}")

        def _do_scan():
            pipeline = GameCleanerPipeline(target)
            results = pipeline.run_scan_only()

            clean_count = 0
            medium_count = 0
            critical_count = 0
            file_records = []

            for res in results:
                if res.overall_severity == ThreatSeverity.CRITICAL.value:
                    critical_count += 1
                elif res.overall_severity in (ThreatSeverity.HIGH.value, ThreatSeverity.MEDIUM.value):
                    medium_count += 1
                else:
                    clean_count += 1

                file_records.append({
                    "file_name": res.file_name,
                    "relative_path": str(getattr(res, "file_path", res.file_name)),
                    "threat_score": res.threat_score,
                    "severity": res.overall_severity,
                    "verdict": res.verdict,
                    "recommended_action": res.recommended_action,
                    "architecture": getattr(res, "architecture", "Script/Binary"),
                })

            # Audit sideloaded DLLs
            sideload_findings = []
            try:
                auditor = SideloadAuditor(target)
                for s in auditor.audit():
                    sideload_findings.append(asdict(s))
            except Exception:
                pass

            # Inspect Process Shield executables
            shield_exes = []
            try:
                shield = ProcessShield(target)
                shield_exes = shield.get_target_exe_names()
            except Exception:
                pass

            return {
                "target_path": str(target),
                "total_files": len(results),
                "clean_count": clean_count,
                "medium_count": medium_count,
                "critical_count": critical_count,
                "files": file_records,
                "sideloads": sideload_findings,
                "shield_executables": shield_exes,
            }

        if async_mode:
            job_id = self.submit_job("scan", _do_scan)
            return {"job_id": job_id, "status": "running"}

        return _do_scan()

    def clean(self, target_path: Union[str, Path], options: Optional[Dict[str, Any]] = None, async_mode: bool = False) -> Dict[str, Any]:
        """Runs the complete GameCleaner remediation pipeline on the target folder."""
        target = Path(target_path).resolve()
        if not target.exists():
            raise FileNotFoundError(f"Target path does not exist: {target}")

        options = options or {}

        def _do_clean():
            pipeline = GameCleanerPipeline(
                target,
                auto_quarantine=options.get("auto_quarantine", True),
                auto_replace_emu=options.get("auto_replace_emu", True),
                auto_migrate_saves=options.get("auto_migrate_saves", True),
                auto_firewall=options.get("auto_firewall", True),
                generate_sandbox=options.get("generate_sandbox", True),
            )
            report = pipeline.run_full_pipeline()
            return asdict(report)

        if async_mode:
            job_id = self.submit_job("clean", _do_clean)
            return {"job_id": job_id, "status": "running"}

        return _do_clean()

    # -------------------------------------------------------------------------
    # Save Game Snapshots
    # -------------------------------------------------------------------------

    def list_snapshots(self, target_path: Union[str, Path]) -> Dict[str, Any]:
        """Lists all captured point-in-time Goldberg save snapshots for a game."""
        target = Path(target_path).resolve()
        sync_mgr = SaveSyncManager()
        snapshots = sync_mgr.list_snapshots(target)
        return {
            "target_path": str(target),
            "snapshots": [asdict(s) for s in snapshots],
        }

    def create_snapshot(
        self,
        target_path: Union[str, Path],
        note: str = "Web Dashboard Snapshot",
        appid: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Creates a versioned .zip save snapshot."""
        target = Path(target_path).resolve()
        if not target.exists():
            raise FileNotFoundError(f"Target path does not exist: {target}")

        sync_mgr = SaveSyncManager()
        if not appid:
            replacer = EmulatorReplacer(target)
            appid = replacer.discover_appid(target) or "DefaultAppID"

        res = sync_mgr.create_snapshot(target, appid=str(appid), note=note)
        return {
            "success": res.success,
            "snapshot_path": res.snapshot_path,
            "error_message": res.error_message,
            "files_archived": res.files_archived,
            "size_bytes": res.size_bytes,
        }

    def restore_snapshot(self, target_path: Union[str, Path], snapshot_filename: str) -> Dict[str, Any]:
        """Restores a point-in-time save snapshot archive."""
        target = Path(target_path).resolve()
        if not target.exists():
            raise FileNotFoundError(f"Target path does not exist: {target}")

        sync_mgr = SaveSyncManager()
        success = sync_mgr.restore_snapshot(target, snapshot_filename)
        return {
            "success": success,
            "snapshot": snapshot_filename,
            "target_path": str(target),
        }

    # -------------------------------------------------------------------------
    # Process Shield & Containment
    # -------------------------------------------------------------------------

    def apply_shield(
        self,
        target_path: Union[str, Path],
        action: str = "apply",
        exe_names: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Applies or removes Windows Exploit Protection child-process mitigations."""
        target = Path(target_path).resolve()
        if not target.exists():
            raise FileNotFoundError(f"Target path does not exist: {target}")

        shield = ProcessShield(target)
        apply_script, remove_script = shield.generate_scripts()

        if action.lower() == "remove":
            results = shield.remove(exe_names)
        else:
            results = shield.apply(exe_names)

        return {
            "action": action,
            "target_path": str(target),
            "results": [asdict(r) for r in results],
            "apply_script": str(apply_script),
            "remove_script": str(remove_script),
            "is_admin": is_running_as_admin(),
        }

    def firewall(self, target_path: Union[str, Path], apply_rules: bool = False) -> Dict[str, Any]:
        """Generates firewall isolation scripts and optionally applies rules."""
        target = Path(target_path).resolve()
        if not target.exists():
            raise FileNotFoundError(f"Target path does not exist: {target}")

        fw = FirewallManager(target)
        block_ps1, unblock_ps1 = fw.generate_scripts()
        fix_launcher = fw.generate_fix_and_run_script()

        applied_rules = []
        if apply_rules and is_running_as_admin():
            results = fw.apply_firewall_rules()
            applied_rules = [asdict(r) for r in results]

        return {
            "target_path": str(target),
            "block_script": str(block_ps1),
            "unblock_script": str(unblock_ps1),
            "fix_launcher": str(fix_launcher),
            "rules_applied": len(applied_rules) > 0,
            "applied_results": applied_rules,
        }

    def sandbox(
        self,
        target_path: Union[str, Path],
        read_only: bool = True,
        v_gpu: bool = True,
        allow_network: bool = False,
    ) -> Dict[str, Any]:
        """Generates a dedicated Windows Sandbox (.wsb) disposable profile."""
        target = Path(target_path).resolve()
        if not target.exists():
            raise FileNotFoundError(f"Target path does not exist: {target}")

        gen = SandboxGenerator(target)
        wsb_path = gen.generate_wsb(read_only=read_only, v_gpu=v_gpu, allow_network=allow_network)
        return {
            "target_path": str(target),
            "wsb_path": str(wsb_path),
            "supported_on_host": is_sandbox_supported(),
        }

    def replace_emulator(self, target_path: Union[str, Path]) -> Dict[str, Any]:
        """Identifies DRM wrapper DLLs and replaces them with clean Goldberg emulators."""
        target = Path(target_path).resolve()
        if not target.exists():
            raise FileNotFoundError(f"Target path does not exist: {target}")

        replacer = EmulatorReplacer(target)
        drm_targets = replacer.find_drm_targets()
        replaced = []

        for tgt in drm_targets:
            ok, msg = replacer.replace_with_clean_emulator(tgt)
            if ok:
                replaced.append(tgt.dll_name)

        return {
            "target_path": str(target),
            "drm_targets_found": len(drm_targets),
            "replaced": replaced,
        }

    # -------------------------------------------------------------------------
    # Network Radar & Quarantine
    # -------------------------------------------------------------------------

    def network_monitor(self, target: Optional[Union[str, int]] = None) -> Dict[str, Any]:
        """Samples active network socket connections and categorizes endpoints."""
        mon = NetworkMonitor(target=target)
        records = mon.sample_connections()
        return {
            "target": str(target) if target else "ALL",
            "total_observed": len(records),
            "records": [r.to_dict() for r in records],
        }

    def list_quarantine(self, target_path: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
        """Lists files currently held in the quarantine vault."""
        if not target_path:
            return {"quarantined_files": [], "manifest": {}}

        target = Path(target_path).resolve()
        qm = QuarantineManager(target)
        records = qm.list_quarantined()
        manifest = qm._load_manifest()

        return {
            "target_path": str(target),
            "quarantined_files": [asdict(r) for r in records],
            "manifest": manifest,
        }
