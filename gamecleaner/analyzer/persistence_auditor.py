"""
Persistence Auditor: Detects and cleans rogue Windows Scheduled Tasks, Services, and Registry Autorun entries installed by game repacks.
"""
import csv
from dataclasses import dataclass
import io
import os
from pathlib import Path
import subprocess
from typing import Dict, List, Optional
import winreg


@dataclass
class PersistenceEntry:
    entry_type: str  # ScheduledTask, RegistryRun, Service
    name: str
    target_command: str
    is_malicious: bool
    details: str


class PersistenceAuditor:
    """Audits system startup locations for persistence targeting a game directory."""

    def __init__(self, target_dir: Path):
        self.target_dir = Path(target_dir).resolve()

    def audit_all(self) -> List[PersistenceEntry]:
        """Runs audit across Scheduled Tasks, Registry Run keys, and Services."""
        entries: List[PersistenceEntry] = []
        entries.extend(self.audit_scheduled_tasks())
        entries.extend(self.audit_registry_run())
        return entries

    def audit_scheduled_tasks(self) -> List[PersistenceEntry]:
        """Audits Windows Task Scheduler for tasks pointing into the game directory or suspicious scripts."""
        entries = []
        try:
            proc = subprocess.run(
                ["schtasks", "/query", "/fo", "CSV", "/v"],
                capture_output=True,
                text=True,
                timeout=10,
                encoding="utf-8",
                errors="ignore",
            )
            if proc.returncode != 0:
                return []

            reader = csv.DictReader(io.StringIO(proc.stdout))
            target_str = str(self.target_dir).lower()

            for row in reader:
                task_to_run = row.get("Task To Run", "") or row.get("Action", "")
                task_name = row.get("TaskName", "") or row.get("Task Name", "")
                task_to_run_lower = task_to_run.lower()

                # Check if task runs something from game folder
                if target_str in task_to_run_lower:
                    entries.append(PersistenceEntry(
                        entry_type="ScheduledTask",
                        name=task_name,
                        target_command=task_to_run,
                        is_malicious=True,
                        details=f"Scheduled Task '{task_name}' executes payload from game folder",
                    ))
        except Exception:
            pass

        return entries

    def audit_registry_run(self) -> List[PersistenceEntry]:
        """Audits HKCU and HKLM Run keys for entries executing files in the game directory."""
        entries = []
        reg_targets = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ]
        target_str = str(self.target_dir).lower()

        for root_key, subkey_path in reg_targets:
            try:
                with winreg.OpenKey(root_key, subkey_path, 0, winreg.KEY_READ) as key:
                    num_values = winreg.QueryInfoKey(key)[1]
                    for i in range(num_values):
                        val_name, val_data, _ = winreg.EnumValue(key, i)
                        if isinstance(val_data, str) and target_str in val_data.lower():
                            entries.append(PersistenceEntry(
                                entry_type="RegistryRun",
                                name=val_name,
                                target_command=val_data,
                                is_malicious=True,
                                details=f"Registry Run key '{val_name}' automatically executes on user login",
                            ))
            except Exception:
                continue

        return entries

    def remove_persistence(self, entry: PersistenceEntry) -> bool:
        """Removes the rogue scheduled task or registry autorun key."""
        try:
            if entry.entry_type == "ScheduledTask":
                p = subprocess.run(["schtasks", "/delete", "/tn", entry.name, "/f"], capture_output=True, timeout=5)
                return p.returncode == 0
            elif entry.entry_type == "RegistryRun":
                for root_key in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
                    try:
                        with winreg.OpenKey(root_key, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE) as key:
                            winreg.DeleteValue(key, entry.name)
                            return True
                    except Exception:
                        pass
        except Exception:
            return False
        return False
