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

    def _is_targeting_game(self, cmd_or_path: str) -> bool:
        """Determines if a command line or path points inside the target game directory.
        Handles both canonical long paths and 8.3 short path aliases."""
        if not cmd_or_path or not isinstance(cmd_or_path, str):
            return False
        cmd_lower = cmd_or_path.lower()
        target_lower = str(self.target_dir).lower()
        if target_lower in cmd_lower:
            return True
        try:
            clean = cmd_or_path.strip().strip('"').strip("'")
            if '"' in cmd_or_path:
                clean = cmd_or_path.split('"')[1]
            elif " " in clean:
                clean = clean.split()[0]
            p = Path(clean)
            if p.exists():
                p_resolved = p.resolve()
                if self.target_dir == p_resolved or self.target_dir in p_resolved.parents:
                    return True
        except Exception:
            pass
        return False

    def audit_all(self) -> List[PersistenceEntry]:
        """Runs audit across Scheduled Tasks, Registry Run/RunOnce keys, Startup folder, and Services."""
        entries: List[PersistenceEntry] = []
        entries.extend(self.audit_scheduled_tasks())
        entries.extend(self.audit_registry_run())
        entries.extend(self.audit_registry_runonce())
        entries.extend(self.audit_startup_folder())
        entries.extend(self.audit_services())
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

                # Language-independent fallback for non-English Windows (German, French, Russian, etc.)
                if not task_to_run:
                    for k, v in row.items():
                        if isinstance(v, str) and target_str in v.lower():
                            task_to_run = v
                            break

                if not task_name and row:
                    task_name = list(row.values())[0] or "UnknownTask"

                # Check if task runs something from game folder
                if self._is_targeting_game(task_to_run):
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
            (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        ]
        target_str = str(self.target_dir).lower()

        for root_key, subkey_path in reg_targets:
            try:
                with winreg.OpenKey(root_key, subkey_path, 0, winreg.KEY_READ) as key:
                    num_values = winreg.QueryInfoKey(key)[1]
                    for i in range(num_values):
                        val_name, val_data, _ = winreg.EnumValue(key, i)
                        if self._is_targeting_game(val_data):
                            entries.append(PersistenceEntry(
                                entry_type="RegistryRun",
                                name=val_name,
                                target_command=str(val_data),
                                is_malicious=True,
                                details=f"Registry Run key '{val_name}' automatically executes on user login",
                            ))
            except Exception:
                continue

        return entries

    def audit_registry_runonce(self) -> List[PersistenceEntry]:
        """Audits HKCU and HKLM RunOnce keys for entries executing files in the game directory."""
        entries = []
        reg_targets = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]
        target_str = str(self.target_dir).lower()

        for root_key, subkey_path in reg_targets:
            try:
                with winreg.OpenKey(root_key, subkey_path, 0, winreg.KEY_READ) as key:
                    num_values = winreg.QueryInfoKey(key)[1]
                    for i in range(num_values):
                        val_name, val_data, _ = winreg.EnumValue(key, i)
                        if self._is_targeting_game(val_data):
                            entries.append(PersistenceEntry(
                                entry_type="RegistryRunOnce",
                                name=val_name,
                                target_command=str(val_data),
                                is_malicious=True,
                                details=f"Registry RunOnce key '{val_name}' automatically executes on reboot/login",
                            ))
            except Exception:
                continue

        return entries

    def audit_startup_folder(self) -> List[PersistenceEntry]:
        """Audits user and common Startup folders for items targeting the game directory."""
        entries = []
        appdata = os.environ.get("APPDATA")
        programdata = os.environ.get("PROGRAMDATA", os.environ.get("ALLUSERSPROFILE"))

        startup_dirs = []
        if appdata:
            startup_dirs.append(Path(appdata) / r"Microsoft\Windows\Start Menu\Programs\Startup")
        if programdata:
            startup_dirs.append(Path(programdata) / r"Microsoft\Windows\Start Menu\Programs\Startup")

        target_str = str(self.target_dir).lower()

        for s_dir in startup_dirs:
            if not s_dir.exists():
                continue
            try:
                for entry in s_dir.iterdir():
                    if not entry.is_file():
                        continue
                    matched = False
                    if entry.suffix.lower() == ".lnk":
                        try:
                            content = entry.read_bytes()
                            if target_str.encode("utf-16le") in content.lower() or target_str.encode("utf-8") in content.lower():
                                matched = True
                        except Exception:
                            pass
                    elif entry.suffix.lower() in (".bat", ".cmd", ".vbs", ".ps1", ".url"):
                        try:
                            text = entry.read_text(encoding="utf-8", errors="ignore")
                            if self._is_targeting_game(text):
                                matched = True
                        except Exception:
                            pass

                    if matched:
                        entries.append(PersistenceEntry(
                            entry_type="StartupFolder",
                            name=entry.name,
                            target_command=str(entry),
                            is_malicious=True,
                            details=f"Startup item '{entry.name}' auto-launches from game folder",
                        ))
            except Exception:
                continue

        return entries

    def audit_services(self) -> List[PersistenceEntry]:
        """Audits Windows Services for binaries pointing into the game directory."""
        entries = []
        services_key_path = r"SYSTEM\CurrentControlSet\Services"
        target_str = str(self.target_dir).lower()

        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, services_key_path, 0, winreg.KEY_READ) as s_key:
                num_subkeys = winreg.QueryInfoKey(s_key)[0]
                for i in range(num_subkeys):
                    try:
                        svc_name = winreg.EnumKey(s_key, i)
                        with winreg.OpenKey(s_key, svc_name, 0, winreg.KEY_READ) as svc_sub:
                            try:
                                img_path, _ = winreg.QueryValueEx(svc_sub, "ImagePath")
                                if self._is_targeting_game(img_path):
                                    entries.append(PersistenceEntry(
                                        entry_type="Service",
                                        name=svc_name,
                                        target_command=str(img_path),
                                        is_malicious=True,
                                        details=f"Windows Service '{svc_name}' launches binary from game folder",
                                    ))
                            except FileNotFoundError:
                                pass
                    except Exception:
                        continue
        except Exception:
            pass

        return entries

    def remove_persistence(self, entry: PersistenceEntry) -> bool:
        """Removes the rogue scheduled task, registry autorun key, startup item, or service."""
        try:
            if entry.entry_type == "ScheduledTask":
                p = subprocess.run(["schtasks", "/delete", "/tn", entry.name, "/f"], capture_output=True, timeout=5)
                return p.returncode == 0
            elif entry.entry_type in ("RegistryRun", "RegistryRunOnce"):
                sub_target = (
                    r"Software\Microsoft\Windows\CurrentVersion\Run"
                    if entry.entry_type == "RegistryRun"
                    else r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
                )
                wow_target = (
                    r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
                    if entry.entry_type == "RegistryRun"
                    else r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
                )
                removed = False
                for root_key in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
                    for subkey in (sub_target, wow_target):
                        try:
                            with winreg.OpenKey(root_key, subkey, 0, winreg.KEY_SET_VALUE) as key:
                                winreg.DeleteValue(key, entry.name)
                                removed = True
                        except Exception:
                            pass
                return removed
            elif entry.entry_type == "StartupFolder":
                p = Path(entry.target_command)
                if p.exists():
                    p.unlink()
                    return True
            elif entry.entry_type == "Service":
                subprocess.run(["sc", "stop", entry.name], capture_output=True, timeout=5)
                p = subprocess.run(["sc", "delete", entry.name], capture_output=True, timeout=5)
                return p.returncode == 0
        except Exception:
            return False
        return False
