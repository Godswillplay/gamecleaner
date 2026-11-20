"""
Windows Exploit Protection & Process Mitigation Shield.
Enforces kernel-level process mitigations (DisallowChildProcessCreation, StrictHandleCheck)
to eliminate dropper capabilities, child process spawning (cmd.exe, powershell.exe),
and handle manipulation / process hollowing vulnerabilities in game executables.
"""
from dataclasses import dataclass
import json
import os
from pathlib import Path
import subprocess
from typing import Any, Dict, List, Optional, Tuple, Union

from gamecleaner.containment.firewall import is_running_as_admin


@dataclass
class ShieldResult:
    """Represents the mitigation status and application result for an executable."""
    exe_name: str
    applied: bool
    disallow_child_process: bool = False
    strict_handle: bool = False
    script_path: Optional[Path] = None
    details: str = ""

    @property
    def is_shielded(self) -> bool:
        return self.applied or (self.disallow_child_process and self.strict_handle)

    @property
    def disallow_child_processes(self) -> bool:
        return self.disallow_child_process

    @property
    def strict_handle_checks(self) -> bool:
        return self.strict_handle

    @property
    def executable_name(self) -> str:
        return self.exe_name


class ProcessShield:
    """
    Manages Windows Exploit Protection mitigations for game executables.
    Generates Apply_Process_Shield.ps1 and Remove_Process_Shield.ps1 scripts,
    applies mitigations directly if elevated, and inspects active mitigation states.
    """

    def __init__(self, target_dir: Union[Path, str], exes: Optional[List[str]] = None):
        """
        Initializes the ProcessShield manager for a game directory.

        Args:
            target_dir: Target game directory containing binaries.
            exes: Optional list of specific executable names or paths to target.
        """
        self.target_dir = Path(target_dir).resolve()
        self.explicit_exes = exes

    def find_executables(self) -> List[Path]:
        """Finds all executables in the target directory, excluding tools and quarantine."""
        if self.explicit_exes:
            resolved = []
            for e in self.explicit_exes:
                p = Path(e)
                if not p.is_absolute():
                    p = self.target_dir / p
                resolved.append(p.resolve())
            return resolved

        if self.target_dir.is_file() and self.target_dir.suffix.lower() == ".exe":
            return [self.target_dir]

        exes: List[Path] = []
        if not self.target_dir.exists():
            return exes

        for path in self.target_dir.rglob("*.exe"):
            path_str = str(path)
            if ".gamecleaner" in path_str or ".quarantine" in path_str:
                continue
            exes.append(path.resolve())
        return exes

    def get_target_exe_names(self) -> List[str]:
        """Returns sorted unique executable names (e.g. 'game.exe')."""
        if self.explicit_exes:
            return sorted(list(set(Path(e).name for e in self.explicit_exes)))
        found = self.find_executables()
        return sorted(list(set(e.name for e in found)))

    def generate_scripts(self) -> Tuple[Path, Path]:
        """
        Generates Apply_Process_Shield.ps1 and Remove_Process_Shield.ps1 in the game directory.

        Returns:
            Tuple of (apply_script_path, remove_script_path).
        """
        self.target_dir.mkdir(parents=True, exist_ok=True)
        apply_script_path = self.target_dir / "Apply_Process_Shield.ps1"
        remove_script_path = self.target_dir / "Remove_Process_Shield.ps1"

        exe_names = self.get_target_exe_names()
        escaped_exes = [f"'{name.replace(chr(39), chr(39)+chr(39))}'" for name in exe_names]
        exes_ps = ",\n    ".join(escaped_exes) if escaped_exes else ""

        apply_content = f"""# GameCleaner Exploit Protection & Process Mitigation Shield Script
# Enables DisallowChildProcessCreation and StrictHandleCheck via Set-ProcessMitigation.
# Run this script in PowerShell as Administrator.
param(
    [switch]$NoPause
)

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host " GameCleaner: Applying Exploit Protection Process Shield" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {{
    Write-Host "[WARNING] Administrative privileges are required to configure Image File Execution Options." -ForegroundColor Yellow
    Write-Host "Please re-run this script in an elevated PowerShell session.`n" -ForegroundColor Yellow
}}

$exes = @(
    {exes_ps}
)

$successCount = 0
$failCount = 0

foreach ($exe in $exes) {{
    if ([string]::IsNullOrWhiteSpace($exe)) {{ continue }}
    try {{
        Set-ProcessMitigation -Name $exe -Enable DisallowChildProcessCreation,StrictHandleCheck -ErrorAction Stop
        Write-Host "  [SHIELDED] $exe" -ForegroundColor Green
        Write-Host "             + DisallowChildProcessCreation: ENABLED" -ForegroundColor DarkGreen
        Write-Host "             + StrictHandleCheck: ENABLED" -ForegroundColor DarkGreen
        $successCount++
    }} catch {{
        Write-Host "  [FAIL] Failed to apply mitigations for $exe`: $($_.Exception.Message)" -ForegroundColor Red
        $failCount++
    }}
}}

Write-Host ""
Write-Host "Process Shield summary: $successCount applied, $failCount failed." -ForegroundColor Cyan

if (-not $NoPause) {{
    try {{
        if ([Environment]::UserInteractive -and -not [Console]::IsInputRedirected) {{
            Pause
        }}
    }} catch {{}}
}}
"""

        remove_content = f"""# GameCleaner Exploit Protection & Process Mitigation Shield Removal Script
# Disables DisallowChildProcessCreation and StrictHandleCheck via Set-ProcessMitigation.
# Run this script in PowerShell as Administrator.
param(
    [switch]$NoPause
)

Write-Host "========================================================" -ForegroundColor Yellow
Write-Host " GameCleaner: Removing Exploit Protection Process Shield" -ForegroundColor Yellow
Write-Host "========================================================" -ForegroundColor Yellow
Write-Host ""

$exes = @(
    {exes_ps}
)

$successCount = 0
$failCount = 0

foreach ($exe in $exes) {{
    if ([string]::IsNullOrWhiteSpace($exe)) {{ continue }}
    try {{
        Set-ProcessMitigation -Name $exe -Disable DisallowChildProcessCreation,StrictHandleCheck -ErrorAction Stop
        Write-Host "  [REMOVED] Process Shield disabled for: $exe" -ForegroundColor Yellow
        $successCount++
    }} catch {{
        Write-Host "  [FAIL] Failed to remove mitigations for $exe`: $($_.Exception.Message)" -ForegroundColor Red
        $failCount++
    }}
}}

Write-Host ""
Write-Host "Process Shield removal summary: $successCount disabled, $failCount failed." -ForegroundColor Yellow

if (-not $NoPause) {{
    try {{
        if ([Environment]::UserInteractive -and -not [Console]::IsInputRedirected) {{
            Pause
        }}
    }} catch {{}}
}}
"""

        apply_script_path.write_text(apply_content, encoding="utf-8")
        remove_script_path.write_text(remove_content, encoding="utf-8")
        return apply_script_path, remove_script_path

    def generate_shield_script(self) -> Path:
        apply_p, _ = self.generate_scripts()
        return apply_p

    def generate_unshield_script(self) -> Path:
        _, remove_p = self.generate_scripts()
        return remove_p

    def audit(self) -> List[ShieldResult]:
        return [self.inspect_mitigations(name) for name in self.get_target_exe_names()]

    def inspect_mitigations(self, exe_name: str) -> ShieldResult:
        """
        Inspects current exploit mitigation status using Get-ProcessMitigation.

        Args:
            exe_name: Executable name (e.g. 'game.exe').

        Returns:
            ShieldResult reflecting active mitigations.
        """
        exe_clean = Path(exe_name).name
        if os.name != "nt":
            return ShieldResult(
                exe_name=exe_clean,
                applied=False,
                disallow_child_process=False,
                strict_handle=False,
                details="Get-ProcessMitigation is only supported on Windows NT.",
            )

        ps_cmd = (
            "param($name) "
            "$m = Get-ProcessMitigation -Name $name -ErrorAction SilentlyContinue; "
            "if ($m) { "
            "$d = if ($m.ChildProcess -and $m.ChildProcess.DisallowChildProcessCreation -eq 'ON') { $true } else { $false }; "
            "$s = if ($m.StrictHandle -and $m.StrictHandle.Enable -eq 'ON') { $true } else { $false }; "
            "[PSCustomObject]@{ Exe = $name; Disallow = $d; Strict = $s } | ConvertTo-Json -Compress "
            "} else { Write-Output '{}' }"
        )

        try:
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd, "-name", exe_clean],
                capture_output=True,
                text=True,
                timeout=8,
            )
            raw = proc.stdout.strip()
            if raw and raw.startswith("{"):
                data = json.loads(raw)
                disallow = bool(data.get("Disallow", False))
                strict = bool(data.get("Strict", False))
                applied = disallow and strict
                return ShieldResult(
                    exe_name=exe_clean,
                    applied=applied,
                    disallow_child_process=disallow,
                    strict_handle=strict,
                    details=f"Active mitigations: DisallowChildProcessCreation={'ON' if disallow else 'OFF'}, StrictHandleCheck={'ON' if strict else 'OFF'}",
                )
        except Exception as e:
            return ShieldResult(
                exe_name=exe_clean,
                applied=False,
                disallow_child_process=False,
                strict_handle=False,
                details=f"Inspection failed: {e}",
            )

        return ShieldResult(
            exe_name=exe_clean,
            applied=False,
            disallow_child_process=False,
            strict_handle=False,
            details="No mitigations configured in Image File Execution Options.",
        )

    def apply(self, exe_names: Optional[Union[str, List[str]]] = None) -> List[ShieldResult]:
        """
        Applies process shield mitigations (DisallowChildProcessCreation, StrictHandleCheck).
        If elevated, applies directly via PowerShell cmdlet Set-ProcessMitigation.
        If non-elevated, generates Apply_Process_Shield.ps1 and reports required elevation.

        Args:
            exe_names: Optional single exe name or list of exe names to shield.

        Returns:
            List of ShieldResult objects for each targeted executable.
        """
        apply_script, _ = self.generate_scripts()

        if isinstance(exe_names, str):
            targets = [Path(exe_names).name]
        elif exe_names:
            targets = [Path(e).name for e in exe_names]
        else:
            targets = self.get_target_exe_names()

        if not targets:
            return []

        admin = is_running_as_admin()
        results: List[ShieldResult] = []

        for exe in targets:
            if admin and os.name == "nt":
                try:
                    proc = subprocess.run(
                        [
                            "powershell",
                            "-NoProfile",
                            "-NonInteractive",
                            "-ExecutionPolicy",
                            "Bypass",
                            "-Command",
                            "param($name) Set-ProcessMitigation -Name $name -Enable DisallowChildProcessCreation,StrictHandleCheck -ErrorAction Stop",
                            "-name",
                            exe,
                        ],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    if proc.returncode == 0:
                        status = self.inspect_mitigations(exe)
                        results.append(ShieldResult(
                            exe_name=exe,
                            applied=True,
                            disallow_child_process=status.disallow_child_process or True,
                            strict_handle=status.strict_handle or True,
                            script_path=apply_script,
                            details="Applied Set-ProcessMitigation directly with Administrator privileges.",
                        ))
                    else:
                        results.append(ShieldResult(
                            exe_name=exe,
                            applied=False,
                            disallow_child_process=False,
                            strict_handle=False,
                            script_path=apply_script,
                            details=f"Cmdlet execution error: {proc.stderr.strip() or proc.stdout.strip()}",
                        ))
                except Exception as e:
                    results.append(ShieldResult(
                        exe_name=exe,
                        applied=False,
                        disallow_child_process=False,
                        strict_handle=False,
                        script_path=apply_script,
                        details=f"Failed to apply Set-ProcessMitigation: {e}",
                    ))
            else:
                results.append(ShieldResult(
                    exe_name=exe,
                    applied=False,
                    disallow_child_process=False,
                    strict_handle=False,
                    script_path=apply_script,
                    details="Requires Administrator elevation. Generated Apply_Process_Shield.ps1 script ready to run.",
                ))

        return results

    def remove(self, exe_names: Optional[Union[str, List[str]]] = None) -> List[ShieldResult]:
        """
        Removes process shield mitigations (-Disable DisallowChildProcessCreation,StrictHandleCheck).

        Args:
            exe_names: Optional single exe name or list of exe names to disable.

        Returns:
            List of ShieldResult objects for each targeted executable.
        """
        _, remove_script = self.generate_scripts()

        if isinstance(exe_names, str):
            targets = [Path(exe_names).name]
        elif exe_names:
            targets = [Path(e).name for e in exe_names]
        else:
            targets = self.get_target_exe_names()

        if not targets:
            return []

        admin = is_running_as_admin()
        results: List[ShieldResult] = []

        for exe in targets:
            if admin and os.name == "nt":
                try:
                    proc = subprocess.run(
                        [
                            "powershell",
                            "-NoProfile",
                            "-NonInteractive",
                            "-ExecutionPolicy",
                            "Bypass",
                            "-Command",
                            "param($name) Set-ProcessMitigation -Name $name -Disable DisallowChildProcessCreation,StrictHandleCheck -ErrorAction Stop",
                            "-name",
                            exe,
                        ],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    results.append(ShieldResult(
                        exe_name=exe,
                        applied=proc.returncode == 0,
                        disallow_child_process=False,
                        strict_handle=False,
                        script_path=remove_script,
                        details="Process mitigations disabled directly via Set-ProcessMitigation." if proc.returncode == 0 else proc.stderr.strip(),
                    ))
                except Exception as e:
                    results.append(ShieldResult(
                        exe_name=exe,
                        applied=False,
                        disallow_child_process=False,
                        strict_handle=False,
                        script_path=remove_script,
                        details=f"Failed to disable Set-ProcessMitigation: {e}",
                    ))
            else:
                results.append(ShieldResult(
                    exe_name=exe,
                    applied=False,
                    disallow_child_process=False,
                    strict_handle=False,
                    script_path=remove_script,
                    details="Requires Administrator elevation. Generated Remove_Process_Shield.ps1 script ready to run.",
                ))

        return results

    def request_elevation_and_apply(self) -> bool:
        """Launches the generated apply script with a Windows UAC elevation prompt."""
        apply_script, _ = self.generate_scripts()
        try:
            cmd = f'Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File \\"{apply_script}\\""'
            subprocess.run(["powershell", "-NoProfile", "-Command", cmd], timeout=10)
            return True
        except Exception:
            return False
