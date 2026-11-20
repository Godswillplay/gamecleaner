"""
Windows Firewall containment manager: Blocks inbound and outbound network access for game executables.
"""
import ctypes
from dataclasses import dataclass
import os
from pathlib import Path
import subprocess
from typing import List, Tuple


def is_running_as_admin() -> bool:
    """Checks whether current process has Windows Administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


@dataclass
class FirewallRuleResult:
    executable: str
    rule_name: str
    direction: str  # Outbound / Inbound
    status: str     # Applied / Requires Admin / Failed


class FirewallManager:
    """Manages Windows Firewall rules to completely isolate game binaries from the network."""

    def __init__(self, target_dir: Path):
        self.target_dir = Path(target_dir).resolve()
        # Clean rule prefix to avoid special characters in PowerShell rule names and keep well under 255-char limit
        safe_prefix = "".join(c if c.isalnum() else "_" for c in self.target_dir.name)[:40]
        self.rule_prefix = f"GameCleaner_{safe_prefix}"

    def find_executables(self) -> List[Path]:
        """Finds all executables in the target directory, excluding tools/quarantine."""
        exes = []
        for path in self.target_dir.rglob("*.exe"):
            if ".gamecleaner" in str(path) or ".quarantine" in str(path):
                continue
            exes.append(path.resolve())
        return exes

    def generate_scripts(self) -> Tuple[Path, Path]:
        """
        Generates both block and unblock PowerShell (.ps1) scripts in the target directory,
        as well as Fix_Firewall_And_Run.bat for automated unblock remediation and launching.
        These use fast array batching and can be executed as Administrator.
        """
        exes = self.find_executables()
        block_script_path = self.target_dir / "block_game_network.ps1"
        unblock_script_path = self.target_dir / "unblock_game_network.ps1"

        # Safe single-quote literal paths for PowerShell (escapes ' as '')
        escaped_paths = [f"'{str(e).replace(chr(39), chr(39)+chr(39))}'" for e in exes]
        exe_paths_ps = ",\n    ".join(escaped_paths)

        block_content = f"""# GameCleaner High-Performance Outbound/Inbound Network Isolation Script
# Run this script in PowerShell as Administrator
param(
    [switch]$NoPause
)

Write-Host "Applying GameCleaner Network Firewall Isolation..." -ForegroundColor Cyan

$exes = @(
    {exe_paths_ps}
)

$successCount = 0
$failCount = 0

foreach ($exe in $exes) {{
    if (-not (Test-Path -LiteralPath $exe)) {{ continue }}
    $exeName = [System.IO.Path]::GetFileNameWithoutExtension($exe)
    $cleanName = ($exeName -replace '[^a-zA-Z0-9_]', '_')
    if ($cleanName.Length -gt 30) {{ $cleanName = $cleanName.Substring(0, 30) }}
    $pathHash = [Math]::Abs($exe.ToLowerInvariant().GetHashCode()).ToString("X")
    $ruleOut = "{self.rule_prefix}_" + $cleanName + "_" + $pathHash + "_Out"
    $ruleIn = "{self.rule_prefix}_" + $cleanName + "_" + $pathHash + "_In"

    try {{
        Remove-NetFirewallRule -DisplayName $ruleOut -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName $ruleOut -Direction Outbound -Program $exe -Action Block -Profile Any -Description "GameCleaner outbound containment" | Out-Null

        # Block Inbound on Public/Untrusted networks to prevent external access, while permitting local loopback sockets on Private profiles
        Remove-NetFirewallRule -DisplayName $ruleIn -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName $ruleIn -Direction Inbound -Program $exe -Action Block -Profile Public -Description "GameCleaner inbound public containment" | Out-Null

        Write-Host "  [OK] Isolated: $exeName" -ForegroundColor Green
        $successCount++
    }} catch {{
        Write-Host "  [FAIL] Could not block: $exeName ($($_.Exception.Message))" -ForegroundColor Red
        $failCount++
    }}
}}

Write-Host "`nIsolation complete: $successCount blocked, $failCount failed." -ForegroundColor Cyan

if (-not $NoPause) {{
    try {{
        if ([Environment]::UserInteractive -and -not [Console]::IsInputRedirected) {{
            Pause
        }}
    }} catch {{}}
}}
"""

        unblock_content = f"""# GameCleaner Network Firewall Rule Removal Script
# Run this script in PowerShell as Administrator
param(
    [switch]$NoPause
)

Write-Host "Removing GameCleaner Network Firewall Rules..." -ForegroundColor Yellow

$exes = @(
    {exe_paths_ps}
)

foreach ($exe in $exes) {{
    $exeName = [System.IO.Path]::GetFileNameWithoutExtension($exe)
    $cleanName = ($exeName -replace '[^a-zA-Z0-9_]', '_')
    if ($cleanName.Length -gt 30) {{ $cleanName = $cleanName.Substring(0, 30) }}
    $pathHash = [Math]::Abs($exe.ToLowerInvariant().GetHashCode()).ToString("X")
    $ruleOut = "{self.rule_prefix}_" + $cleanName + "_" + $pathHash + "_Out"
    $ruleIn = "{self.rule_prefix}_" + $cleanName + "_" + $pathHash + "_In"

    Remove-NetFirewallRule -DisplayName $ruleOut -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName $ruleIn -ErrorAction SilentlyContinue
    Write-Host "  [UNBLOCKED] $exeName" -ForegroundColor Yellow
}}

Write-Host "`nAll GameCleaner firewall rules removed." -ForegroundColor Green

if (-not $NoPause) {{
    try {{
        if ([Environment]::UserInteractive -and -not [Console]::IsInputRedirected) {{
            Pause
        }}
    }} catch {{}}
}}
"""

        block_script_path.write_text(block_content, encoding="utf-8")
        unblock_script_path.write_text(unblock_content, encoding="utf-8")

        # Automatically generate Fix_Firewall_And_Run.bat
        self.generate_fix_and_run_script()

        return block_script_path, unblock_script_path

    def generate_fix_and_run_script(self) -> Path:
        """
        Generates Fix_Firewall_And_Run.bat in the target directory.
        Removes accidental Windows Firewall 'Cancel trap' inbound blocks,
        verifies GameCleaner outbound isolation, and launches the game executable.
        """
        fix_bat_path = self.target_dir / "Fix_Firewall_And_Run.bat"
        content = f"""@echo off
setlocal enabledelayedexpansion
title GameCleaner - Fix Firewall and Run

echo ========================================================
echo GameCleaner: Windows Firewall Remediation and Launcher
echo ========================================================
echo.

:: 1. Check for Administrator privileges; self-elevate if needed
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] Administrator rights required to adjust Windows Firewall rules.
    echo Requesting elevation...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process cmd -ArgumentList '/c `\"%~f0`\"' -Verb RunAs"
    exit /b
)

:: 2. Purge accidental Windows Inbound block rules (fixes Windows Firewall 'Cancel' trap)
echo [1/3] Purging conflicting Windows Inbound block rules...
set "GC_TARGET_DIR=%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "& {{
    $scriptDir = $env:GC_TARGET_DIR.TrimEnd('\\')
    $exes = Get-ChildItem -Path $scriptDir -Filter '*.exe' -Recurse | Where-Object {{
        $_.FullName -notmatch '\\\\.gamecleaner' -and $_.FullName -notmatch '\\\\.quarantine'
    }}
    foreach ($exeItem in $exes) {{
        $exe = $exeItem.FullName
        Get-NetFirewallApplicationFilter -Program $exe -ErrorAction SilentlyContinue | ForEach-Object {{
            $r = Get-NetFirewallRule -Name $_.AppId -ErrorAction SilentlyContinue
            if ($r -and $r.Direction -eq 'Inbound' -and $r.Action -eq 'Block') {{
                Remove-NetFirewallRule -Name $r.Name -ErrorAction SilentlyContinue
                Write-Host \"  [CLEARED] Inbound block rule for: $($exeItem.Name)\" -ForegroundColor Yellow
            }}
        }}
    }}
}}"

:: 3. Re-apply safe GameCleaner containment rules
echo.
echo [2/3] Verifying GameCleaner network containment...
if exist "%~dp0block_game_network.ps1" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0block_game_network.ps1" -NoPause
)

:: 4. Locate and launch game executable from proper working directory
echo.
echo [3/3] Locating game executable...

set "GAME_EXE="
set "GAME_DIR="

for %%d in ("%~dp0" "%~dp0bin\\" "%~dp0bin\\x64\\" "%~dp0bin\\x86\\" "%~dp0Binaries\\Win64\\" "%~dp0Binaries\\Win32\\" "%~dp0x64\\" "%~dp0x86\\") do (
    if not defined GAME_EXE (
        if exist "%%~d" (
            for %%f in ("%%~d*.exe") do (
                set "NAME=%%~nxf"
                if /i not "!NAME!"=="unins000.exe" if /i not "!NAME!"=="unins001.exe" if /i not "!NAME!"=="UnityCrashHandler64.exe" if /i not "!NAME!"=="UnityCrashHandler32.exe" if /i not "!NAME!"=="CrashReportClient.exe" if /i not "!NAME!"=="DXSETUP.exe" if /i not "!NAME!"=="oalinst.exe" (
                    set "GAME_EXE=%%~dpnxf"
                    set "GAME_DIR=%%~dpf"
                    goto :found_exe
                )
            )
        )
    )
)

if not defined GAME_EXE (
    for /r "%~dp0" %%f in (*.exe) do (
        set "FULL=%%~dpnxf"
        set "NAME=%%~nxf"
        echo !FULL! | findstr /i "\\.gamecleaner \\.quarantine" >nul
        if errorlevel 1 (
            if /i not "!NAME!"=="unins000.exe" if /i not "!NAME!"=="unins001.exe" if /i not "!NAME!"=="UnityCrashHandler64.exe" if /i not "!NAME!"=="UnityCrashHandler32.exe" if /i not "!NAME!"=="CrashReportClient.exe" if /i not "!NAME!"=="DXSETUP.exe" if /i not "!NAME!"=="oalinst.exe" (
                set "GAME_EXE=%%~dpnxf"
                set "GAME_DIR=%%~dpf"
                goto :found_exe
            )
        )
    )
)

:found_exe
if not defined GAME_EXE (
    echo [ERROR] No valid game executable found in "%~dp0".
    pause
    exit /b 1
)

echo.
echo ========================================================
echo Starting: !GAME_EXE!
echo Working Dir: !GAME_DIR!
echo ========================================================
echo.
cd /d "!GAME_DIR!"
start "" "!GAME_EXE!"
exit /b 0
"""
        fix_bat_path.write_text(content, encoding="utf-8")
        return fix_bat_path

    def generate_fix_firewall_batch(self) -> Path:
        """Alias for generate_fix_and_run_script."""
        return self.generate_fix_and_run_script()

    def apply_firewall_rules(self) -> List[FirewallRuleResult]:
        """
        Attempts to apply firewall rules directly using batched PowerShell.
        If admin rights are required and missing, reports 'Requires Admin'.
        """
        exes = self.find_executables()
        if not exes:
            return []

        admin = is_running_as_admin()
        results = []

        if admin:
            block_ps1, _ = self.generate_scripts()
            try:
                proc = subprocess.run(
                    ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(block_ps1), "-NoPause"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                status = "Applied" if proc.returncode == 0 else "Execution Error"
            except Exception:
                status = "Execution Error"
        else:
            status = "Requires Admin (Use generated .ps1 script or UAC prompt)"

        for exe in exes:
            safe_name = f"{self.rule_prefix}_{exe.stem}"
            results.append(FirewallRuleResult(
                executable=exe.name,
                rule_name=f"{safe_name}_Out",
                direction="Outbound",
                status=status,
            ))

        return results

    def request_elevation_and_apply(self) -> bool:
        """Launches the generated block script with a Windows UAC elevation prompt."""
        block_ps1, _ = self.generate_scripts()
        try:
            # Use PowerShell Start-Process -Verb RunAs to pop UAC prompt
            cmd = f'Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File \\"{block_ps1}\\""'
            subprocess.run(["powershell", "-NoProfile", "-Command", cmd], timeout=10)
            return True
        except Exception:
            return False
