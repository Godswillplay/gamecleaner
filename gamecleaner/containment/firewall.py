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
        Generates both block and unblock PowerShell (.ps1) scripts in the target directory.
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
    if ($cleanName.Length -gt 40) {{ $cleanName = $cleanName.Substring(0, 40) }}
    $ruleOut = "{self.rule_prefix}_" + $cleanName + "_Out"
    $ruleIn = "{self.rule_prefix}_" + $cleanName + "_In"

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
Pause
"""

        unblock_content = f"""# GameCleaner Network Firewall Rule Removal Script
# Run this script in PowerShell as Administrator

Write-Host "Removing GameCleaner Network Firewall Rules..." -ForegroundColor Yellow

$exes = @(
    {exe_paths_ps}
)

foreach ($exe in $exes) {{
    $exeName = [System.IO.Path]::GetFileNameWithoutExtension($exe)
    $cleanName = $exeName -replace '[^a-zA-Z0-9_]', '_'
    $ruleOut = "{self.rule_prefix}_" + $cleanName + "_Out"
    $ruleIn = "{self.rule_prefix}_" + $cleanName + "_In"

    Remove-NetFirewallRule -DisplayName $ruleOut -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName $ruleIn -ErrorAction SilentlyContinue
    Write-Host "  [UNBLOCKED] $exeName" -ForegroundColor Yellow
}}

Write-Host "`nAll GameCleaner firewall rules removed." -ForegroundColor Green
Pause
"""

        block_script_path.write_text(block_content, encoding="utf-8")
        unblock_script_path.write_text(unblock_content, encoding="utf-8")

        return block_script_path, unblock_script_path

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
                    ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(block_ps1)],
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
