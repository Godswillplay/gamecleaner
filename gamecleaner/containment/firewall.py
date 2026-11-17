"""
Windows Firewall containment manager: Blocks inbound and outbound network access for game executables.
"""
from dataclasses import dataclass
import os
from pathlib import Path
import subprocess
from typing import List, Tuple


@dataclass
class FirewallRuleResult:
    executable: str
    rule_name: str
    direction: str  # Outbound / Inbound
    status: str     # Created / Failed / ScriptOnly


class FirewallManager:
    """Manages Windows Firewall rules to completely isolate game binaries from the network."""

    def __init__(self, target_dir: Path):
        self.target_dir = Path(target_dir).resolve()
        self.rule_prefix = f"GameCleaner_{self.target_dir.name}"

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
        These can be run by an administrator anytime.
        """
        exes = self.find_executables()
        block_script_path = self.target_dir / "block_game_network.ps1"
        unblock_script_path = self.target_dir / "unblock_game_network.ps1"

        # Build block script
        block_lines = [
            "# GameCleaner Outbound/Inbound Network Isolation Script",
            "# Run this script in PowerShell as Administrator",
            "Write-Host 'Applying GameCleaner Network Firewall Isolation...' -ForegroundColor Cyan",
            "",
        ]

        for exe in exes:
            safe_name = f"{self.rule_prefix}_{exe.stem}"
            block_lines.extend([
                f"# Rule for: {exe.name}",
                f'Remove-NetFirewallRule -DisplayName "{safe_name}_Out" -ErrorAction SilentlyContinue',
                f'New-NetFirewallRule -DisplayName "{safe_name}_Out" -Direction Outbound -Program "{exe}" -Action Block -Profile Any -Description "GameCleaner outbound containment rule"',
                f'Remove-NetFirewallRule -DisplayName "{safe_name}_In" -ErrorAction SilentlyContinue',
                f'New-NetFirewallRule -DisplayName "{safe_name}_In" -Direction Inbound -Program "{exe}" -Action Block -Profile Any -Description "GameCleaner inbound containment rule"',
                "",
            ])

        block_lines.extend([
            "Write-Host 'Firewall rules successfully applied. All game binaries are network-isolated.' -ForegroundColor Green",
            "Pause",
        ])

        # Build unblock script
        unblock_lines = [
            "# GameCleaner Network Firewall Rule Removal Script",
            "# Run this script in PowerShell as Administrator",
            "Write-Host 'Removing GameCleaner Network Firewall Rules...' -ForegroundColor Yellow",
            "",
        ]

        for exe in exes:
            safe_name = f"{self.rule_prefix}_{exe.stem}"
            unblock_lines.extend([
                f'Remove-NetFirewallRule -DisplayName "{safe_name}_Out" -ErrorAction SilentlyContinue',
                f'Remove-NetFirewallRule -DisplayName "{safe_name}_In" -ErrorAction SilentlyContinue',
            ])

        unblock_lines.extend([
            "Write-Host 'GameCleaner firewall rules removed.' -ForegroundColor Green",
            "Pause",
        ])

        block_script_path.write_text("\n".join(block_lines), encoding="utf-8")
        unblock_script_path.write_text("\n".join(unblock_lines), encoding="utf-8")

        return block_script_path, unblock_script_path

    def apply_firewall_rules(self) -> List[FirewallRuleResult]:
        """
        Attempts to apply firewall rules directly using PowerShell.
        If admin rights are required, falls back to generating the script.
        """
        exes = self.find_executables()
        results = []

        for exe in exes:
            safe_name = f"{self.rule_prefix}_{exe.stem}"
            # Test executing PowerShell command
            ps_cmd = (
                f'Remove-NetFirewallRule -DisplayName "{safe_name}_Out" -ErrorAction SilentlyContinue; '
                f'New-NetFirewallRule -DisplayName "{safe_name}_Out" -Direction Outbound -Program "{exe}" -Action Block -Profile Any'
            )
            try:
                proc = subprocess.run(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if proc.returncode == 0:
                    status = "Applied"
                else:
                    status = "Requires Admin (Use generated .ps1 script)"
            except Exception:
                status = "Execution Error"

            results.append(FirewallRuleResult(
                executable=exe.name,
                rule_name=f"{safe_name}_Out",
                direction="Outbound",
                status=status,
            ))

        return results
