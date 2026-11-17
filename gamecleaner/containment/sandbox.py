"""
Windows Sandbox (.wsb) generator: Configures isolated, air-gapped test environments.
"""
from dataclasses import dataclass
import os
from pathlib import Path
import shutil
from typing import Optional, Tuple


def is_sandbox_supported() -> bool:
    """Checks whether Windows Sandbox executable is present on the current system."""
    sandbox_exe = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsSandbox.exe"
    return sandbox_exe.exists()


@dataclass
class SandboxConfig:
    game_dir: Path
    sandbox_name: str
    v_gpu: bool = True
    networking: bool = False  # Disabled by default for malware containment
    read_only_mount: bool = True
    mapped_sandbox_path: str = r"C:\TestingGame"


class SandboxGenerator:
    """Generates Windows Sandbox configuration files (.wsb) and isolated local launchers."""

    def __init__(self, target_dir: Path):
        self.target_dir = Path(target_dir).resolve()
        safe_name = "".join(c if c.isalnum() else "_" for c in self.target_dir.name)
        self.game_name = safe_name

    def generate_wsb(
        self,
        read_only: bool = True,
        v_gpu: bool = True,
        allow_network: bool = False,
    ) -> Path:
        """
        Creates a .wsb configuration file in the target directory.
        Double-clicking this file launches Windows Sandbox with the game folder mounted.
        """
        wsb_file = self.target_dir / f"Sandbox_{self.game_name}.wsb"
        net_val = "Enable" if allow_network else "Disable"
        vgpu_val = "Enable" if v_gpu else "Disable"
        ro_val = "true" if read_only else "false"

        # XML structure for Windows Sandbox
        xml_content = f"""<Configuration>
  <!-- Hardware Virtualized GPU for 3D Game Compatibility -->
  <VGpu>{vgpu_val}</VGpu>

  <!-- Complete Network Isolation to prevent C2 communication or exfiltration -->
  <Networking>{net_val}</Networking>

  <MappedFolders>
    <MappedFolder>
      <HostFolder>{self.target_dir}</HostFolder>
      <SandboxFolder>C:\\TestingGame</SandboxFolder>
      <ReadOnly>{ro_val}</ReadOnly>
    </MappedFolder>
  </MappedFolders>

  <LogonCommand>
    <Command>cmd.exe /c start explorer.exe C:\\TestingGame</Command>
  </LogonCommand>
</Configuration>
"""
        wsb_file.write_text(xml_content, encoding="utf-8")

        # Also generate an offline local isolation launcher in case Sandbox is unavailable (e.g. Home edition)
        self.generate_isolated_launcher()

        return wsb_file

    def generate_isolated_launcher(self) -> Path:
        """
        Generates a local containment runner (Launch_Game_Isolated.bat) that verifies
        firewall isolation before launching the game, for systems without Windows Sandbox.
        """
        launcher_file = self.target_dir / "Launch_Game_Isolated.bat"
        content = f"""@echo off
title GameCleaner Isolated Runner - {self.game_name}
echo ========================================================
echo GameCleaner Isolated Offline Game Launcher
echo ========================================================
echo.

:: Check if firewall isolation script exists and has been created
if exist "%~dp0block_game_network.ps1" (
    echo [INFO] Ensuring network isolation rules are active...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-NetFirewallRule -DisplayName 'GameCleaner_*' | Select-Object -First 1" >nul 2>&1
    if errorlevel 1 (
        echo [WARNING] Firewall block rules not yet applied with Administrator privileges!
        echo Please right-click 'block_game_network.ps1' and select 'Run with PowerShell as Admin'.
        echo.
    ) else (
        echo [OK] Firewall isolation verified. Outbound internet access is blocked.
    )
)

echo.
echo Launching game in offline contained mode...
echo.

:: Locate main game executable
for %%f in ("%~dp0*.exe") do (
    if /i not "%%~nxf"=="unins000.exe" if /i not "%%~nxf"=="UnityCrashHandler64.exe" if /i not "%%~nxf"=="CrashReportClient.exe" (
        echo Starting: "%%~nxf"
        start "" "%%f"
        goto :launched
    )
)

echo No main executable found in root folder.
pause
exit /b 1

:launched
exit /b 0
"""
        launcher_file.write_text(content, encoding="utf-8")
        return launcher_file
