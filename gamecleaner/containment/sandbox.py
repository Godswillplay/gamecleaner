"""
Windows Sandbox (.wsb) generator: Configures isolated, air-gapped test environments.
"""
from dataclasses import dataclass
import os
from pathlib import Path
import shutil
from typing import Optional, Tuple
from xml.sax.saxutils import escape as xml_escape


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

    @property
    def is_supported(self) -> bool:
        """Returns whether Windows Sandbox is supported on this host."""
        return is_sandbox_supported()

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
        escaped_host_dir = xml_escape(str(self.target_dir))

        # XML structure for Windows Sandbox
        xml_content = f"""<Configuration>
  <!-- Hardware Virtualized GPU for 3D Game Compatibility -->
  <VGpu>{vgpu_val}</VGpu>

  <!-- Complete Network Isolation to prevent C2 communication or exfiltration -->
  <Networking>{net_val}</Networking>

  <MappedFolders>
    <MappedFolder>
      <HostFolder>{escaped_host_dir}</HostFolder>
      <SandboxFolder>C:\\TestingGame</SandboxFolder>
      <ReadOnly>{ro_val}</ReadOnly>
    </MappedFolder>
  </MappedFolders>

  <LogonCommand>
    <Command>cmd.exe /c if exist C:\\TestingGame\\Sandbox_Staged_Runner.cmd ( C:\\TestingGame\\Sandbox_Staged_Runner.cmd ) else ( start explorer.exe C:\\TestingGame )</Command>
  </LogonCommand>
</Configuration>
"""
        wsb_file.write_text(xml_content, encoding="utf-8")

        # Generate container bootstrap script for writable staging and redist setup
        self.generate_sandbox_staged_runner()

        # Also generate an offline local isolation launcher in case Sandbox is unavailable (e.g. Home edition)
        self.generate_isolated_launcher()

        return wsb_file

    def generate_sandbox_staged_runner(self) -> Path:
        """
        Generates Sandbox_Staged_Runner.cmd which runs inside Windows Sandbox upon logon.
        Stages the read-only mounted host directory into container RAM and auto-installs runtimes.
        """
        runner_file = self.target_dir / "Sandbox_Staged_Runner.cmd"
        content = """@echo off
setlocal enabledelayedexpansion
title Windows Sandbox Staged Runner
echo ========================================================
echo GameCleaner Windows Sandbox Container Environment
echo ========================================================
echo.
echo Staging read-only host mount to writable container RAM...
set "DEST=C:\\Users\\WDAGUtilityAccount\\Desktop\\Game"
if not exist "!DEST!" (
    robocopy "C:\\TestingGame" "!DEST!" /e /xd .gamecleaner_quarantine .gamecleaner_backup >nul
)
:: Check and install redists if present inside the container
for %%r in ("!DEST!\\_CommonRedist\\DirectX\\Jun2010\\DXSETUP.exe" "!DEST!\\redist\\DXSETUP.exe") do (
    if exist "%%~r" (
        echo [INFO] Installing DirectX runtimes in container...
        start /wait "" "%%~r" /silent
    )
)
for %%v in ("!DEST!\\_CommonRedist\\vcredist\\*\\*.exe" "!DEST!\\redist\\vc*.exe") do (
    if exist "%%~v" (
        echo [INFO] Installing Visual C++ runtime in container...
        start /wait "" "%%~v" /quiet /norestart
    )
)
echo.
echo Opening writable game directory in Sandbox...
start explorer.exe "!DEST!"
"""
        runner_file.write_text(content, encoding="utf-8")
        return runner_file

    def generate_batch_runner(self) -> Path:
        """Alias for generate_isolated_launcher to support batch runner generation."""
        return self.generate_isolated_launcher()

    def generate_isolated_launcher(self) -> Path:
        """
        Generates a local containment runner (Launch_Game_Isolated.bat) that verifies
        firewall isolation before launching the game, for systems without Windows Sandbox.
        """
        launcher_file = self.target_dir / "Launch_Game_Isolated.bat"
        content = f"""@echo off
setlocal enabledelayedexpansion
title GameCleaner Isolated Runner - {self.game_name}
echo ========================================================
echo GameCleaner Isolated Offline Game Launcher
echo ========================================================
echo.

:: Check if firewall isolation script exists and has been created
if exist "%~dp0block_game_network.ps1" (
    echo [INFO] Ensuring network isolation rules are active...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "if (-not (Get-NetFirewallRule -DisplayName 'GameCleaner_*' -ErrorAction SilentlyContinue)) {{ exit 1 }}" >nul 2>&1
    if errorlevel 1 (
        echo [WARNING] Firewall block rules not yet applied with Administrator privileges!
        echo Please right-click 'block_game_network.ps1' and select 'Run with PowerShell as Admin',
        echo or run 'Fix_Firewall_And_Run.bat' as Administrator.
        echo.
    ) else (
        echo [OK] Firewall isolation verified. Outbound internet access is blocked.
    )
)

echo.
echo Launching game in offline contained mode...
echo.

set "GAME_EXE="
set "GAME_DIR="

:: Check root folder first
for %%f in ("%~dp0*.exe") do (
    set "NAME=%%~nxf"
    if /i not "!NAME!"=="unins000.exe" if /i not "!NAME!"=="unins001.exe" if /i not "!NAME!"=="UnityCrashHandler64.exe" if /i not "!NAME!"=="UnityCrashHandler32.exe" if /i not "!NAME!"=="CrashReportClient.exe" if /i not "!NAME!"=="DXSETUP.exe" if /i not "!NAME!"=="oalinst.exe" (
        set "GAME_EXE=%%~dpnxf"
        set "GAME_DIR=%%~dpf"
        goto :launch_now
    )
)

:: Subdirectory executable search for common repack structures (bin, bin\\x64, Binaries\\Win64, etc.)
for %%d in ("%~dp0bin\\" "%~dp0bin\\x64\\" "%~dp0bin\\x86\\" "%~dp0Binaries\\Win64\\" "%~dp0Binaries\\Win32\\" "%~dp0x64\\" "%~dp0x86\\" "%~dp0Engine\\Binaries\\Win64\\") do (
    if not defined GAME_EXE (
        if exist "%%~d" (
            for %%f in ("%%~d*.exe") do (
                set "NAME=%%~nxf"
                if /i not "!NAME!"=="unins000.exe" if /i not "!NAME!"=="unins001.exe" if /i not "!NAME!"=="UnityCrashHandler64.exe" if /i not "!NAME!"=="UnityCrashHandler32.exe" if /i not "!NAME!"=="CrashReportClient.exe" if /i not "!NAME!"=="DXSETUP.exe" if /i not "!NAME!"=="oalinst.exe" (
                    set "GAME_EXE=%%~dpnxf"
                    set "GAME_DIR=%%~dpf"
                    goto :launch_now
                )
            )
        )
    )
)

:: Fallback recursive scan
if not defined GAME_EXE (
    for /r "%~dp0" %%f in (*.exe) do (
        set "FULL=%%~dpnxf"
        set "NAME=%%~nxf"
        echo !FULL! | findstr /i "\\.gamecleaner \\.quarantine" >nul
        if errorlevel 1 (
            if /i not "!NAME!"=="unins000.exe" if /i not "!NAME!"=="unins001.exe" if /i not "!NAME!"=="UnityCrashHandler64.exe" if /i not "!NAME!"=="UnityCrashHandler32.exe" if /i not "!NAME!"=="CrashReportClient.exe" if /i not "!NAME!"=="DXSETUP.exe" if /i not "!NAME!"=="oalinst.exe" (
                set "GAME_EXE=%%~dpnxf"
                set "GAME_DIR=%%~dpf"
                goto :launch_now
            )
        )
    )
)

if not defined GAME_EXE (
    echo [ERROR] No valid game executable found in "%~dp0" or common subfolders.
    pause
    exit /b 1
)

:launch_now
echo Starting: !GAME_EXE!
echo Working Dir: !GAME_DIR!
cd /d "!GAME_DIR!"
start "" "!GAME_EXE!"
exit /b 0
"""
        launcher_file.write_text(content, encoding="utf-8")
        return launcher_file
