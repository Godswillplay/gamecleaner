"""
Windows Sandbox (.wsb) generator: Configures isolated, air-gapped test environments.
"""
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class SandboxConfig:
    game_dir: Path
    sandbox_name: str
    v_gpu: bool = True
    networking: bool = False  # Disabled by default for malware containment
    read_only_mount: bool = True
    mapped_sandbox_path: str = r"C:\TestingGame"


class SandboxGenerator:
    """Generates Windows Sandbox configuration files (.wsb) for safe execution testing."""

    def __init__(self, target_dir: Path):
        self.target_dir = Path(target_dir).resolve()
        self.game_name = self.target_dir.name

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
        return wsb_file
