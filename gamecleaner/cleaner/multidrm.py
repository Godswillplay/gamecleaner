"""
Unified Multi-DRM Orchestration Engine.
Detects, triages, and sanitizes multi-layered DRM implementations across PC games:
- Steam (Valve Steamworks & Steam Stub DRM -> Goldberg Emulator)
- Epic Games Store (Epic Online Services EOS SDK -> Clean EOS Emulator / Stub)
- Ubisoft Connect (Uplay / UPC Loader -> Clean Emulator / Isolation)
- GOG (DRM-Free manifests & GOG Galaxy SDK)
Supports hybrid DRM triage (games with both Steam and EOS), clean configuration generation,
and unified safe backup / rollback.
"""
from dataclasses import dataclass, field
from enum import Enum
import json
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from gamecleaner.cleaner.emu_replacer import EmulatorReplacer, DRMTarget
from gamecleaner.cleaner.eos_replacer import EOSReplacer, EOSTarget, EOSConfig


class DRMPlatform(Enum):
    STEAM = "Steam"
    EPIC = "Epic Games (EOS)"
    UBISOFT = "Ubisoft Connect"
    GOG = "GOG (DRM-Free)"
    UNKNOWN = "Unknown"


@dataclass
class DRMLayer:
    """Represents a specific DRM layer detected within the game folder."""
    platform: DRMPlatform
    name: str
    binaries: List[Path] = field(default_factory=list)
    configs: List[Path] = field(default_factory=list)
    is_emulated: bool = False
    emulator_flavor: Optional[str] = None
    architecture: str = "x64"
    metadata: Dict[str, Any] = field(default_factory=dict)
    recommended_action: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "platform": self.platform.value,
            "name": self.name,
            "binaries": [str(b) for b in self.binaries],
            "configs": [str(c) for c in self.configs],
            "is_emulated": self.is_emulated,
            "emulator_flavor": self.emulator_flavor,
            "architecture": self.architecture,
            "metadata": self.metadata,
            "recommended_action": self.recommended_action,
        }


@dataclass
class MultiDRMReport:
    """Consolidated multi-DRM triage and remediation report."""
    game_dir: Path
    layers_found: List[DRMLayer] = field(default_factory=list)
    is_hybrid: bool = False
    summary: str = ""
    replaced_files: List[str] = field(default_factory=list)
    generated_configs: List[str] = field(default_factory=list)
    isolated_files: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "game_dir": str(self.game_dir),
            "layers_found": [layer.to_dict() for layer in self.layers_found],
            "is_hybrid": self.is_hybrid,
            "summary": self.summary,
            "replaced_files": self.replaced_files,
            "generated_configs": self.generated_configs,
            "isolated_files": self.isolated_files,
            "warnings": self.warnings,
            "errors": self.errors,
        }


class MultiDRMOrchestrator:
    """
    Coordinates multi-DRM triage and clean emulator replacement across
    Steam, Epic Games Store, Ubisoft, and GOG.
    """

    STEAM_DLLS = {"steam_api.dll", "steam_api64.dll"}
    EOS_DLLS = {"eossdk-win64-shipping.dll", "eossdk-win32-shipping.dll", "eossdk.dll"}
    UBISOFT_DLLS = {
        "uplay_r1_loader.dll", "uplay_r1_loader64.dll",
        "upc_r1_loader.dll", "upc_r1_loader64.dll",
        "uplay_r2_loader.dll", "uplay_r2_loader64.dll",
    }
    GOG_GALAXY_DLLS = {"galaxy.dll", "galaxy64.dll", "galaxypeer.dll", "galaxypeer64.dll"}

    def __init__(self, game_dir: Path, emulator_storage: Optional[Path] = None):
        self.game_dir = Path(game_dir).resolve()
        self.emulator_storage = Path(emulator_storage).resolve() if emulator_storage else None
        self.steam_replacer = EmulatorReplacer(self.game_dir, emulator_storage=self.emulator_storage)
        self.eos_replacer = EOSReplacer(self.game_dir, emulator_storage=self.emulator_storage)

    def _detect_pe_arch(self, path: Path) -> str:
        """Helper to detect PE architecture (x64 vs x86)."""
        try:
            with open(path, "rb") as f:
                mz = f.read(2)
                if mz == b"MZ":
                    f.seek(0x3C)
                    pe_offset = int.from_bytes(f.read(4), "little")
                    f.seek(pe_offset + 4)
                    machine = int.from_bytes(f.read(2), "little")
                    if machine == 0x8664:
                        return "x64"
                    elif machine == 0x014C:
                        return "x86"
        except Exception:
            pass
        return "x64" if "64" in path.name.lower() else "x86"

    def triage(self) -> MultiDRMReport:
        """
        Scans game directory to identify all DRM layers present, detects hybrid
        configurations (e.g. Steam + EOS), and gathers metadata for clean remediation.
        """
        report = MultiDRMReport(game_dir=self.game_dir)
        if not self.game_dir.exists():
            report.summary = f"Game directory not found: {self.game_dir}"
            return report

        # 1. Detect Steam Layer
        steam_layer = self._triage_steam()
        if steam_layer:
            report.layers_found.append(steam_layer)

        # 2. Detect Epic Online Services (EOS) Layer
        eos_layer = self._triage_eos()
        if eos_layer:
            report.layers_found.append(eos_layer)

        # 3. Detect Ubisoft Connect Layer
        ubisoft_layer = self._triage_ubisoft()
        if ubisoft_layer:
            report.layers_found.append(ubisoft_layer)

        # 4. Detect GOG Layer
        gog_layer = self._triage_gog()
        if gog_layer:
            report.layers_found.append(gog_layer)

        # 5. Evaluate Hybrid Status
        active_drm_count = len(report.layers_found)
        report.is_hybrid = active_drm_count > 1

        if active_drm_count == 0:
            report.summary = "No known commercial DRM layers detected. Application appears DRM-Free or custom."
        elif active_drm_count == 1:
            layer = report.layers_found[0]
            report.summary = f"Single DRM layer detected: {layer.platform.value} ({layer.name})"
        else:
            platforms = ", ".join([l.platform.value for l in report.layers_found])
            report.summary = (
                f"Hybrid Multi-DRM Architecture Detected ({active_drm_count} layers): {platforms}. "
                "Coordinated multi-emulator remediation required."
            )

        return report

    def _triage_steam(self) -> Optional[DRMLayer]:
        """Triages Steamworks SDK and Steam emulator configurations."""
        binaries: List[Path] = []
        configs: List[Path] = []
        app_id: Optional[str] = None
        is_emulated = False
        flavor: Optional[str] = None
        primary_arch = "x64"

        for p in self.game_dir.rglob("*.dll"):
            if ".gamecleaner" in str(p) or ".quarantine" in str(p):
                continue
            if p.name.lower() in self.STEAM_DLLS:
                binaries.append(p)
                primary_arch = self._detect_pe_arch(p)

                # Check if it's already Goldberg or a crack
                try:
                    content = p.read_bytes().lower()
                    if b"goldberg" in content or b"mr_goldberg" in content:
                        is_emulated = True
                        flavor = "Goldberg"
                    elif b"codex" in content:
                        is_emulated = True
                        flavor = "CODEX"
                    elif b"rune" in content:
                        is_emulated = True
                        flavor = "RUNE"
                    elif b"valve corporation" in content:
                        is_emulated = False
                        flavor = "Official_Steamworks"
                    elif b"emulator" in content or b"crack" in content:
                        is_emulated = True
                        flavor = "Unknown_Scene_Crack"
                except Exception:
                    pass

                # Check appid
                found_id = self.steam_replacer.discover_appid(p.parent)
                if found_id and not app_id:
                    app_id = found_id

        # Also search for steam config files
        for cfg_name in ["steam_appid.txt", "steam_emu.ini", "codex.ini", "flt.ini", "Rune.ini"]:
            for cfg_p in self.game_dir.rglob(cfg_name):
                if ".gamecleaner" not in str(cfg_p) and cfg_p not in configs:
                    configs.append(cfg_p)

        steam_settings = self.game_dir / "steam_settings"
        if steam_settings.exists() and steam_settings.is_dir():
            for p in steam_settings.glob("*.*"):
                if p not in configs:
                    configs.append(p)

        if not binaries and not configs:
            return None

        # Check for Steam Stub DRM on nearby executables
        steam_stub_wrapped = False
        try:
            from gamecleaner.analyzer.steam_stub import SteamStubDetector
            for exe in self.game_dir.rglob("*.exe"):
                if ".gamecleaner" in str(exe) or ".quarantine" in str(exe):
                    continue
                detector = SteamStubDetector(exe)
                res = detector.scan()
                if res.is_wrapped:
                    steam_stub_wrapped = True
                    break
        except Exception:
            pass

        rec_action = "REPLACE_WITH_GOLDBERG"
        if flavor == "Goldberg" and app_id:
            rec_action = "VERIFIED_CLEAN_GOLDBERG"

        return DRMLayer(
            platform=DRMPlatform.STEAM,
            name="Steamworks DRM",
            binaries=binaries,
            configs=configs,
            is_emulated=is_emulated,
            emulator_flavor=flavor,
            architecture=primary_arch,
            metadata={
                "app_id": app_id,
                "steam_stub_wrapped": steam_stub_wrapped,
                "has_interfaces": any(c.name == "steam_interfaces.txt" for c in configs),
                "has_dlc_txt": any(c.name == "DLC.txt" for c in configs),
            },
            recommended_action=rec_action,
        )

    def _triage_eos(self) -> Optional[DRMLayer]:
        """Triages Epic Online Services SDK and EOS emulator configurations."""
        eos_targets = self.eos_replacer.find_eos_targets()
        if not eos_targets:
            # Check if EOS configs exist even if DLL is in different subfolder
            cfg, cfg_files = self.eos_replacer.discover_config(self.game_dir)
            if not cfg_files:
                return None
            return DRMLayer(
                platform=DRMPlatform.EPIC,
                name="Epic Online Services (Config-Only)",
                binaries=[],
                configs=cfg_files,
                is_emulated=True,
                emulator_flavor="Configuration_Present",
                architecture="x64",
                metadata=cfg.to_dict(),
                recommended_action="GENERATE_CLEAN_CONFIG",
            )

        binaries = [t.full_path for t in eos_targets]
        all_configs: List[Path] = []
        primary_arch = eos_targets[0].architecture
        is_emulated = any(t.is_emulator for t in eos_targets)
        flavor = next((t.emulator_flavor for t in eos_targets if t.emulator_flavor), None)
        primary_cfg = eos_targets[0].config

        for t in eos_targets:
            for c in t.config_files:
                if c not in all_configs:
                    all_configs.append(c)

        rec_action = "REPLACE_OR_ISOLATE_EOS"
        if is_emulated and flavor == "Nemirtingas":
            rec_action = "AUDIT_AND_SANITY_CHECK_EOS"

        return DRMLayer(
            platform=DRMPlatform.EPIC,
            name="Epic Online Services (EOS)",
            binaries=binaries,
            configs=all_configs,
            is_emulated=is_emulated,
            emulator_flavor=flavor,
            architecture=primary_arch,
            metadata=primary_cfg.to_dict(),
            recommended_action=rec_action,
        )

    def _triage_ubisoft(self) -> Optional[DRMLayer]:
        """Triages Ubisoft Connect / Uplay loader binaries and configurations."""
        binaries: List[Path] = []
        configs: List[Path] = []
        primary_arch = "x64"
        is_emulated = False
        flavor: Optional[str] = None

        for p in self.game_dir.rglob("*.dll"):
            if ".gamecleaner" in str(p) or ".quarantine" in str(p):
                continue
            name_lower = p.name.lower()
            if name_lower in self.UBISOFT_DLLS or ("uplay_r" in name_lower and name_lower.endswith(".dll")):
                binaries.append(p)
                primary_arch = self._detect_pe_arch(p)

                try:
                    content = p.read_bytes().lower()
                    if b"ubisoft" in content:
                        flavor = "Official_Uplay"
                    elif b"emulator" in content or b"crack" in content or b"codex" in content:
                        is_emulated = True
                        flavor = "Scene_Uplay_Crack"
                except Exception:
                    pass

        for cfg_name in ["uplay_r1.ini", "saves.ini", "ubisoft.ini"]:
            for cfg_p in self.game_dir.rglob(cfg_name):
                if ".gamecleaner" not in str(cfg_p) and cfg_p not in configs:
                    configs.append(cfg_p)

        if not binaries and not configs:
            return None

        return DRMLayer(
            platform=DRMPlatform.UBISOFT,
            name="Ubisoft Connect DRM",
            binaries=binaries,
            configs=configs,
            is_emulated=is_emulated,
            emulator_flavor=flavor,
            architecture=primary_arch,
            metadata={"loader_count": len(binaries)},
            recommended_action="REPLACE_UBISOFT_LOADER",
        )

    def _triage_gog(self) -> Optional[DRMLayer]:
        """Triages GOG DRM-free manifests and GOG Galaxy integration."""
        gog_infos: List[Path] = []
        galaxy_binaries: List[Path] = []
        metadata: Dict[str, Any] = {}

        for p in self.game_dir.glob("goggame-*.info"):
            gog_infos.append(p)
            try:
                data = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
                if isinstance(data, dict):
                    metadata["game_id"] = data.get("gameId")
                    metadata["name"] = data.get("name")
                    metadata["dlcs"] = data.get("dlcs", [])
            except Exception:
                pass

        for p in self.game_dir.rglob("*.dll"):
            if ".gamecleaner" in str(p) or ".quarantine" in str(p):
                continue
            if p.name.lower() in self.GOG_GALAXY_DLLS:
                galaxy_binaries.append(p)

        if not gog_infos and not galaxy_binaries:
            return None

        return DRMLayer(
            platform=DRMPlatform.GOG,
            name="GOG DRM-Free Release",
            binaries=galaxy_binaries,
            configs=gog_infos,
            is_emulated=False,
            emulator_flavor="GOG_Galaxy_SDK" if galaxy_binaries else "Pure_DRM_Free",
            architecture="x64",
            metadata=metadata,
            recommended_action="PRESERVE_GOG_MANIFEST",
        )

    def sanitize(
        self,
        replace_steam: bool = True,
        replace_eos: bool = True,
        replace_ubisoft: bool = True,
        custom_clean_eos_dll: Optional[Path] = None,
    ) -> MultiDRMReport:
        """
        Orchestrates clean replacement and configuration generation across all active DRM layers.
        Safely swaps untrusted closed-source binaries, writes clean configurations, and
        mirrors required files to application executable directories.
        """
        report = self.triage()

        for layer in report.layers_found:
            # 1. Remediate Steam Layer
            if layer.platform == DRMPlatform.STEAM and replace_steam:
                steam_targets = self.steam_replacer.find_drm_targets()
                for tgt in steam_targets:
                    if tgt.platform == "Steam":
                        success, msg = self.steam_replacer.replace_with_clean_emulator(tgt)
                        if success:
                            report.replaced_files.append(tgt.dll_name)
                        else:
                            report.errors.append(f"Steam replacement error on {tgt.dll_name}: {msg}")

                # Verify steam configs
                goldberg_cfg = self.game_dir / "steam_settings"
                if (goldberg_cfg / "steam_appid.txt").exists():
                    report.generated_configs.append("steam_settings/steam_appid.txt")
                if (goldberg_cfg / "DLC.txt").exists():
                    report.generated_configs.append("steam_settings/DLC.txt")
                if (goldberg_cfg / "steam_interfaces.txt").exists():
                    report.generated_configs.append("steam_settings/steam_interfaces.txt")

            # 2. Remediate Epic Online Services (EOS) Layer
            elif layer.platform == DRMPlatform.EPIC and replace_eos:
                eos_targets = self.eos_replacer.find_eos_targets()
                for target in eos_targets:
                    res = self.eos_replacer.replace_or_isolate(
                        target,
                        custom_clean_dll=custom_clean_eos_dll,
                        isolate_if_no_clean=True,
                    )
                    if res.success:
                        if res.action_taken == "REPLACED_WITH_CLEAN_EMU":
                            report.replaced_files.append(target.dll_name)
                        elif res.action_taken == "ISOLATED_AND_STUBBED":
                            report.isolated_files.append(target.dll_name)
                        if res.config_generated_path:
                            report.generated_configs.append(res.config_generated_path.name)
                    else:
                        report.errors.append(f"EOS remediation error on {target.dll_name}: {res.message}")

            # 3. Remediate Ubisoft Connect Layer
            elif layer.platform == DRMPlatform.UBISOFT and replace_ubisoft:
                ubi_targets = self.steam_replacer.find_drm_targets()
                for tgt in ubi_targets:
                    if tgt.platform == "Ubisoft":
                        success, msg = self.steam_replacer.replace_with_clean_emulator(tgt)
                        if success:
                            report.replaced_files.append(tgt.dll_name)
                        else:
                            report.warnings.append(f"Ubisoft replacement advisory: {msg}")

            # 4. GOG Layer Maintenance
            elif layer.platform == DRMPlatform.GOG:
                # GOG is DRM-free; verify manifest integrity
                report.generated_configs.append("GOG_Manifest_Preserved")

        return report

    def rollback_all(self) -> Dict[str, Any]:
        """Restores all backed up Steam, EOS, and Ubisoft DLLs from .gamecleaner_backup."""
        results = {
            "steam_ubisoft_rollbacks": self.steam_replacer.rollback_all(),
            "eos_rollbacks": self.eos_replacer.rollback_all(),
        }
        return results
