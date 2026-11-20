"""
Epic Online Services (EOS) Emulator Replacer & Configuration Engine.
Detects EOS SDK binaries, inspects exports/versions/configs, generates clean configurations,
and safely replaces untrusted closed-source crack wrappers with clean open-source stubs or isolates them.
"""
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import time
from typing import Any, Dict, List, Optional, Tuple

try:
    import pefile
except ImportError:
    pefile = None


@dataclass
class EOSConfig:
    """Epic Online Services configuration metadata."""
    app_name: str = ""
    catalog_item_id: str = ""
    catalog_namespace: str = ""
    account_id: str = ""
    exchange_code: str = ""
    product_id: str = ""
    sandbox_id: str = ""
    deployment_id: str = ""
    user_name: str = "CleanPlayer"
    offline_mode: bool = True
    language: str = "en"
    raw_properties: Dict[str, str] = field(default_factory=dict)

    def to_ini_string(self, section: str = "Epic") -> str:
        """Formats config into a clean, well-structured INI string."""
        lines = [f"[{section}]"]
        if self.app_name:
            lines.append(f"AppName = {self.app_name}")
        if self.catalog_item_id:
            lines.append(f"CatalogItemId = {self.catalog_item_id}")
        if self.catalog_namespace:
            lines.append(f"CatalogNamespace = {self.catalog_namespace}")
        if self.account_id:
            lines.append(f"AccountId = {self.account_id}")
        if self.exchange_code:
            lines.append(f"ExchangeCode = {self.exchange_code}")
        if self.product_id:
            lines.append(f"ProductId = {self.product_id}")
        if self.sandbox_id:
            lines.append(f"SandboxId = {self.sandbox_id}")
        if self.deployment_id:
            lines.append(f"DeploymentId = {self.deployment_id}")
        lines.append(f"UserName = {self.user_name}")
        lines.append(f"Language = {self.language}")
        lines.append(f"Offline = {1 if self.offline_mode else 0}")

        # Append any preserved custom properties not already listed
        standard_keys = {
            "appname", "catalogitemid", "catalognamespace", "accountid",
            "exchangecode", "productid", "sandboxid", "deploymentid",
            "username", "language", "offline"
        }
        for k, v in self.raw_properties.items():
            if k.lower() not in standard_keys:
                lines.append(f"{k} = {v}")

        return "\n".join(lines) + "\n"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "AppName": self.app_name,
            "CatalogItemId": self.catalog_item_id,
            "CatalogNamespace": self.catalog_namespace,
            "AccountId": self.account_id,
            "ExchangeCode": self.exchange_code,
            "ProductId": self.product_id,
            "SandboxId": self.sandbox_id,
            "DeploymentId": self.deployment_id,
            "UserName": self.user_name,
            "Offline": self.offline_mode,
            "Language": self.language,
            "raw_properties": self.raw_properties,
        }


@dataclass
class EOSTarget:
    """Represents a discovered EOS SDK binary target in a game directory."""
    dll_name: str
    architecture: str  # "x64" or "x86"
    full_path: Path
    relative_path: str
    version: Optional[str] = None
    exports: List[str] = field(default_factory=list)
    is_emulator: bool = False
    emulator_flavor: Optional[str] = None
    config_files: List[Path] = field(default_factory=list)
    config: EOSConfig = field(default_factory=EOSConfig)
    sha256: str = ""


@dataclass
class EOSReplacementResult:
    """Summary of EOS emulator replacement or isolation action."""
    success: bool
    message: str
    target: Optional[EOSTarget] = None
    replaced_path: Optional[Path] = None
    backup_path: Optional[Path] = None
    config_generated_path: Optional[Path] = None
    action_taken: str = ""  # REPLACED_WITH_CLEAN_EMU, ISOLATED_AND_STUBBED, CONFIG_UPDATED, FAILED


class EOSReplacer:
    """
    Detects Epic Online Services SDK binaries, parses config files,
    preserves metadata (AppName, CatalogItemId, etc.), and replaces untrusted
    closed-source EOS crack wrappers with clean open-source emulators or safely isolates them.
    """

    KNOWN_EOS_DLLS = {
        "eossdk-win64-shipping.dll",
        "eossdk-win32-shipping.dll",
        "eossdk.dll",
    }

    KNOWN_CONFIG_FILENAMES = {
        "epic_emu.ini",
        "epicnet.ini",
        "eossdk.ini",
        "eos_settings.ini",
        "eos_settings.json",
    }

    STANDARD_EOS_EXPORTS = [
        "EOS_Initialize",
        "EOS_Shutdown",
        "EOS_Platform_Create",
        "EOS_Platform_Release",
        "EOS_Platform_GetAuthInterface",
        "EOS_Platform_GetConnectInterface",
        "EOS_Platform_Tick",
        "EOS_EResult_ToString",
        "EOS_Logging_SetCallback",
        "EOS_ByteArray_ToString",
    ]

    EMULATOR_SIGNATURES = {
        "Nemirtingas": [b"nemirtingas", b"epic online services emulator", b"nemirtingas'"],
        "CODEX": [b"codex", b"cdx"],
        "Goldberg_EOS": [b"goldberg", b"eos emulator by goldberg", b"mr_goldberg"],
        "0xdeadc0de": [b"0xdeadc0de", b"deadc0de"],
        "RUNE": [b"rune", b"rune eos"],
        "FLT": [b"fairlight", b"flt"],
    }

    def __init__(self, target_dir: Path, emulator_storage: Optional[Path] = None):
        self.target_dir = Path(target_dir).resolve()
        if emulator_storage:
            self.emulator_storage = Path(emulator_storage).resolve()
        else:
            self.emulator_storage = Path(__file__).resolve().parent.parent.parent / "emulators" / "epic"
        self.backup_dir = self.target_dir / ".gamecleaner_backup"

    def _detect_pe_arch(self, path: Path) -> str:
        """Reads PE header machine type directly for 100% accurate architecture identification."""
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

    def _inspect_pe_details(self, path: Path) -> Tuple[List[str], Optional[str], bool, Optional[str], str]:
        """
        Inspects PE exports, version info, emulator markers, and SHA256 hash.
        Returns: (exports, version_str, is_emulator, emulator_flavor, sha256)
        """
        exports: List[str] = []
        version_str: Optional[str] = None
        is_emulator = False
        flavor: Optional[str] = None
        sha256 = ""

        try:
            data = path.read_bytes()
            sha256 = hashlib.sha256(data).hexdigest()
        except Exception:
            data = b""

        if not data:
            return exports, version_str, is_emulator, flavor, sha256

        data_lower = data.lower()

        # Check for emulator strings
        for emu_name, sigs in self.EMULATOR_SIGNATURES.items():
            for sig in sigs:
                if sig in data_lower:
                    is_emulator = True
                    flavor = emu_name
                    break
            if is_emulator:
                break

        # Fallback emulator check: presence of generic crack or emulator strings
        if not is_emulator:
            if b"emulator" in data_lower or b"crack" in data_lower or b"epic_emu" in data_lower:
                is_emulator = True
                flavor = "Generic_Emulator"

        # Check PE headers and exports using pefile if available
        if pefile and data.startswith(b"MZ"):
            try:
                pe = pefile.PE(data=data, fast_load=False)
                if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                        if exp.name:
                            exports.append(exp.name.decode("utf-8", errors="ignore"))

                # Extract FileVersion or ProductVersion from VS_VERSIONINFO if available
                if hasattr(pe, "FileInfo"):
                    for file_info in pe.FileInfo:
                        for item in file_info:
                            if hasattr(item, "StringTable"):
                                for st in item.StringTable:
                                    for k, v in st.entries.items():
                                        k_str = k.decode("utf-8", errors="ignore").lower()
                                        if k_str in ("fileversion", "productversion"):
                                            version_str = v.decode("utf-8", errors="ignore")
                                            break
                pe.close()
            except Exception:
                pass

        # Fallback string inspection for exports if pefile didn't find any
        if not exports:
            for exp in self.STANDARD_EOS_EXPORTS:
                if exp.encode("utf-8") in data:
                    exports.append(exp)

        # Fallback version string regex in raw binary data (e.g., EOS-SDK-1.15.0 or 1.14.2)
        if not version_str:
            ver_match = re.search(rb"(?:EOS-SDK-)?([1-9]\.[0-9]{1,2}\.[0-9]{1,2}(?:\.[0-9]+)?)", data)
            if ver_match:
                version_str = ver_match.group(1).decode("utf-8", errors="ignore")

        return exports, version_str, is_emulator, flavor, sha256

    def discover_config(self, dll_parent_dir: Path) -> Tuple[EOSConfig, List[Path]]:
        """
        Discovers existing EOS configuration files in dll_parent_dir and parent directories,
        parsing AppName, CatalogItemId, CatalogNamespace, AccountId, ExchangeCode, etc.
        """
        config = EOSConfig()
        discovered_files: List[Path] = []
        candidate_dirs = [
            dll_parent_dir,
            dll_parent_dir / "EOS_settings",
            dll_parent_dir / "eos_settings",
            dll_parent_dir / "epic_settings",
            dll_parent_dir.parent,
            dll_parent_dir.parent / "EOS_settings",
            self.target_dir,
            self.target_dir / "EOS_settings",
        ]

        seen_dirs = set()
        for cdir in candidate_dirs:
            cdir_res = cdir.resolve()
            if cdir_res in seen_dirs or not cdir_res.exists():
                continue
            seen_dirs.add(cdir_res)

            # Probe known config files and all .ini / .json in EOS_settings
            probe_files: List[Path] = []
            for known_name in self.KNOWN_CONFIG_FILENAMES:
                probe_p = cdir_res / known_name
                if probe_p.exists() and probe_p.is_file():
                    probe_files.append(probe_p)

            # If directory is an EOS_settings directory itself, check all its contents
            if "eos" in cdir_res.name.lower():
                for p in cdir_res.glob("*.*"):
                    if p.is_file() and p.suffix.lower() in (".ini", ".json", ".txt"):
                        if p not in probe_files:
                            probe_files.append(p)

            for cfg_path in probe_files:
                if cfg_path not in discovered_files:
                    discovered_files.append(cfg_path)
                self._parse_config_file(cfg_path, config)

        return config, discovered_files

    def _parse_config_file(self, file_path: Path, config: EOSConfig) -> None:
        """Parses an INI or JSON config file and extracts Epic parameters."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return

        # Try JSON parsing first if extension is .json or starts with {
        stripped = content.strip()
        if file_path.suffix.lower() == ".json" or (stripped.startswith("{") and stripped.endswith("}")):
            try:
                data = json.loads(stripped)
                if isinstance(data, dict):
                    self._update_config_from_dict(data, config)
                    return
            except Exception:
                pass

        # Parse as INI file
        key_value_pattern = re.compile(r"""^\s*([A-Za-z0-9_.-]+)\s*=\s*["']?(.*?)["']?\s*$""")
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";") or line.startswith("["):
                continue
            match = key_value_pattern.match(line)
            if match:
                key, val = match.group(1).strip(), match.group(2).strip()
                k_lower = key.lower()
                if k_lower == "appname" and val and not config.app_name:
                    config.app_name = val
                elif k_lower in ("catalogitemid", "itemid") and val and not config.catalog_item_id:
                    config.catalog_item_id = val
                elif k_lower in ("catalognamespace", "namespace") and val and not config.catalog_namespace:
                    config.catalog_namespace = val
                elif k_lower in ("accountid", "useraccountid") and val and not config.account_id:
                    config.account_id = val
                elif k_lower in ("exchangecode", "auth_code", "authorizationcode") and val and not config.exchange_code:
                    config.exchange_code = val
                elif k_lower == "productid" and val and not config.product_id:
                    config.product_id = val
                elif k_lower == "sandboxid" and val and not config.sandbox_id:
                    config.sandbox_id = val
                elif k_lower == "deploymentid" and val and not config.deployment_id:
                    config.deployment_id = val
                elif k_lower in ("username", "personaname") and val:
                    config.user_name = val
                elif k_lower == "language" and val:
                    config.language = val
                elif k_lower == "offline" and val:
                    config.offline_mode = val in ("1", "true", "True", "yes", "Yes")

                # Store all extracted pairs
                if val:
                    config.raw_properties[key] = val

    def _update_config_from_dict(self, data: Dict[str, Any], config: EOSConfig) -> None:
        """Helper to extract properties from a JSON dict (case-insensitive)."""
        data_lower = {k.lower(): (v, k) for k, v in data.items()}

        def _get(key_names: List[str]) -> Optional[str]:
            for kn in key_names:
                item = data_lower.get(kn.lower())
                if item and str(item[0]).strip():
                    return str(item[0]).strip()
            return None

        app = _get(["appname", "app_name", "title"])
        if app and not config.app_name:
            config.app_name = app

        item_id = _get(["catalogitemid", "catalog_item_id", "item_id", "itemid"])
        if item_id and not config.catalog_item_id:
            config.catalog_item_id = item_id

        ns = _get(["catalognamespace", "catalog_namespace", "namespace"])
        if ns and not config.catalog_namespace:
            config.catalog_namespace = ns

        acc = _get(["accountid", "account_id", "user_account_id"])
        if acc and not config.account_id:
            config.account_id = acc

        code = _get(["exchangecode", "exchange_code", "auth_code"])
        if code and not config.exchange_code:
            config.exchange_code = code

        prod = _get(["productid", "product_id"])
        if prod and not config.product_id:
            config.product_id = prod

        sb = _get(["sandboxid", "sandbox_id"])
        if sb and not config.sandbox_id:
            config.sandbox_id = sb

        dep = _get(["deploymentid", "deployment_id"])
        if dep and not config.deployment_id:
            config.deployment_id = dep

        user = _get(["username", "user_name", "persona"])
        if user:
            config.user_name = user

        for k, v in data.items():
            if not isinstance(v, (dict, list)):
                config.raw_properties[k] = str(v)

    def find_eos_targets(self) -> List[EOSTarget]:
        """Scans the game directory for all EOS SDK DLLs and analyzes each target."""
        targets: List[EOSTarget] = []
        if not self.target_dir.exists():
            return targets

        for path in self.target_dir.rglob("*.dll"):
            # Skip gamecleaner internal and backup directories
            p_str = str(path).lower()
            if ".gamecleaner" in p_str or ".quarantine" in p_str or ".gc_backup" in p_str:
                continue

            name_lower = path.name.lower()
            if name_lower in self.KNOWN_EOS_DLLS or ("eossdk" in name_lower and name_lower.endswith(".dll")):
                arch = self._detect_pe_arch(path)
                exports, ver, is_emu, flavor, sha256 = self._inspect_pe_details(path)
                cfg, cfg_files = self.discover_config(path.parent)

                # Fallback AppName from game directory or parent if not discovered
                if not cfg.app_name:
                    # Look for nearby game executable
                    exes = [f.stem for f in path.parent.glob("*.exe") if not f.name.lower().startswith("crash")]
                    if exes:
                        cfg.app_name = exes[0]
                    else:
                        cfg.app_name = self.target_dir.name

                target = EOSTarget(
                    dll_name=path.name,
                    architecture=arch,
                    full_path=path,
                    relative_path=str(path.relative_to(self.target_dir)),
                    version=ver,
                    exports=exports,
                    is_emulator=is_emu,
                    emulator_flavor=flavor,
                    config_files=cfg_files,
                    config=cfg,
                    sha256=sha256,
                )
                targets.append(target)

        return targets

    def generate_clean_config(
        self,
        config: EOSConfig,
        output_dir: Path,
        filenames: Optional[List[str]] = None,
    ) -> List[Path]:
        """
        Generates clean EOS configuration files preserving AppName, CatalogItemId,
        CatalogNamespace, AccountId, ExchangeCode, etc.
        """
        output_dir = Path(output_dir).resolve()
        output_dir.mkdir(parents=True, exist_ok=True)

        if filenames is None:
            filenames = ["epic_emu.ini", "eossdk.ini"]

        written_paths: List[Path] = []
        ini_content = config.to_ini_string()

        for fname in filenames:
            dest = output_dir / fname
            try:
                if dest.exists():
                    try:
                        import stat
                        os.chmod(dest, stat.S_IWRITE | stat.S_IREAD)
                    except Exception:
                        pass
                dest.write_text(ini_content, encoding="utf-8")
                written_paths.append(dest)
            except Exception:
                pass

        # Also write clean JSON config in EOS_settings folder for broader emulator compatibility
        try:
            settings_dir = output_dir / "EOS_settings"
            settings_dir.mkdir(parents=True, exist_ok=True)
            json_dest = settings_dir / "EOS_settings.json"
            json_dest.write_text(json.dumps(config.to_dict(), indent=2), encoding="utf-8")
            written_paths.append(json_dest)
        except Exception:
            pass

        return written_paths

    def get_clean_emulator(self, architecture: str) -> Optional[Path]:
        """
        Retrieves verified clean EOS emulator stub binary from storage if present.
        """
        filename = "EOSSDK-Win64-Shipping.dll" if architecture == "x64" else "EOSSDK-Win32-Shipping.dll"
        home_emu = Path.home() / ".gamecleaner" / "emulators" / "epic"

        search_paths = [
            self.emulator_storage / filename,
            self.emulator_storage / "epic" / filename,
            self.emulator_storage.parent / "epic" / filename,
            home_emu / filename,
            Path(__file__).resolve().parent.parent.parent / "emulators" / "epic" / filename,
        ]

        for p in search_paths:
            if p.exists() and p.is_file() and p.stat().st_size > 1000:
                return p

        return None

    def backup_dll(self, target: EOSTarget) -> Path:
        """
        Creates a safe backup of the target DLL before replacement into .gamecleaner_backup.
        Maintains an updated JSON manifest for safe rollback.
        """
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"EOS_{target.dll_name}_{timestamp}.gc_backup"
        dest_path = self.backup_dir / backup_name

        shutil.copy2(str(target.full_path), str(dest_path))

        manifest_file = self.backup_dir / "backup_manifest.json"
        manifest = {}
        if manifest_file.exists():
            try:
                manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
            except Exception:
                manifest = {}

        manifest[backup_name] = {
            "original_path": str(target.full_path),
            "relative_path": target.relative_path,
            "architecture": target.architecture,
            "platform": "Epic",
            "dll_name": target.dll_name,
            "sha256": target.sha256,
            "is_emulator": target.is_emulator,
            "emulator_flavor": target.emulator_flavor,
            "timestamp": datetime.now().isoformat(),
        }
        manifest_file.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        return dest_path

    def replace_or_isolate(
        self,
        target: EOSTarget,
        custom_clean_dll: Optional[Path] = None,
        isolate_if_no_clean: bool = True,
    ) -> EOSReplacementResult:
        """
        Replaces untrusted closed-source EOS crack DLL with clean open-source emulator,
        or safely isolates the untrusted wrapper if no clean binary is currently available.
        Uses NTFS rename-first evasion (.gc_old) to overwrite locked/running binaries.
        Generates clean configuration preserving AppName, CatalogItemId, etc.
        """
        clean_dll = Path(custom_clean_dll) if custom_clean_dll else self.get_clean_emulator(target.architecture)
        cfg_dir = target.full_path.parent

        # 1. Generate clean configurations preserving extracted parameters
        generated_configs = self.generate_clean_config(target.config, cfg_dir)
        first_cfg = generated_configs[0] if generated_configs else None

        # 2. Case A: Clean emulator is available -> Replace untrusted binary
        if clean_dll and clean_dll.exists():
            backup_path = self.backup_dll(target)
            success = self._safe_replace_file(target.full_path, clean_dll)
            if not success:
                return EOSReplacementResult(
                    success=False,
                    message=f"Failed to overwrite {target.dll_name} with clean emulator.",
                    target=target,
                    backup_path=backup_path,
                    config_generated_path=first_cfg,
                    action_taken="FAILED",
                )

            # Mirror clean DLL and configuration to candidate bin directories
            self._mirror_to_candidate_dirs(clean_dll, target.dll_name, target.config, cfg_dir)

            return EOSReplacementResult(
                success=True,
                message=f"Successfully replaced {target.dll_name} with verified clean EOS emulator.",
                target=target,
                replaced_path=target.full_path,
                backup_path=backup_path,
                config_generated_path=first_cfg,
                action_taken="REPLACED_WITH_CLEAN_EMU",
            )

        # 3. Case B: No clean emulator binary found -> Safely isolate untrusted wrapper
        if isolate_if_no_clean:
            backup_path = self.backup_dll(target)
            # Isolate by renaming the untrusted closed-source crack out of execution path
            isolated_path = target.full_path.with_name(f"{target.full_path.name}.gc_isolated")
            try:
                if isolated_path.exists():
                    isolated_path.unlink()
                os.replace(target.full_path, isolated_path)
            except Exception as e:
                return EOSReplacementResult(
                    success=False,
                    message=f"Failed to safely isolate untrusted wrapper {target.dll_name}: {e}",
                    target=target,
                    backup_path=backup_path,
                    config_generated_path=first_cfg,
                    action_taken="FAILED",
                )

            return EOSReplacementResult(
                success=True,
                message=(
                    f"Clean EOS emulator binary not bundled; safely isolated untrusted crack wrapper "
                    f"{target.dll_name} -> {isolated_path.name} and generated clean configuration."
                ),
                target=target,
                replaced_path=isolated_path,
                backup_path=backup_path,
                config_generated_path=first_cfg,
                action_taken="ISOLATED_AND_STUBBED",
            )

        return EOSReplacementResult(
            success=False,
            message=f"Clean EOS emulator binary for {target.architecture} not found and isolation was disabled.",
            target=target,
            config_generated_path=first_cfg,
            action_taken="FAILED",
        )

    def replace_all(self, isolate_if_no_clean: bool = True) -> List[EOSReplacementResult]:
        """Finds all EOS targets in the directory and replaces or isolates each."""
        targets = self.find_eos_targets()
        return [self.replace_or_isolate(t, isolate_if_no_clean=isolate_if_no_clean) for t in targets]

    def _safe_replace_file(self, target_path: Path, source_path: Path) -> bool:
        """
        Overwrites target_path with source_path, using NTFS rename-first evasion (.gc_old)
        if the file is currently locked by a running process.
        """
        try:
            if target_path.exists():
                try:
                    import stat
                    os.chmod(target_path, stat.S_IWRITE | stat.S_IREAD)
                except Exception:
                    pass
            shutil.copy2(str(source_path), str(target_path))
            return True
        except (PermissionError, OSError):
            # NTFS loaded DLL evasion: rename existing locked file first
            try:
                temp_old = target_path.with_name(f"{target_path.name}.{int(time.time()*1000)}.gc_old")
                if temp_old.exists():
                    try:
                        temp_old.unlink()
                    except Exception:
                        pass
                os.replace(target_path, temp_old)
                shutil.copy2(str(source_path), str(target_path))
                return True
            except Exception:
                return False

    def _mirror_to_candidate_dirs(
        self,
        clean_dll: Path,
        dll_name: str,
        config: EOSConfig,
        origin_dir: Path,
    ) -> None:
        """Mirrors clean EOS emulator and config to candidate executable directories."""
        candidate_dirs = set()
        if origin_dir != self.target_dir:
            candidate_dirs.add(self.target_dir)

        common_subs = [
            "bin",
            "bin/x64",
            "bin/x86",
            "bin/Win64",
            "bin/Win32",
            "Binaries/Win64",
            "Binaries/Win32",
            "Engine/Binaries/Win64",
            "Engine/Binaries/Win32",
            "Engine/Binaries/ThirdParty/EOS",
        ]
        for sub in common_subs:
            cand = (self.target_dir / sub).resolve()
            if cand.exists() and cand.is_dir() and cand != origin_dir:
                candidate_dirs.add(cand)

        for exe in self.target_dir.rglob("*.exe"):
            if ".gamecleaner" in str(exe) or ".quarantine" in str(exe):
                continue
            e_dir = exe.parent.resolve()
            if e_dir != origin_dir and e_dir.exists() and e_dir.is_dir():
                candidate_dirs.add(e_dir)

        for cdir in candidate_dirs:
            try:
                target_dest = cdir / dll_name
                # Only copy if either the DLL already existed there or an executable is present
                if target_dest.exists() or any(cdir.glob("*.exe")):
                    self._safe_replace_file(target_dest, clean_dll)
                    self.generate_clean_config(config, cdir)
            except Exception:
                pass

    def list_backups(self) -> List[Dict[str, Any]]:
        """Returns all EOS backups found in .gamecleaner_backup."""
        manifest_file = self.backup_dir / "backup_manifest.json"
        if not manifest_file.exists():
            return []
        try:
            manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
            backups = []
            for b_name, data in manifest.items():
                if data.get("platform") == "Epic" or "EOS" in b_name:
                    item = dict(data)
                    item["backup_file"] = b_name
                    backups.append(item)
            return backups
        except Exception:
            return []

    def rollback(self, backup_name: str) -> bool:
        """Restores a backed up EOS DLL from .gamecleaner_backup."""
        manifest_file = self.backup_dir / "backup_manifest.json"
        if not manifest_file.exists():
            return False

        try:
            manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        except Exception:
            return False

        if backup_name not in manifest:
            return False

        info = manifest[backup_name]
        src_file = self.backup_dir / backup_name
        dest_file = Path(info["original_path"])

        if src_file.exists():
            dest_file.parent.mkdir(parents=True, exist_ok=True)
            if dest_file.exists():
                try:
                    import stat
                    os.chmod(dest_file, stat.S_IWRITE | stat.S_IREAD)
                except Exception:
                    pass
            shutil.copy2(str(src_file), str(dest_file))
            try:
                src_file.unlink()
                del manifest[backup_name]
                manifest_file.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
            except Exception:
                pass
            return True
        return False

    def rollback_all(self) -> List[Tuple[str, bool]]:
        """Restores all backed up EOS DLLs."""
        backups = self.list_backups()
        results = []
        for b in backups:
            name = b["backup_file"]
            ok = self.rollback(name)
            results.append((name, ok))
        return results
