"""
Cryptographic Game Integrity Verifier: Generates and audits cryptographic SHA-256 manifests.
Detects corrupt files, post-cleaning tampering, and newly injected unknown binaries.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Set


MANIFEST_FILENAME = ".gamecleaner_manifest.json"


@dataclass
class FileIntegrityRecord:
    relative_path: str
    sha256: str
    size: int
    category: str


@dataclass
class IntegrityReport:
    game_dir: str
    manifest_path: str
    is_valid: bool
    total_verified: int
    missing_files: List[str] = field(default_factory=list)
    modified_files: List[str] = field(default_factory=list)
    untracked_binaries: List[str] = field(default_factory=list)
    tamper_alerts: List[str] = field(default_factory=list)


class IntegrityVerifier:
    """Creates and verifies cryptographic SHA-256 integrity manifests for game directories."""

    def __init__(self, game_dir: Path):
        self.game_dir = Path(game_dir)
        self.manifest_path = self.game_dir / MANIFEST_FILENAME

    @staticmethod
    def compute_sha256(file_path: Path) -> str:
        """Computes the SHA-256 hash of a file efficiently in 64KB chunks."""
        hasher = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return ""

    def categorize_file(self, file_path: Path) -> str:
        name_lower = file_path.name.lower()
        suffix = file_path.suffix.lower()
        if "steam_api" in name_lower or "goldberg" in name_lower:
            return "emulator"
        if suffix == ".exe":
            return "executable"
        if suffix == ".dll":
            return "dll"
        if suffix in (".ini", ".txt", ".json", ".xml", ".cfg"):
            return "config"
        return "data"

    def create_manifest(self, appid: Optional[str] = None, exclude_dirs: Optional[Set[str]] = None) -> Path:
        """Generates a cryptographic manifest of all executables, DLLs, and configs in the game folder."""
        if not self.game_dir.exists():
            raise FileNotFoundError(f"Game directory does not exist: {self.game_dir}")

        if exclude_dirs is None:
            exclude_dirs = {".gamecleaner", ".quarantine", ".gamecleaner_quarantine", ".gamecleaner_backup"}

        records: List[FileIntegrityRecord] = []

        for root, dirs, files in os.walk(self.game_dir):
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            r_path = Path(root)

            for f in sorted(files):
                if f == MANIFEST_FILENAME or f.startswith(".gc_"):
                    continue
                f_path = r_path / f
                suffix = f_path.suffix.lower()

                # Focus on executable code, libraries, and game configs
                if suffix in (".exe", ".dll", ".ini", ".txt", ".json", ".cfg", ".bat", ".ps1", ".cmd", ".vbs"):
                    rel_p = str(f_path.relative_to(self.game_dir)).replace("\\", "/")
                    sha = self.compute_sha256(f_path)
                    try:
                        sz = f_path.stat().st_size
                    except Exception:
                        sz = 0

                    records.append(
                        FileIntegrityRecord(
                            relative_path=rel_p,
                            sha256=sha,
                            size=sz,
                            category=self.categorize_file(f_path),
                        )
                    )

        manifest_data = {
            "generator": "GameCleaner Integrity Engine",
            "version": "2.0.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "appid": appid,
            "total_files": len(records),
            "files": [
                {
                    "path": r.relative_path,
                    "sha256": r.sha256,
                    "size": r.size,
                    "category": r.category,
                }
                for r in records
            ],
        }

        self.manifest_path.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")
        return self.manifest_path

    def verify(self) -> IntegrityReport:
        """Audits current game folder state against recorded cryptographic manifest."""
        if not self.manifest_path.exists():
            return IntegrityReport(
                game_dir=str(self.game_dir),
                manifest_path=str(self.manifest_path),
                is_valid=False,
                total_verified=0,
                tamper_alerts=[f"Manifest file not found: {self.manifest_path.name}. Run 'verify --create' first."],
            )

        try:
            data = json.loads(self.manifest_path.read_text(encoding="utf-8"))
            recorded_files = {item["path"]: item for item in data.get("files", [])}
        except Exception as e:
            return IntegrityReport(
                game_dir=str(self.game_dir),
                manifest_path=str(self.manifest_path),
                is_valid=False,
                total_verified=0,
                tamper_alerts=[f"Failed to parse manifest JSON: {e}"],
            )

        missing: List[str] = []
        modified: List[str] = []
        tamper_alerts: List[str] = []
        verified_count = 0

        # Check all recorded files
        for rel_path, rec in recorded_files.items():
            f_path = self.game_dir / rel_path.replace("/", os.sep)
            if not f_path.exists():
                missing.append(rel_path)
                if rec.get("category") in ("executable", "emulator"):
                    tamper_alerts.append(f"Critical binary missing: {rel_path}")
            else:
                current_sha = self.compute_sha256(f_path)
                if current_sha != rec.get("sha256"):
                    modified.append(rel_path)
                    tamper_alerts.append(f"Binary modification/tampering detected: {rel_path}")
                else:
                    verified_count += 1

        # Check for untracked binaries injected after manifest creation
        untracked: List[str] = []
        for root, dirs, files in os.walk(self.game_dir):
            dirs[:] = [d for d in dirs if not d.startswith(".gamecleaner") and not d.startswith(".quarantine")]
            r_path = Path(root)

            for f in files:
                if f == MANIFEST_FILENAME:
                    continue
                f_path = r_path / f
                if f_path.suffix.lower() in (".exe", ".dll"):
                    rel_p = str(f_path.relative_to(self.game_dir)).replace("\\", "/")
                    if rel_p not in recorded_files:
                        untracked.append(rel_p)
                        tamper_alerts.append(f"Untracked / newly injected binary detected: {rel_p}")

        is_valid = len(missing) == 0 and len(modified) == 0 and len(untracked) == 0

        return IntegrityReport(
            game_dir=str(self.game_dir),
            manifest_path=str(self.manifest_path),
            is_valid=is_valid,
            total_verified=verified_count,
            missing_files=missing,
            modified_files=modified,
            untracked_binaries=untracked,
            tamper_alerts=tamper_alerts,
        )
