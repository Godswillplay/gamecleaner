"""
Steam Stub DRM Detector: Identifies executables wrapped in Valve's proprietary Steam Stub DRM (.bind sections).
Prevents crash-on-launch scenarios when Goldberg emulator is applied to encrypted binaries.
"""
from dataclasses import dataclass
import math
from pathlib import Path
from typing import Optional

try:
    import pefile
except ImportError:
    pefile = None


@dataclass
class SteamStubResult:
    file_path: str
    is_wrapped: bool
    stub_version: str
    section_name: Optional[str] = None
    entropy: float = 0.0
    guidance: str = ""


class SteamStubDetector:
    """Detects Valve Steam Stub DRM encapsulation in Windows PE binaries."""

    def __init__(self, binary_path: Path):
        self.binary_path = Path(binary_path)

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculates Shannon entropy for given byte slice."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        frequencies = [0] * 256
        for b in data:
            frequencies[b] += 1
        for count in frequencies:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 2)

    def scan(self) -> SteamStubResult:
        """Analyzes binary headers for Steam Stub DRM wrappers."""
        if not self.binary_path.exists() or not self.binary_path.is_file():
            return SteamStubResult(
                file_path=str(self.binary_path),
                is_wrapped=False,
                stub_version="None",
                guidance="File does not exist.",
            )

        try:
            content = self.binary_path.read_bytes()
        except Exception as e:
            return SteamStubResult(
                file_path=str(self.binary_path),
                is_wrapped=False,
                stub_version="None",
                guidance=f"Read error: {e}",
            )

        if not content.startswith(b"MZ"):
            return SteamStubResult(
                file_path=str(self.binary_path),
                is_wrapped=False,
                stub_version="None",
                guidance="Not a valid PE executable.",
            )

        # 1. Signature / Byte pattern checks for fast identification
        has_bind_string = (
            b".bind" in content
            or b"bind64.dll" in content
            or b"bind.dll" in content
            or b"SteamDrmPfn" in content
        )

        if not pefile:
            # Fallback when pefile is unavailable
            if has_bind_string:
                return SteamStubResult(
                    file_path=str(self.binary_path),
                    is_wrapped=True,
                    stub_version="Steam Stub (Signature Match)",
                    guidance="Binary contains Steam Stub signature markers (.bind). Unpack with Steamless before applying Goldberg.",
                )
            return SteamStubResult(
                file_path=str(self.binary_path),
                is_wrapped=False,
                stub_version="None",
                guidance="Clean (No Steam Stub markers found).",
            )

        try:
            pe = pefile.PE(data=content, fast_load=True)
            pe.parse_data_directories()

            entry_point_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            is_64bit = pe.FILE_HEADER.Machine == 0x8664

            target_section = None
            ep_in_bind = False

            for section in pe.sections:
                sec_name = section.Name.decode("utf-8", errors="ignore").rstrip("\x00").strip()
                sec_start = section.VirtualAddress
                sec_size = section.Misc_VirtualSize or section.SizeOfRawData
                sec_end = sec_start + sec_size

                if sec_name.lower() in (".bind", ".stub", ".steam"):
                    target_section = section
                    sec_entropy = self.calculate_entropy(section.get_data())
                    if sec_start <= entry_point_rva < sec_end:
                        ep_in_bind = True

                    variant = "SteamStub v3 (64-bit)" if is_64bit else "SteamStub v3 (32-bit)"
                    pe.close()
                    return SteamStubResult(
                        file_path=str(self.binary_path),
                        is_wrapped=True,
                        stub_version=variant,
                        section_name=sec_name,
                        entropy=sec_entropy,
                        guidance=(
                            f"Active Steam Stub DRM detected in section '{sec_name}' (Entropy: {sec_entropy}). "
                            "Executable entrypoint is encrypted! Goldberg emulator cannot launch until "
                            "the binary is unpacked using Steamless CLI."
                        ),
                    )

            # Check if entry point is outside normal code sections with high entropy
            for section in pe.sections:
                sec_start = section.VirtualAddress
                sec_size = section.Misc_VirtualSize or section.SizeOfRawData
                sec_end = sec_start + sec_size
                sec_name = section.Name.decode("utf-8", errors="ignore").rstrip("\x00").strip()

                if sec_start <= entry_point_rva < sec_end:
                    # If entry point is in an unusual section and has bind strings
                    if has_bind_string and sec_name.lower() not in (".text", "code"):
                        sec_entropy = self.calculate_entropy(section.get_data())
                        pe.close()
                        return SteamStubResult(
                            file_path=str(self.binary_path),
                            is_wrapped=True,
                            stub_version="SteamStub Custom Variant",
                            section_name=sec_name,
                            entropy=sec_entropy,
                            guidance=(
                                f"Custom Steam Stub DRM detected in entry section '{sec_name}'. "
                                "Steamless unpacking recommended."
                            ),
                        )

            pe.close()
        except Exception as e:
            if has_bind_string:
                return SteamStubResult(
                    file_path=str(self.binary_path),
                    is_wrapped=True,
                    stub_version="Steam Stub (Fallback)",
                    guidance=f"Binary contains Steam Stub .bind markers (PE parse: {e}). Unpack with Steamless before applying Goldberg.",
                )

        return SteamStubResult(
            file_path=str(self.binary_path),
            is_wrapped=False,
            stub_version="None",
            guidance="Clean (No Steam Stub DRM wrapper detected).",
        )
