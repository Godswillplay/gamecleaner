"""
Electron ASAR Archive Unpacker: Extracts JavaScript code and assets from Electron-based game launchers.
"""
from dataclasses import dataclass
import json
from pathlib import Path
import shutil
import struct
from typing import Dict, List, Optional


@dataclass
class AsarFileInfo:
    path: str
    size: int
    offset: int


class AsarUnpacker:
    """Extracts files from Chromium/Electron ASAR archives in pure Python."""

    def is_asar(self, file_path: Path) -> bool:
        file_path = Path(file_path)
        if not file_path.exists() or file_path.stat().st_size < 16:
            return False
        try:
            with open(file_path, "rb") as f:
                magic = f.read(4)
                return magic == b"\x04\x00\x00\x00"
        except Exception:
            return False

    def unpack(self, asar_path: Path, output_dir: Path) -> List[Path]:
        """Unpacks an ASAR archive into the target output directory."""
        asar_path = Path(asar_path).resolve()
        output_dir = Path(output_dir).resolve()
        output_dir.mkdir(parents=True, exist_ok=True)

        extracted_files: List[Path] = []
        unpacked_external_dir = asar_path.parent / f"{asar_path.name}.unpacked"

        with open(asar_path, "rb") as f:
            header_magic = f.read(4)
            if header_magic != b"\x04\x00\x00\x00":
                raise ValueError("Not a valid ASAR archive (magic mismatch)")

            # Chromium pickle framing:
            # Offset 0..3: magic (4)
            # Offset 4..7: header_pickle_size (uint32)
            # Offset 8..11: inner_pickle_size (uint32)
            # Offset 12..15: json_size (uint32)
            # Offset 16..16+json_size: json bytes
            # Offset 8 + header_pickle_size: Payload Data Start (always 4-byte aligned by pickle framing)
            header_pickle_size = struct.unpack("<I", f.read(4))[0]
            inner_size = struct.unpack("<I", f.read(4))[0]
            json_size = struct.unpack("<I", f.read(4))[0]

            json_bytes = f.read(json_size)
            header_json = json.loads(json_bytes.decode("utf-8", errors="ignore"))

            # Physical payload begins at 8 + header_pickle_size
            payload_base_offset = 8 + header_pickle_size

            def extract_node(node: dict, current_rel_path: str):
                files = node.get("files", {})
                for name, info in files.items():
                    # Sanitize node path against directory traversal
                    clean_name = name.replace("\\", "/").strip("/")
                    node_path = f"{current_rel_path}/{clean_name}" if current_rel_path else clean_name
                    parts = [p for p in node_path.split("/") if p and p != "."]
                    if any(p == ".." for p in parts):
                        continue

                    safe_rel_path = Path(*parts)
                    dest_file = (output_dir / safe_rel_path).resolve()

                    # Guarantee containment within output_dir
                    try:
                        if not dest_file.is_relative_to(output_dir):
                            continue
                    except AttributeError:
                        # Fallback for Python < 3.9
                        if not str(dest_file).startswith(str(output_dir)):
                            continue

                    if "files" in info:
                        # Directory node
                        extract_node(info, node_path)
                    elif info.get("unpacked") is True:
                        # File was unpacked separately during build (stored in *.asar.unpacked)
                        dest_file.parent.mkdir(parents=True, exist_ok=True)
                        external_file = unpacked_external_dir / safe_rel_path
                        if external_file.exists() and external_file.is_file():
                            shutil.copy2(str(external_file), str(dest_file))
                            extracted_files.append(dest_file)
                    elif "size" in info:
                        # Standard embedded file
                        size = int(info.get("size", 0))
                        dest_file.parent.mkdir(parents=True, exist_ok=True)

                        if size == 0:
                            dest_file.write_bytes(b"")
                            extracted_files.append(dest_file)
                        elif "offset" in info:
                            rel_offset = int(info["offset"])
                            f.seek(payload_base_offset + rel_offset)
                            data = f.read(size)
                            dest_file.write_bytes(data)
                            extracted_files.append(dest_file)

            extract_node(header_json, "")

        return extracted_files
