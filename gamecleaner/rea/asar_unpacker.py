"""
Electron ASAR Archive Unpacker: Extracts JavaScript code and assets from Electron-based game launchers.
"""
from dataclasses import dataclass
import json
from pathlib import Path
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

        with open(asar_path, "rb") as f:
            header_magic = f.read(4)
            if header_magic != b"\x04\x00\x00\x00":
                raise ValueError("Not a valid ASAR archive")

            total_size = struct.unpack("<I", f.read(4))[0]
            header_size = struct.unpack("<I", f.read(4))[0]
            json_size = struct.unpack("<I", f.read(4))[0]

            json_bytes = f.read(json_size)
            header_json = json.loads(json_bytes.decode("utf-8", errors="ignore"))

            # Payload data starts right after header
            payload_base_offset = f.tell()

            def extract_node(node: dict, current_rel_path: str):
                files = node.get("files", {})
                for name, info in files.items():
                    node_path = f"{current_rel_path}/{name}" if current_rel_path else name
                    if "files" in info:
                        # Directory
                        extract_node(info, node_path)
                    elif "size" in info and "offset" in info:
                        # File
                        size = info["size"]
                        rel_offset = int(info["offset"])
                        dest_file = output_dir / node_path.replace("/", "\\")
                        dest_file.parent.mkdir(parents=True, exist_ok=True)

                        # Seek and read
                        f.seek(payload_base_offset + rel_offset)
                        data = f.read(size)
                        dest_file.write_bytes(data)
                        extracted_files.append(dest_file)

            extract_node(header_json, "")

        return extracted_files
