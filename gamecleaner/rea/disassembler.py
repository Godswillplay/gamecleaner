"""
Binary Disassembly Engine: Disassembles x86/x64 instructions at entry points and sensitive routines.
"""
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional
import pefile

try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False


@dataclass
class DisassembledInstruction:
    address: int
    mnemonic: str
    op_str: str
    bytes_hex: str


@dataclass
class DisassemblyBlock:
    function_name: str
    rva: int
    instructions: List[DisassembledInstruction]


class BinaryDisassembler:
    """Disassembles x86/x64 code inside PE binaries using Capstone."""

    def __init__(self):
        self.is_available = CAPSTONE_AVAILABLE

    def disassemble_entry_point(self, binary_path: Path, max_instructions: int = 50) -> Optional[DisassemblyBlock]:
        """Disassembles instructions starting at the PE Entry Point."""
        if not self.is_available:
            return None

        binary_path = Path(binary_path)
        if not binary_path.exists():
            return None

        try:
            pe = pefile.PE(str(binary_path), fast_load=True)
            ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            image_base = pe.OPTIONAL_HEADER.ImageBase

            # Select architecture
            if pe.FILE_HEADER.Machine == 0x8664:
                mode = capstone.CS_MODE_64
            else:
                mode = capstone.CS_MODE_32

            # Read raw bytes at entry point
            ep_data = pe.get_data(ep_rva, max_instructions * 15)
            pe.close()
        except Exception:
            return None

        md = capstone.Cs(capstone.CS_ARCH_X86, mode)
        instructions: List[DisassembledInstruction] = []

        for i in md.disasm(ep_data, image_base + ep_rva):
            instructions.append(DisassembledInstruction(
                address=i.address,
                mnemonic=i.mnemonic,
                op_str=i.op_str,
                bytes_hex=i.bytes.hex(),
            ))
            if len(instructions) >= max_instructions:
                break

        return DisassemblyBlock(
            function_name="EntryPoint",
            rva=ep_rva,
            instructions=instructions,
        )

    def format_block_as_text(self, block: DisassemblyBlock) -> str:
        """Formats instructions as an annotated assembly listing for LLM reasoning."""
        lines = [f"; Disassembly of {block.function_name} (RVA: 0x{block.rva:08X})"]
        for ins in block.instructions:
            lines.append(f"0x{ins.address:016X}:  {ins.bytes_hex.ljust(20)} {ins.mnemonic:<8} {ins.op_str}")
        return "\n".join(lines)
