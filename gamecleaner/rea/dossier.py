"""
Evidence Dossier Compiler: Prepares structured reverse-engineering evidence for AI agents (Claude Code / Antigravity).
"""
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from gamecleaner.analyzer import PEScanner
from gamecleaner.rea.disassembler import BinaryDisassembler
from gamecleaner.rea.interface_extractor import InterfaceExtractor
from gamecleaner.rea.string_xref import StringCrossReferencer


class EvidenceDossierCompiler:
    """Builds structured Markdown evidence dossiers for AI agent consumption."""

    def __init__(self):
        self.pe_scanner = PEScanner()
        self.string_xref = StringCrossReferencer()
        self.disasm = BinaryDisassembler()
        self.interface_extractor = InterfaceExtractor()

    def build_dossier(self, binary_path: Path) -> str:
        binary_path = Path(binary_path).resolve()
        if not binary_path.exists():
            return f"Error: Binary {binary_path} not found."

        pe_res = self.pe_scanner.scan_file(binary_path)
        strings = self.string_xref.analyze_pe_strings(binary_path)
        interfaces = self.interface_extractor.extract_from_binary(binary_path)
        disasm_block = self.disasm.disassemble_entry_point(binary_path, max_instructions=30)

        lines = [
            f"# REA Evidence Dossier: `{binary_path.name}`",
            f"**Path:** `{binary_path}`  ",
            f"**SHA256:** `{pe_res.sha256}`  ",
            f"**Architecture:** {pe_res.architecture}  ",
            f"**Authenticode Signature Status:** {pe_res.signature_status} (Valid: {pe_res.is_signed})  ",
            f"**Threat Score:** {pe_res.threat_score}/100 ({pe_res.overall_severity})  ",
            "",
            "## 1. Suspicious API Imports & Findings",
        ]

        if pe_res.findings:
            for f in pe_res.findings:
                lines.append(f"- **[{f.severity}] {f.name}** ({f.category}): {f.details}")
        else:
            lines.append("- *No high-risk Windows APIs flagged.*")

        lines.extend([
            "",
            "## 2. High-Value String Artifacts & Section Cross-References",
        ])

        if strings:
            lines.append("| Category | Value | Section | Offset | Encoding |")
            lines.append("| :--- | :--- | :--- | :--- | :--- |")
            for s in strings:
                enc = "UTF-16" if s.is_wide else "ASCII"
                safe_val = s.value[:60].replace("|", "\\|").replace("\r", " ").replace("\n", " ").replace("`", "'")
                lines.append(f"| `{s.category}` | `{safe_val}` | `{s.section}` | `0x{s.offset:X}` | {enc} |")
        else:
            lines.append("- *No categorized C2, stealer, or anti-analysis strings discovered.*")

        lines.extend([
            "",
            "## 3. Discovered Steamworks Interfaces (For Goldberg Emulator)",
        ])

        if interfaces:
            lines.append(", ".join([f"`{i}`" for i in interfaces]))
        else:
            lines.append("- *No Steamworks interface version strings found.*")

        lines.extend([
            "",
            "## 4. Disassembled Entry Point Assembly",
            "```x86asm",
        ])

        if disasm_block and disasm_block.instructions:
            lines.append(self.disasm.format_block_as_text(disasm_block))
        else:
            lines.append("; Capstone disassembly not available or empty entrypoint")

        lines.extend([
            "```",
            "",
            "## 5. Agent Instructions",
            "Review the evidence above to answer:",
            "1. Is this binary a legitimate game file, a harmless crack wrapper hook, or a hostile trojan?",
            "2. If strings target browser paths (`User Data`, `Cookies`) or C2 webhooks, what is the exfiltration mechanism?",
            "3. If replacing with Goldberg emulator, use the discovered interfaces in Section 3 for `steam_interfaces.txt`.",
        ])

        return "\n".join(lines)
