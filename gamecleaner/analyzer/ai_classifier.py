"""
AI-Assisted REA / Ghidra Decompiler Analysis Pipeline.
Extracts decompiled pseudo-code, disassembly, and string xrefs from suspicious game binaries
and formats structured prompts and triage payloads for Antigravity, Claude Code, or local LLMs
to classify whether a binary contains a benign DRM crack vs. hostile malware payload.
"""
from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from gamecleaner.analyzer.pe_scanner import PEScanResult
from gamecleaner.rea.disassembler import BinaryDisassembler
from gamecleaner.rea.string_xref import StringCrossReferencer, StringEvidence


@dataclass
class AITriagePayload:
    binary_path: str
    sha256: str
    architecture: str
    threat_severity: str
    suspicious_apis: List[str]
    critical_strings: List[str]
    disassembly_snippets: Dict[str, str]
    formatted_llm_prompt: str
    offline_heuristic_verdict: str
    offline_confidence: float


class AIDecompilerClassifier:
    """Bridges REA disassembly and Ghidra decompilation with agentic LLM triage."""

    def __init__(self):
        self.disassembler = BinaryDisassembler()
        self.string_scanner = StringCrossReferencer()

    def build_triage_payload(self, scan_result: PEScanResult, max_instructions: int = 40) -> AITriagePayload:
        """Constructs a comprehensive triage payload and prompt ready for Antigravity or Claude Code."""
        binary_p = Path(scan_result.file_path)
        
        # 1. Disassemble Entry Point
        disasm_map = {}
        try:
            entry_block = self.disassembler.disassemble_entry_point(binary_p, max_instructions=max_instructions)
            if entry_block and entry_block.instructions:
                lines = [f"0x{ins.address:08X}: {ins.mnemonic} {ins.op_str}" for ins in entry_block.instructions]
                disasm_map["entry_point"] = "\n".join(lines)
        except Exception:
            pass

        # 2. Extract suspicious strings
        critical_strings = []
        try:
            evidences = self.string_scanner.analyze_pe_strings(binary_p)
            for ev in evidences:
                critical_strings.append(f"{ev.category}: {ev.value}")
        except Exception:
            pass

        # Extract suspicious APIs
        sensitive_apis = getattr(scan_result, "sensitive_imports_found", None)
        if not sensitive_apis:
            sensitive_apis = []
            from gamecleaner.analyzer.threat_rules import SENSITIVE_APIS
            for dll_funcs in getattr(scan_result, "imports", {}).values():
                for func in dll_funcs:
                    if func in SENSITIVE_APIS:
                        sensitive_apis.append(func)
            scan_result.sensitive_imports_found = sensitive_apis

        # 3. Offline Heuristic Rule Assessment
        verdict, confidence = self._evaluate_offline_heuristics(scan_result, critical_strings, sensitive_apis=sensitive_apis)

        # 4. Format Prompt for LLM Agent
        prompt = self._format_agent_prompt(
            binary_name=binary_p.name,
            sha256=scan_result.sha256,
            architecture=scan_result.architecture,
            imports=sensitive_apis,
            strings=critical_strings,
            disassembly=disasm_map.get("entry_point", "N/A"),
            offline_verdict=verdict,
        )

        return AITriagePayload(
            binary_path=str(binary_p),
            sha256=scan_result.sha256,
            architecture=scan_result.architecture,
            threat_severity=scan_result.overall_severity,
            suspicious_apis=sensitive_apis,
            critical_strings=critical_strings,
            disassembly_snippets=disasm_map,
            formatted_llm_prompt=prompt,
            offline_heuristic_verdict=verdict,
            offline_confidence=confidence,
        )

    def _evaluate_offline_heuristics(
        self,
        scan_result: PEScanResult,
        critical_strings: List[str],
        sensitive_apis: Optional[List[str]] = None,
    ) -> Tuple[str, float]:
        """Calculates an offline triage verdict based on REA evidence."""
        if sensitive_apis is not None:
            imports = set(sensitive_apis)
        else:
            imports = set(getattr(scan_result, "sensitive_imports_found", None) or [])
            if not imports and hasattr(scan_result, "imports") and scan_result.imports:
                from gamecleaner.analyzer.threat_rules import SENSITIVE_APIS
                for dll_funcs in scan_result.imports.values():
                    for func in dll_funcs:
                        if func in SENSITIVE_APIS:
                            imports.add(func)
        
        # Injection & Evasion combinations
        has_injection = any("WriteProcessMemory" in imp or "CreateRemoteThread" in imp or "VirtualAllocEx" in imp for imp in imports)
        has_network = any("InternetOpen" in imp or "HttpSendRequest" in imp or "WSAStartup" in imp or "URLDownloadToFile" in imp for imp in imports)
        has_payload_strings = any("powershell" in s.lower() or "cmd.exe" in s.lower() or "http://" in s.lower() or "https://" in s.lower() for s in critical_strings)

        if has_injection and has_payload_strings:
            return "MALICIOUS_PROCESS_INJECTION", 0.92
        elif has_injection and has_network:
            return "MALICIOUS_DROPPER_OR_BEACON", 0.88
        elif any("VirtualProtect" in imp for imp in imports) and not has_network and not has_payload_strings:
            return "BENIGN_INLINE_DRM_HOOK", 0.78
        elif (
            getattr(scan_result, "is_steam_wrapper", False)
            or any(k in scan_result.file_name.lower() for k in ("steam_api", "eossdk", "uplay_r1", "uplay_r2"))
        ) and not has_injection:
            return "PIRATED_DRM_EMULATOR_WRAPPER", 0.85
        else:
            return "SUSPICIOUS_UNKNOWN", 0.50

    def _format_agent_prompt(
        self,
        binary_name: str,
        sha256: str,
        architecture: str,
        imports: List[str],
        strings: List[str],
        disassembly: str,
        offline_verdict: str,
    ) -> str:
        """Formats the prompt to be dispatched to Antigravity, Claude Code, or Gemini."""
        return (
            f"# GameCleaner AI Reverse-Engineering Triage: {binary_name}\n\n"
            f"**File Details:**\n"
            f"- Architecture: {architecture}\n"
            f"- SHA256: {sha256}\n"
            f"- Baseline Heuristic Verdict: {offline_verdict}\n\n"
            f"**Suspicious API Imports:**\n"
            f"{json.dumps(imports, indent=2)}\n\n"
            f"**Critical String Indicators:**\n"
            f"{json.dumps(strings, indent=2)}\n\n"
            f"**Entry Point Disassembly:**\n"
            f"```x86asm\n{disassembly}\n```\n\n"
            f"**Task for AI Security Analyst:**\n"
            f"Evaluate whether this binary's behavior represents:\n"
            f"1. A **benign DRM crack** (e.g., license check bypass, offline Steam/EOS emulator hook).\n"
            f"2. A **hostile malware payload** (e.g., cryptominer, remote access trojan, process hollowing, stealer).\n\n"
            f"Provide a definitive verdict (BENIGN_CRACK or HOSTILE_MALWARE), key evidence markers, and containment recommendations."
        )
