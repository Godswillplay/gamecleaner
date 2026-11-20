"""
Unit tests for REA reverse-engineering modules.
"""
from pathlib import Path
import shutil
import tempfile
import unittest

from gamecleaner.rea import (
    BinaryDisassembler,
    EvidenceDossierCompiler,
    InterfaceExtractor,
    StringCrossReferencer,
)


class TestREAModules(unittest.TestCase):

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="rea_test_")).resolve()
        self.explorer_path = Path(r"C:\Windows\explorer.exe")
        if not self.explorer_path.exists():
            self.explorer_path = Path(r"C:\Windows\System32\cmd.exe")

    def tearDown(self):
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_interface_extractor(self):
        extractor = InterfaceExtractor()
        fake_binary = self.test_dir / "game.exe"
        fake_binary.write_bytes(
            b"Hello\x00SteamClient020\x00SteamUser021\x00SteamFriends017\x00World"
        )

        interfaces = extractor.extract_from_binary(fake_binary)
        self.assertIn("SteamClient020", interfaces)
        self.assertIn("SteamUser021", interfaces)
        self.assertIn("SteamFriends017", interfaces)

        out_file = self.test_dir / "steam_interfaces.txt"
        extractor.generate_interfaces_file(self.test_dir, out_file)
        self.assertTrue(out_file.exists())
        content = out_file.read_text(encoding="utf-8")
        self.assertIn("SteamClient020", content)

    def test_string_cross_referencer(self):
        xref = StringCrossReferencer()
        fake_binary = self.test_dir / "trojan.exe"
        fake_binary.write_bytes(
            b"MZ" + b"\x00" * 200 +
            b"https://c2-malware.example.com/api/steal\x00" +
            b"\\Google\\Chrome\\User Data\\Default\\Login Data\x00" +
            b"x64dbg\x00"
        )

        evidence = xref.analyze_pe_strings(fake_binary)
        categories = {e.category for e in evidence}
        self.assertIn("NETWORK_C2", categories)
        self.assertIn("INFOSTEALER_TARGET", categories)
        self.assertIn("ANTI_ANALYSIS", categories)

    def test_disassembler_on_explorer(self):
        if not self.explorer_path.exists():
            self.skipTest("explorer.exe not present")

        disasm = BinaryDisassembler()
        self.assertTrue(disasm.is_available)

        block = disasm.disassemble_entry_point(self.explorer_path, max_instructions=10)
        self.assertIsNotNone(block)
        self.assertGreater(len(block.instructions), 0)
        text = disasm.format_block_as_text(block)
        self.assertIn("EntryPoint", text)

    def test_dossier_compiler(self):
        if not self.explorer_path.exists():
            self.skipTest("explorer.exe not present")

        compiler = EvidenceDossierCompiler()
        dossier = compiler.build_dossier(self.explorer_path)
        self.assertIn("REA Evidence Dossier", dossier)
        self.assertIn("Disassembled Entry Point", dossier)
        self.assertIn(self.explorer_path.name, dossier)


if __name__ == "__main__":
    unittest.main()
