import shutil
import tempfile
import unittest
from pathlib import Path

from gamecleaner.analyzer.pe_scanner import _verify_trust_win32, check_authenticode_signature


class TestSingleQuoteHandling(unittest.TestCase):
    def test_single_quote_in_filename(self):
        tmp = Path(tempfile.mkdtemp(prefix="gc_quote_"))
        sample = tmp / "Assassin's Creed.exe"
        try:
            shutil.copy2(r"C:\Windows\explorer.exe", str(sample))
            res = _verify_trust_win32(str(sample.resolve()))
            self.assertEqual(res, "Valid")

            status = check_authenticode_signature(sample)
            self.assertEqual(status, "Valid")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
