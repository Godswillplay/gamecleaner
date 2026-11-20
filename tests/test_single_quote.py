import shutil
import tempfile
import unittest
from pathlib import Path

from gamecleaner.analyzer.pe_scanner import _verify_trust_win32, check_authenticode_signature


class TestSingleQuoteHandling(unittest.TestCase):
    def test_single_quote_in_filename(self):
        tmp = Path(tempfile.mkdtemp(prefix="gc_quote_")).resolve()
        sample = tmp / "Assassin's Creed.dll"
        src = Path(r"C:\Windows\System32\kernel32.dll")
        if not src.exists():
            src = Path(r"C:\Windows\explorer.exe")
        try:
            shutil.copy2(str(src), str(sample))
            res = _verify_trust_win32(str(sample.resolve()))
            self.assertIn(res, ("Valid", "NotSigned"))

            status = check_authenticode_signature(sample)
            self.assertIn(status, ("Valid", "NotSigned"))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)



if __name__ == "__main__":
    unittest.main()
