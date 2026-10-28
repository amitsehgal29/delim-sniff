import unittest
from delim_sniff import sniff

class T(unittest.TestCase):
    def test_semicolon_crlf_bom(self):
        r = sniff(b"\xef\xbb\xbfid;name\r\n1;a\r\n2;b\r\n")
        self.assertEqual((r["delimiter"], r["line_endings"], r["bom"]), (";", "CRLF", True))
        self.assertFalse(r["ragged"])
    def test_pipe_ragged(self):
        r = sniff(b"a|b|c\n1|2|3\n4|5\n")
        self.assertEqual(r["delimiter"], "|")
        self.assertTrue(r["ragged"])
    def test_latin1(self):
        r = sniff("id,city\n1,M\xfcnchen\n".encode("latin-1"))
        self.assertEqual(r["encoding"], "latin-1")
    def test_tab(self):
        self.assertEqual(sniff(b"x\ty\n1\t2\n")["delimiter"], "\t")

if __name__ == "__main__":
    unittest.main()
