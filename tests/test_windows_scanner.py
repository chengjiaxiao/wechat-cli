import contextlib
import io
import sys
import unittest
from unittest.mock import patch


@unittest.skipUnless(sys.platform == 'win32', 'Windows process API')
class WindowsScannerTests(unittest.TestCase):
    def setUp(self):
        from wechat_cli.keys import scanner_windows
        self.scanner = scanner_windows

    def test_find_bytes_across_chunk_boundary(self):
        memory = b'aaConfig.Cipherbb'
        with patch.object(self.scanner, '_read_mem',
                          side_effect=lambda h, addr, n: memory[addr-0x10000:addr-0x10000+n]):
            self.assertEqual(self.scanner._find_bytes(1, [(0x10000, len(memory))],
                                                      b'Config.Cipher', chunk_size=4), [0x10002])

    def test_unreadable_gap_cannot_create_a_false_match(self):
        def read(h, addr, n):
            return {0x10000: b'ab', 0x10002: None, 0x10004: b'cd'}.get(addr)
        with patch.object(self.scanner, '_read_mem', side_effect=read):
            self.assertEqual(self.scanner._find_bytes(1, [(0x10000, 6)], b'abcd', 2), [])

    def test_key_material_is_omitted_from_scan_logs(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.scanner._scan_log('    enc_key=synthetic-secret')
            self.scanner._scan_log('  OK: message/message_0.db')
        self.assertNotIn('synthetic-secret', output.getvalue())
        self.assertIn('OK:', output.getvalue())


if __name__ == '__main__':
    unittest.main()
