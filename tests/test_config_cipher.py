import hashlib
import hmac
import struct
import unittest

from wechat_cli.keys.config_cipher import (
    CONFIG_CIPHER_NAME, CONFIG_XOR_MASK, iter_cipher_blobs, scan_config_cipher_keys,
)


class CipherFixture:
    """Synthetic object memory; no real process data or encryption keys."""
    name_addr, ref, config_ptr, data_ptr = 0x10000, 0x20010, 0x30000, 0x40000

    def __init__(self, literal):
        self.node = bytearray(0x50)
        struct.pack_into('<QQ', self.node, 0x10, self.name_addr, len(CONFIG_CIPHER_NAME))
        struct.pack_into('<Q', self.node, 0x28, self.config_ptr)
        self.obj = bytearray(0x28)
        self.blob = bytes(v ^ CONFIG_XOR_MASK[i % len(CONFIG_XOR_MASK)]
                          for i, v in enumerate(literal))
        struct.pack_into('<QQ', self.obj, 8, self.data_ptr, len(self.blob))

    def find(self, needle):
        if needle == CONFIG_CIPHER_NAME:
            return [self.name_addr]
        if needle == struct.pack('<QQ', self.name_addr, len(CONFIG_CIPHER_NAME)):
            return [self.ref]
        return []

    def read(self, addr, size):
        data = {self.ref - 0x10: self.node, self.config_ptr + 0x88: self.obj,
                self.data_ptr: self.blob}.get(addr)
        return bytes(data[:size]) if data is not None else None


def authenticated_page(key, salt):
    """Build an independently authenticated SQLCipher4 page for acceptance tests."""
    page = bytearray(salt + bytes(4096 - 16))
    mac_key = hashlib.pbkdf2_hmac('sha512', key, bytes(b ^ 0x3A for b in salt), 2, dklen=32)
    page[-64:] = hmac.new(mac_key, page[16:4032] + struct.pack('<I', 1), hashlib.sha512).digest()
    return bytes(page)


class ConfigCipherTests(unittest.TestCase):
    key = bytes(range(32))
    salt = bytes(range(16))

    def scan(self, literal, page=None):
        fixture = CipherFixture(literal)
        page = authenticated_page(self.key, self.salt) if page is None else page
        salt = self.salt.hex()
        keys, remaining = {}, {salt}
        scan_config_cipher_keys(fixture.read, fixture.find,
                                [('message/message_0.db', 'unused', 4096, salt, page)],
                                {salt: ['message/message_0.db']}, keys, remaining, 1, lambda _: None)
        return keys, remaining

    def test_xor_decode_preserves_raw_literal(self):
        literal = b"prefix x'" + self.key.hex().encode() + b"' suffix"
        fixture = CipherFixture(literal)
        self.assertEqual(list(iter_cipher_blobs(fixture.read, fixture.find)),
                         [(fixture.data_ptr, literal)])

    def test_96_hex_raw_key_accepted_only_with_page_authentication(self):
        keys, remaining = self.scan(b"X'" + (self.key + self.salt).hex().upper().encode() + b"'")
        self.assertEqual(keys, {self.salt.hex(): self.key.hex()})
        self.assertEqual(remaining, set())

    def test_64_hex_raw_key_accepted(self):
        keys, _ = self.scan(b"x'" + self.key.hex().encode() + b"'")
        self.assertEqual(keys, {self.salt.hex(): self.key.hex()})

    def test_wrong_candidate_cannot_unlock_database(self):
        keys, remaining = self.scan(b"x'" + bytes(range(1, 33)).hex().encode() + b"'")
        self.assertEqual(keys, {})
        self.assertEqual(remaining, {self.salt.hex()})

    def test_corrupt_page_cannot_be_accepted(self):
        page = bytearray(authenticated_page(self.key, self.salt))
        page[128] ^= 1
        keys, _ = self.scan(b"x'" + self.key.hex().encode() + b"'", bytes(page))
        self.assertEqual(keys, {})

    def test_bad_candidate_does_not_hide_later_valid_key(self):
        literal = (b"x'" + bytes(32).hex().encode() + b"' x'"
                   + self.key.hex().encode() + b"'")
        keys, _ = self.scan(literal)
        self.assertEqual(keys, {self.salt.hex(): self.key.hex()})

    def test_invalid_object_references_are_skipped(self):
        for field, value in [('name', 0), ('length', 1), ('pointer', 0), ('size', 1025)]:
            with self.subTest(field=field):
                fixture = CipherFixture(b"x'" + self.key.hex().encode() + b"'")
                target, offset = {'name': (fixture.node, 0x10), 'length': (fixture.node, 0x18),
                                  'pointer': (fixture.obj, 8), 'size': (fixture.obj, 0x10)}[field]
                struct.pack_into('<Q', target, offset, value)
                self.assertEqual(list(iter_cipher_blobs(fixture.read, fixture.find)), [])

    def test_short_memory_reads_are_skipped(self):
        fixture = CipherFixture(b"x'" + self.key.hex().encode() + b"'")
        original = fixture.read
        self.assertEqual(list(iter_cipher_blobs(
            lambda addr, size: original(addr, size)[:8] if original(addr, size) else None,
            fixture.find)), [])

    def test_truncated_blob_is_skipped(self):
        fixture = CipherFixture(b"x'" + self.key.hex().encode() + b"'")
        fixture.blob = fixture.blob[:-1]
        self.assertEqual(list(iter_cipher_blobs(fixture.read, fixture.find)), [])

    def test_missing_wechat_object_is_empty(self):
        self.assertEqual(list(iter_cipher_blobs(lambda *_: None, lambda _: [])), [])


if __name__ == '__main__':
    unittest.main()
