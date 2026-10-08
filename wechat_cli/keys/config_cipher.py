"""Read WCDB Config.Cipher objects without modifying process memory.

Object layout and XOR decoding adapted from Apache-2.0 licensed
wechatauto-replica's wechatauto/db.py; see THIRD_PARTY_NOTICES.md.
"""
import re
import struct

from .common import scan_memory_for_keys

CONFIG_CIPHER_NAME = b"com.Tencent.WCDB.Config.Cipher"
CONFIG_XOR_MASK = bytes.fromhex(
    "d2c7442458020000004889442450488b"
    "450048844c2448488944254048584c24"
)
HEX_LITERAL_RE = re.compile(rb"[xX]'([0-9a-fA-F]{64,192})'")


def _valid_pointer(addr):
    return 0x10000 <= addr < 0x800000000000


def iter_cipher_blobs(read, find):
    """Yield (address, decoded blob) through injected read/find backends."""
    names = set(find(CONFIG_CIPHER_NAME))
    for name_addr in sorted(names):
        pair = struct.pack("<QQ", name_addr, len(CONFIG_CIPHER_NAME))
        for ref in find(pair):
            if not _valid_pointer(ref - 0x10):
                continue
            node = read(ref - 0x10, 0x50)
            if not node or len(node) < 0x40:
                continue
            if struct.unpack_from("<Q", node, 0x10)[0] not in names:
                continue
            if struct.unpack_from("<Q", node, 0x18)[0] != len(CONFIG_CIPHER_NAME):
                continue
            config_ptr = struct.unpack_from("<Q", node, 0x28)[0]
            if not _valid_pointer(config_ptr) or not _valid_pointer(config_ptr + 0x88):
                continue
            obj = read(config_ptr + 0x88, 0x28)
            if not obj or len(obj) < 0x18:
                continue
            data_ptr, data_len = struct.unpack_from("<QQ", obj, 8)
            if not _valid_pointer(data_ptr) or not 0 < data_len <= 1024:
                continue
            blob = read(data_ptr, data_len)
            if not blob or len(blob) != data_len:
                continue
            decoded = bytes(v ^ CONFIG_XOR_MASK[i % len(CONFIG_XOR_MASK)]
                            for i, v in enumerate(blob))
            yield data_ptr, decoded


def scan_config_cipher_keys(read, find, db_files, salt_to_dbs, key_map,
                            remaining_salts, pid, log):
    """Verify every candidate against a real database page before accepting."""
    matches = 0
    for addr, blob in iter_cipher_blobs(read, find):
        matches += scan_memory_for_keys(
            blob, HEX_LITERAL_RE, db_files, salt_to_dbs, key_map,
            remaining_salts, addr, pid, log,
        )
        if not remaining_salts:
            break
    return matches
