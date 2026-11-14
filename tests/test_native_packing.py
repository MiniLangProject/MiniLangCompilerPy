"""Bounds and codec checks for the built-in executable packer."""

import random
import unittest

from mlc import native_packing as packing


class NativePackingCodecTests(unittest.TestCase):
    def test_lz4_roundtrip(self):
        random_bytes = random.Random(1764).randbytes(8192)
        for source in (b'', b'a', b'hello world', b'a' * 4096,
                       bytes(range(256)) * 4, random_bytes,
                       b'abc123' * 20000):
            encoded = packing.lz4_encode(source)
            self.assertEqual(packing.lz4_decode(encoded, len(source)), source)

    def test_lz4_corruption_and_bounds(self):
        for block, size in ((b'', 0), (b'\xf0', 0), (b'\x10', 1),
                            (b'\x00\x00\x00', 4), (b'\x00\x01\x00', 4),
                            (b'\x10a', 2)):
            with self.subTest(block=block, size=size):
                with self.assertRaises(packing.NativePackingError):
                    packing.lz4_decode(block, size)

    def test_reject_non_compiler_image(self):
        with self.assertRaises(packing.NativePackingError):
            packing.pack_image(b'MZ random bytes')
        with self.assertRaises(packing.NativePackingError):
            packing.unpack_image(b'MZ random bytes')


if __name__ == '__main__':
    unittest.main()
