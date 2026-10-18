"""Packing metadata/CLI validation, independent of an installed UPX binary."""
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mlc import packing as p


class PackingTests(unittest.TestCase):
    def test_exact_roundtrips(self):
        for size in (1, 4095, 4096, 4097, 9000):
            for difference in (-1, 0, 3):
                original = bytes([37]) * size
                restored = bytearray(bytes([37]) * max(1, size + difference))
                restored[0] = 99
                packed = b'MZ compressed payload'
                image = packed + p.make_overlay(original, packed, restored)
                info = p.parse_overlay(image)
                self.assertEqual(p.restore_image(restored, info), original)

    def test_corruption(self):
        original, packed = b'x' * 5000, b'MZ packed payload'
        image = packed + p.make_overlay(original, packed, original)
        for offset in (0, len(packed), len(image) - 17, len(image) - 16, len(image) - 1):
            changed = bytearray(image)
            changed[offset] ^= 1
            with self.assertRaises(p.PackingError):
                p.parse_overlay(changed)
        info = p.parse_overlay(image)
        for wrong in (b'y' * 5000, b'x' * 4999, b'x' * 5001):
            with self.assertRaises(p.PackingError):
                p.restore_image(wrong, info)

    def test_rechecksummed_invalid_records(self):
        packed = b'MZ payload'
        header = struct.pack('<5I', 10, len(packed), 10, 0, zlib.crc32(packed))
        records = (struct.pack('<I', 100),
                   struct.pack('<3I', 1, 11, 1) + b'x',
                   struct.pack('<3I', 1, 0, 0),
                   struct.pack('<I', 0) + b'x',
                   struct.pack('<3I', 2, 0, 2) + b'xx' + struct.pack('<2I', 1, 1) + b'x')
        for record in records:
            metadata = header + record
            image = packed + metadata + p.MAGIC + struct.pack('<2I', len(metadata), zlib.crc32(metadata))
            with self.assertRaises(p.PackingError):
                p.parse_overlay(image)

    def test_invalid_options_and_environment(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {'MINILANG_UPX': ''}):
            upx = Path(tmp) / 'trusted tool'
            upx.touch()
            for args in (['--pack'], ['--pack=unknown'], ['--upx'], ['--upx', str(upx)],
                         ['--pack', '--unpack-exe'], ['--pack-exe', 'one', '--upx', str(upx)],
                         ['--pack', '--upx', str(upx), '--upx', str(upx)]):
                with self.assertRaises(p.PackingError):
                    p.parse_options(args)
            with patch.dict(os.environ, {'MINILANG_UPX': str(upx)}):
                parsed = p.parse_options(['source.ml', 'app.exe', '--pack=upx'])
                self.assertEqual(parsed.mode, 'compile')
                self.assertEqual(parsed.args, ['source.ml', 'app.exe'])

    def test_no_overwrite_before_running_tool(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, target = Path(tmp) / 'input', Path(tmp) / 'output'
            source.write_bytes(b'MZ original')
            target.write_bytes(b'keep me')
            with self.assertRaises(p.PackingError):
                p.transform(source, target, 'not-called')
            self.assertEqual(target.read_bytes(), b'keep me')
            self.assertEqual(source.read_bytes(), b'MZ original')


if __name__ == '__main__':
    unittest.main()
