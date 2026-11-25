"""Cross-target contract, loader metadata and unsupported-import regressions."""
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class MinuxTargetTests(unittest.TestCase):
    """Verify deployable MinUX output without depending on a booted guest."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='mlc-minux-test-')
        self.addCleanup(self.directory.cleanup)
        self.work = Path(self.directory.name)

    def compile(self, source, *options, target='minux-x64'):
        source_path, output = self.work/'main.ml', self.work/'app'
        source_path.write_text(source, encoding='utf-8')
        result = subprocess.run([sys.executable, str(ROOT/'mlc_win64.py'), str(source_path),
            str(output), '--target', target, '-I', str(ROOT), *options],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return result, output

    def test_minux_metadata_and_predefined_values(self):
        result, output = self.compile('''#if TARGET_OS != "minux" or TARGET_ARCH != "x64" or TARGET_ABI != "sysv" or TARGET_FORMAT != "elf" or POINTER_SIZE != 8
#error "incorrect target values"
#endif
print "hello"
''')
        self.assertEqual(result.returncode, 0, result.stdout)
        data = output.read_bytes()
        self.assertEqual(data[:7], b'\x7fELF\x02\x01\x01')
        self.assertEqual(struct.unpack_from('<Q', data, 24)[0], 0x100001000)
        phoff = struct.unpack_from('<Q', data, 32)[0]
        phnum = struct.unpack_from('<H', data, 56)[0]
        headers = [struct.unpack_from('<IIQQQQQQ', data, phoff+i*56) for i in range(phnum)]
        interp = next(row for row in headers if row[0] == 3)
        self.assertEqual(data[interp[2]:interp[2]+interp[5]], b'/lib/ld-minux.so\0')
        for row in headers:
            if row[0] == 1:
                self.assertGreaterEqual(row[3], 0x100000000)
                self.assertNotEqual(row[1] & 3, 3, 'writable executable segment')
        self.assertIn(b'libc.so.1\0', data)
        self.assertNotIn(b'libc.so.6\0', data)
        self.assertNotIn(b'libdl.so.2\0', data)

    def test_all_public_stdlib_packages_accept_minux(self):
        imports = []
        for source in sorted((ROOT/'std').rglob('*.ml')):
            if any(part.startswith('_') for part in source.relative_to(ROOT).parts):
                continue  # Private platform providers are selected by public modules.
            module = '.'.join(source.relative_to(ROOT).with_suffix('').parts)
            statement = f'import {module}'
            # Aliases require package metadata. Namespace-only modules are also
            # valid public modules and must be covered through their bare import.
            if re.search(r'(?m)^\s*package\s+', source.read_text(encoding='utf-8')):
                statement += f' as probe{len(imports)}'
            imports.append(statement)
        self.assertGreater(len(imports), 30)
        result, output = self.compile('\n'.join(imports) + '\nprint "public stdlib imports accepted"\n')
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertTrue(output.is_file())
        data = output.read_bytes()
        for library in (b'libc.so.6\0', b'libm.so.6\0', b'kernel32.dll\0'):
            self.assertNotIn(library, data)

    def test_rejects_unrepresentable_native_imports(self):
        cases = [
            ('libc.so.6', 'strlen', 'Linux ABI library'),
            ('kernel32.dll', 'GetCurrentProcessId', 'minux-x64 target'),
            ('/lib/libc.so.1', 'strlen', 'exact library basename'),
            ('libc.so.1 ', 'strlen', 'exact library basename'),
            ('__minilang_minux_runtime', 'unknown', 'unknown private'),
        ]
        for library, symbol, message in cases:
            with self.subTest(library=library):
                result, output = self.compile(f'extern function native() from "{library}" symbol "{symbol}" returns int\nprint native()\n')
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(message, result.stdout)
                self.assertFalse(output.exists())

    def test_rejects_global_symbol_collision(self):
        result, output = self.compile('''extern function first() from "liba.so" symbol "shared" returns int
extern function second() from "libb.so" symbol "shared" returns int
print first() + second()
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('global ELF namespace', result.stdout)
        self.assertFalse(output.exists())

    def test_duplicate_aliases_of_one_native_function(self):
        result, output = self.compile('''extern function first(text as cstr) from "libc.so.1" symbol "strlen" returns u64
extern function second(text as cstr) from "libc.so.1" symbol "strlen" returns u64
print first("abc") + second("def")
''')
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertTrue(output.exists())

    def test_minux_packing_roundtrip(self):
        from mlc.native_packing import unpack_image
        result, output = self.compile('print "hello"\n')
        self.assertEqual(result.returncode, 0, result.stdout)
        original = output.read_bytes()
        result, output = self.compile('print "hello"\n', '--pack')
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(unpack_image(output.read_bytes()), original)
        self.assertLess(len(output.read_bytes()),len(original))

    def test_standalone_packer_selects_native_minux_stub(self):
        from mlc.native_packing import pack_image, unpack_image
        from mlc.pack_loader_bytes import MINUX, LINUX
        result, output = self.compile('print "hello"\n')
        self.assertEqual(result.returncode, 0, result.stdout)
        original=output.read_bytes()
        packed=pack_image(original)
        self.assertEqual(unpack_image(packed), original)
        entry=struct.unpack_from('<Q',packed,24)[0]
        phoff=struct.unpack_from('<Q',packed,32)[0]
        count=struct.unpack_from('<H',packed,56)[0]
        rows=[struct.unpack_from('<IIQQQQQQ',packed,phoff+i*56) for i in range(count)]
        loader=next(row for row in rows if row[0]==1 and row[3]<=entry<row[3]+row[5])
        offset=loader[2]+entry-loader[3]
        self.assertEqual(packed[offset:offset+3],b'\x57\x56\x52','MinUX loader must preserve argc/argv/envp')
        # Native protection/exit requests use int 0x80; Linux uses syscall.
        self.assertIn(b'\xcd\x80',MINUX)
        self.assertNotEqual(MINUX,LINUX)

    def test_windows_subsystem_is_rejected(self):
        result, output = self.compile('print "hello"\n', '--subsystem', 'windows')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('console subsystem only', result.stdout)
        self.assertFalse(output.exists())

    def test_legacy_upx_is_rejected_before_tool_execution(self):
        from mlc.packing import transform, PackingError
        result, output=self.compile('print "hello"\n')
        self.assertEqual(result.returncode,0,result.stdout)
        destination=self.work/'packed'
        with self.assertRaisesRegex(PackingError,'built-in packer'):
            transform(output,destination,'tool-that-must-not-run')
        self.assertFalse(destination.exists())

    def test_writer_allows_large_intermediate_for_packing(self):
        from mlc.elf import build_elf64
        image=build_elf64(b'\xc3', b'\0'*(16*1024*1024), b'', 0, target='minux-x64')
        self.assertGreater(len(image),16*1024*1024)

    def test_target_participates_in_incremental_cache_identity(self):
        cache = self.work/'cache'
        source = 'print "cache target"\n'
        result, output = self.compile(source, '--incremental-cache', str(cache))
        self.assertEqual(result.returncode, 0, result.stdout)
        first = output.read_bytes()
        result, output = self.compile(source, '--incremental-cache', str(cache), target='linux-x64')
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertNotEqual(output.read_bytes(), first)
        result, output = self.compile(source, '--incremental-cache', str(cache))
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(output.read_bytes(), first)


if __name__ == '__main__':
    unittest.main()
