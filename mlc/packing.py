"""Optional UPX packing with deterministic, byte-exact MiniLang restoration.

UPX can normalize PE headers/import tables. A small checked overlay records
changed 4-KiB blocks so --unpack-exe restores the original file, not merely an
equivalent executable. CRCs detect corruption, not hostile tampering. Only use
this feature with trusted executables and a trusted UPX installation.
"""
from dataclasses import dataclass
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import zlib

MAGIC = b'MLPACK01'
LIMIT = 1 << 30
META_LIMIT = 16 << 20
BLOCK = 4096


class PackingError(ValueError):
    """A failed operation which must not replace the destination."""


@dataclass
class Options:
    """Resolved packaging switches for a compiler invocation."""
    args: list[str]
    mode: str = ''
    upx: str = ''


def parse_options(args):
    """Strip packing switches; standalone modes accept exactly two paths."""
    out = Options([])
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ('--pack', '--pack=upx', '--pack-exe', '--unpack-exe'):
            if out.mode:
                raise PackingError('packing modes are mutually exclusive')
            out.mode = {'--pack-exe': 'pack', '--unpack-exe': 'unpack'}.get(arg, 'compile')
        elif arg == '--upx':
            i += 1
            if i >= len(args) or not args[i] or args[i].startswith('--') or out.upx:
                raise PackingError('--upx requires one executable path')
            out.upx = args[i]
        elif arg.startswith('--pack='):
            raise PackingError('only --pack=upx is supported')
        else:
            out.args.append(arg)
        i += 1
    if out.upx and not out.mode:
        raise PackingError('--upx requires a packing mode')
    if out.mode:
        out.upx = out.upx or os.environ.get('MINILANG_UPX', '')
        if not out.upx or not Path(out.upx).is_file():
            raise PackingError('set --upx PATH or MINILANG_UPX to a trusted UPX executable')
        out.upx = str(Path(out.upx).resolve())
        if out.mode != 'compile' and len(out.args) != 2:
            raise PackingError('--pack-exe/--unpack-exe require INPUT OUTPUT')
    return out


def read_image(path):
    """Bound host memory before reading an executable or temporary image."""
    if not path.is_file() or not 0 < path.stat().st_size <= LIMIT:
        raise PackingError('input must be a regular file between 1 byte and 1 GiB')
    return path.read_bytes()


def make_overlay(original, packed, restored):
    """Encode deterministic restoration blocks; no paths, dates or random IDs."""
    patches = bytearray()
    count = 0
    for start in range(0, len(original), BLOCK):
        data = original[start:start + BLOCK]
        if data != restored[start:start + BLOCK]:
            patches += struct.pack('<II', start, len(data)) + data
            count += 1
            if len(patches) > META_LIMIT - 24:
                raise PackingError('UPX normalization requires too much restoration metadata')
    metadata = struct.pack('<6I', len(original), len(packed), len(restored),
                           zlib.crc32(original), zlib.crc32(packed), count) + patches
    return bytes(metadata) + MAGIC + struct.pack('<II', len(metadata), zlib.crc32(metadata))


def parse_overlay(image):
    """Validate every bound/record before invoking the external unpacker."""
    if len(image) < 40 or image[-16:-8] != MAGIC:
        raise PackingError('not a MiniLang packed executable')
    size, checksum = struct.unpack_from('<II', image, len(image) - 8)
    if not 24 <= size <= META_LIMIT or size > len(image) - 16:
        raise PackingError('invalid restoration metadata length')
    metadata = image[-16-size:-16]
    if zlib.crc32(metadata) != checksum:
        raise PackingError('restoration metadata checksum mismatch')
    original_size, packed_size, restored_size, original_crc, packed_crc, count = struct.unpack_from('<6I', metadata)
    if (not 0 < original_size <= LIMIT or not 0 < restored_size <= LIMIT or
            packed_size != len(image) - size - 16 or not packed_size):
        raise PackingError('invalid packed image lengths')
    packed = image[:packed_size]
    if zlib.crc32(packed) != packed_crc:
        raise PackingError('packed image checksum mismatch')
    patches = []
    cursor, end = 24, 0
    if count > (size - 24) // 9:
        raise PackingError('invalid restoration record count')
    for _ in range(count):
        if cursor + 8 > size:
            raise PackingError('truncated restoration record')
        start, length = struct.unpack_from('<II', metadata, cursor)
        cursor += 8
        if (not 0 < length <= BLOCK or start < end or start + length > original_size
                or cursor + length > size):
            raise PackingError('invalid restoration block')
        patches.append((start, metadata[cursor:cursor + length]))
        cursor += length
        end = start + length
    if cursor != size:
        raise PackingError('trailing restoration data')
    return packed, original_size, restored_size, original_crc, patches


def restore_image(restored, info):
    """Apply verified blocks and require the original whole-file checksum."""
    _, size, expected_restored, checksum, patches = info
    if len(restored) != expected_restored:
        raise PackingError('unexpected UPX unpacked size')
    output = bytearray(size)
    output[:min(size, len(restored))] = restored[:size]
    for start, data in patches:
        output[start:start + len(data)] = data
    if zlib.crc32(output) != checksum:
        raise PackingError('restored executable checksum mismatch')
    return bytes(output)


def transform(source, destination, upx, *, unpack=False, replace=False):
    """Stage and validate the result before atomic publication; preserve input."""
    source, destination = Path(source).resolve(), Path(destination).absolute()
    if not replace and destination.exists():
        raise PackingError('destination already exists; choose a new output path')
    original = read_image(source)
    if not unpack and not (original[:2] == b'MZ' or original[:4] == b'\x7fELF'):
        raise PackingError('only PE/ELF executables can be packed')
    if not unpack and original[-16:-8] == MAGIC:
        raise PackingError('input is already MiniLang-packed')
    info = parse_overlay(original) if unpack else None
    with tempfile.TemporaryDirectory(prefix=destination.name + '.mlpack-', dir=destination.parent) as folder:
        folder = Path(folder)
        payload, packed, roundtrip, result = (folder / n for n in ('payload.bin', 'packed.bin', 'roundtrip.bin', 'result.bin'))

        def run(*arguments):
            try:
                process = subprocess.run([upx, '--no-env', '--no-progress', *map(str, arguments)],
                                         timeout=600, check=False)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise PackingError(f'cannot run UPX: {exc}') from exc
            if process.returncode:
                raise PackingError(f'UPX failed (exit {process.returncode}); destination unchanged')

        if unpack:
            payload.write_bytes(info[0])
            run('-d', '-o', roundtrip, payload)
            output = restore_image(read_image(roundtrip), info)
        else:
            run('--best', '--no-lzma', '--overlay=copy', '-o', packed, source)
            run('-t', packed)
            run('-d', '-o', roundtrip, packed)
            packed_data = read_image(packed)
            output = packed_data + make_overlay(original, packed_data, read_image(roundtrip))
            if len(output) >= len(original):
                raise PackingError('packing would not make this executable smaller')
        result.write_bytes(output)
        # Preserve ordinary execute/read/write permissions, never privilege bits.
        os.chmod(result, source.stat().st_mode & 0o777)
        if replace:
            os.replace(result, destination)
        else:
            # link() is atomic and refuses a concurrently created destination.
            os.link(result, destination)
        print(f"OK: {'unpacked' if unpack else 'packed'} {destination} ({len(original)} -> {len(output)} bytes)")
