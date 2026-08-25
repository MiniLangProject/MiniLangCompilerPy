"""Deterministic fixed-address ELF64 image writer for Linux x86-64.

Images without native imports stay completely static.  When MiniLang source
declares Linux ``extern`` functions, the writer adds the smallest useful
``PT_INTERP``/``PT_DYNAMIC`` payload and loader relocations for the compiler's
IAT-compatible function-pointer slots.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterable, Sequence


def _align(value: int, alignment: int) -> int:
    return (int(value) + alignment - 1) & -alignment


@dataclass(frozen=True)
class ELFLayout:
    """File offsets and image-relative virtual addresses for compiler sections."""

    base: int
    text_off: int
    rdata_off: int
    data_off: int
    dynamic_off: int
    bss_off: int


def plan_elf64(text_size: int, rdata_size: int, data_size: int, dynamic_size: int = 0) -> ELFLayout:
    """Return the stable page-aligned layout used by :func:`build_elf64`."""
    text_off = 0x1000
    rdata_off = _align(text_off + int(text_size), 0x1000)
    data_off = _align(rdata_off + int(rdata_size), 0x1000)
    dynamic_off = _align(data_off + int(data_size), 8)
    bss_off = _align(dynamic_off + int(dynamic_size), 16)
    return ELFLayout(0x400000, text_off, rdata_off, data_off, dynamic_off, bss_off)


@dataclass(frozen=True)
class DynamicImport:
    """One ELF symbol and the offset of its writable function-pointer slot."""

    library: str
    symbol: str
    slot_offset: int


@dataclass(frozen=True)
class _DynamicBlob:
    data: bytes
    interp_offset: int
    interp_size: int
    table_offset: int
    table_size: int


def _normalize_imports(imports: Iterable[DynamicImport | Sequence[object]]) -> list[DynamicImport]:
    """Normalize, validate and deterministically de-duplicate loader imports."""
    result: list[DynamicImport] = []
    seen: set[tuple[str, str, int]] = set()
    for raw in imports:
        if isinstance(raw, DynamicImport):
            item = raw
        else:
            item = DynamicImport(str(raw[0]), str(raw[1]), int(raw[2]))
        library = item.library.strip()
        symbol = item.symbol.strip()
        slot = int(item.slot_offset)
        if not library or not symbol or slot < 0:
            raise ValueError('invalid ELF dynamic import')
        key = (library, symbol, slot)
        if key not in seen:
            seen.add(key)
            result.append(DynamicImport(*key))
    return result


def _dynamic_blob(imports: list[DynamicImport], *, image_base: int, data_off: int,
                  blob_off: int) -> _DynamicBlob:
    """Build dynamic strings, symbols, relocations and the ``DT_*`` table."""
    interp = b'/lib64/ld-linux-x86-64.so.2\x00'
    blob = bytearray(interp)

    def align_blob(alignment: int) -> None:
        blob.extend(b'\x00' * (_align(len(blob), alignment) - len(blob)))

    libraries: list[str] = []
    symbols: list[str] = []
    for item in imports:
        if item.library not in libraries:
            libraries.append(item.library)
        if item.symbol not in symbols:
            symbols.append(item.symbol)

    align_blob(8)
    dynstr_off = len(blob)
    dynstr = bytearray(b'\x00')
    string_offsets: dict[str, int] = {}
    for value in libraries + symbols:
        if value in string_offsets:
            continue
        string_offsets[value] = len(dynstr)
        dynstr += value.encode('utf-8') + b'\x00'
    blob += dynstr

    align_blob(8)
    dynsym_off = len(blob)
    blob += b'\x00' * 24
    symbol_indices: dict[str, int] = {}
    for index, symbol in enumerate(symbols, start=1):
        symbol_indices[symbol] = index
        blob += struct.pack('<IBBHQQ', string_offsets[symbol], 0x12, 0, 0, 0, 0)

    # A one-bucket SysV hash table is compact and valid for any symbol count.
    align_blob(8)
    hash_off = len(blob)
    nchain = len(symbols) + 1
    blob += struct.pack('<II', 1, nchain)
    blob += struct.pack('<I', 1 if symbols else 0)
    chains = [0]
    chains.extend((index + 1 if index < len(symbols) else 0) for index in range(1, len(symbols) + 1))
    blob += b''.join(struct.pack('<I', value) for value in chains)

    align_blob(8)
    rela_off = len(blob)
    for item in imports:
        relocation_offset = image_base + data_off + item.slot_offset
        relocation_info = (symbol_indices[item.symbol] << 32) | 6  # R_X86_64_GLOB_DAT
        blob += struct.pack('<QQq', relocation_offset, relocation_info, 0)
    rela_size = len(imports) * 24

    align_blob(8)
    table_off = len(blob)
    blob_addr = image_base + blob_off
    entries: list[tuple[int, int]] = []
    entries.extend((1, string_offsets[library]) for library in libraries)  # DT_NEEDED
    entries.extend((
        (4, blob_addr + hash_off),       # DT_HASH
        (5, blob_addr + dynstr_off),     # DT_STRTAB
        (6, blob_addr + dynsym_off),     # DT_SYMTAB
        (10, len(dynstr)),               # DT_STRSZ
        (11, 24),                        # DT_SYMENT
        (7, blob_addr + rela_off),       # DT_RELA
        (8, rela_size),                  # DT_RELASZ
        (9, 24),                         # DT_RELAENT
        (0, 0),                          # DT_NULL
    ))
    for tag, value in entries:
        blob += struct.pack('<qQ', tag, value)
    return _DynamicBlob(bytes(blob), 0, len(interp), table_off, len(entries) * 16)


def dynamic_size(imports: Iterable[DynamicImport | Sequence[object]]) -> int:
    """Return the loader-metadata size needed by an import set."""
    normalized = _normalize_imports(imports)
    if not normalized:
        return 0
    return len(_dynamic_blob(normalized, image_base=0, data_off=0, blob_off=0).data)


def build_elf64(text: bytes, rdata: bytes, data: bytes, bss_size: int, *, entry_offset: int = 0,
                imports: Iterable[DynamicImport | Sequence[object]] = ()) -> bytes:
    """Build a static or minimally dynamic ET_EXEC image."""
    normalized_imports = _normalize_imports(imports)
    dyn_size = dynamic_size(normalized_imports)
    layout = plan_elf64(len(text), len(rdata), len(data), dyn_size)
    dynamic_info = (_dynamic_blob(normalized_imports, image_base=layout.base, data_off=layout.data_off,
                                  blob_off=layout.dynamic_off) if normalized_imports else None)
    dynamic = dynamic_info.data if dynamic_info is not None else b''
    phnum = 6 if normalized_imports else 4
    header_size = 64 + phnum * 56
    if header_size > layout.text_off:
        raise ValueError('ELF headers overlap .text')

    ident = b'\x7fELF' + bytes((2, 1, 1, 0)) + b'\x00' * 8
    ehdr = ident + struct.pack(
        '<HHIQQQIHHHHHH',
        2, 62, 1, layout.base + layout.text_off + int(entry_offset),
        64, 0, 0, 64, 56, phnum, 0, 0, 0,
    )

    def ph(kind: int, flags: int, off: int, filesz: int, memsz: int, alignment: int = 0x1000) -> bytes:
        return struct.pack('<IIQQQQQQ', kind, flags, off, layout.base + off,
                           layout.base + off, filesz, memsz, alignment)

    headers = bytearray(ehdr)
    if dynamic_info is not None:
        headers += ph(3, 4, layout.dynamic_off + dynamic_info.interp_offset,
                      dynamic_info.interp_size, dynamic_info.interp_size, 1)
    headers += ph(1, 4, 0, layout.text_off, layout.text_off)
    headers += ph(1, 5, layout.text_off, len(text), len(text))
    headers += ph(1, 4, layout.rdata_off, len(rdata), len(rdata))
    data_filesz = layout.bss_off - layout.data_off
    headers += ph(1, 6, layout.data_off, data_filesz, data_filesz + int(bss_size))
    if dynamic_info is not None:
        headers += ph(2, 6, layout.dynamic_off + dynamic_info.table_offset,
                      dynamic_info.table_size, dynamic_info.table_size, 8)

    out = headers
    out += b'\x00' * (layout.text_off - len(out))
    out += text
    out += b'\x00' * (layout.rdata_off - len(out))
    out += rdata
    out += b'\x00' * (layout.data_off - len(out))
    out += data
    out += b'\x00' * (layout.dynamic_off - len(out))
    out += dynamic
    out += b'\x00' * (layout.bss_off - len(out))
    return bytes(out)
