"""
PE32+ (Windows x64) writer utilities.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Dict, List, Tuple

from .tools import align_up, u16, u32, u64


@dataclass
class Section:
    """A PE section (header + raw bytes) used by :class:`PEBuilder`."""
    name: str
    data: bytearray
    characteristics: int
    virt_addr: int = 0
    virt_size: int = 0
    raw_addr: int = 0
    raw_size: int = 0


class PEBuilder:
    """Build a minimal PE32+ (Windows x64) executable image.

    This module intentionally keeps the PE writer small and self-contained. It is
    used by the MiniLang compiler to emit a runnable `.exe` with a handful of
    sections and (optionally) an import directory.

    Attributes are public for convenience; codegen is expected to set:
    - :attr:`entry_rva`   : RVA of the program entry point inside `.text`
    - :attr:`import_rva`  : RVA of the import directory (usually inside `.idata`)
    - :attr:`import_size` : size of the import directory data
    """

    def __init__(self) -> None:
        """Create a new builder with standard PE32+ defaults."""
        self.image_base = 0x140000000
        self.section_alignment = 0x1000
        self.file_alignment = 0x200
        self.sections: List[Section] = []
        self.entry_rva: int = 0
        self.import_rva: int = 0
        self.import_size: int = 0
        # PE Optional Header Subsystem:
        #   2 = IMAGE_SUBSYSTEM_WINDOWS_GUI
        #   3 = IMAGE_SUBSYSTEM_WINDOWS_CUI
        self.subsystem: int = 3

    def add_section(self, name: str, data: bytes, characteristics: int) -> Section:
        """Add a section to the image and return its :class:`Section` record.

        Args:
            name: Section name (max 8 ASCII chars, e.g. ".text").
            data: Raw section bytes.
            characteristics: PE section characteristics bitmask.
        """
        sec = Section(name=name, data=bytearray(data), characteristics=characteristics)
        self.sections.append(sec)
        return sec

    def layout(self) -> None:
        """Assign RVAs / file offsets for all sections and compute header sizes."""
        dos_stub = 0x80
        pe_sig = 4
        coff = 20
        opt = 0xF0
        shdr = 40 * len(self.sections)
        headers_size = align_up(dos_stub + pe_sig + coff + opt + shdr, self.file_alignment)

        rva = align_up(headers_size, self.section_alignment)
        raw = headers_size

        for s in self.sections:
            s.virt_addr = rva
            # Allow callers to override virt_size (e.g. .bss / uninitialized data).
            if not s.virt_size:
                s.virt_size = len(s.data)
            s.raw_addr = raw
            s.raw_size = align_up(len(s.data), self.file_alignment)

            rva = align_up(rva + s.virt_size, self.section_alignment)
            raw += s.raw_size

    def build(self) -> bytes:
        """Build and return the final PE image bytes (ready to write to disk)."""
        self.layout()

        size_of_image = 0
        for s in self.sections:
            size_of_image = max(size_of_image, align_up(s.virt_addr + s.virt_size, self.section_alignment))

        # DOS header
        dos = bytearray()
        dos += b"MZ"
        dos += b"\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00"
        dos += b"\xB8\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00"
        dos += b"\x00" * (0x3C - len(dos))
        dos += u32(0x80)  # e_lfanew
        dos += b"\x00" * (0x80 - len(dos))

        pe = bytearray()
        pe += b"PE\x00\x00"

        # COFF
        machine = 0x8664
        num_sections = len(self.sections)
        pe += struct.pack('<HHIIIHH', machine, num_sections, 0, 0, 0, 0xF0, 0x0022)

        # Optional header (PE32+)
        magic = 0x20B
        major_linker = 14
        minor_linker = 0

        # Optional header size fields are defined by section characteristics.
        IMAGE_SCN_CNT_CODE = 0x00000020
        IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
        IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080

        size_code = 0
        size_init_data = 0
        size_uninit_data = 0
        for s in self.sections:
            vs = align_up(s.virt_size, self.section_alignment)
            if s.characteristics & IMAGE_SCN_CNT_CODE:
                size_code += vs
            if s.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA:
                size_init_data += vs
            if s.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA:
                size_uninit_data += vs

        addr_entry = self.entry_rva
        base_of_code = next((s.virt_addr for s in self.sections if s.name == '.text'), 0)

        image_base = self.image_base
        section_align = self.section_alignment
        file_align = self.file_alignment

        size_headers = align_up(0x80 + 4 + 20 + 0xF0 + 40 * len(self.sections), self.file_alignment)

        subsystem = int(getattr(self, "subsystem", 3) or 3)
        # NX_COMPAT | TERMINAL_SERVER_AWARE ; ASLR OFF (no DYNAMIC_BASE)
        dll_chars = 0x0100 | 0x8000

        opt = bytearray()
        opt += struct.pack('<HBB', magic, major_linker, minor_linker)
        opt += u32(size_code)
        opt += u32(size_init_data)
        opt += u32(size_uninit_data)
        opt += u32(addr_entry)
        opt += u32(base_of_code)
        opt += u64(image_base)
        opt += u32(section_align)
        opt += u32(file_align)
        opt += struct.pack('<HHHHHH', 6, 0, 0, 0, 6, 0)
        opt += u32(0)
        opt += u32(size_of_image)
        opt += u32(size_headers)
        opt += u32(0)
        opt += struct.pack('<HH', subsystem, dll_chars)
        opt += u64(0x100000)
        opt += u64(0x1000)
        opt += u64(0x100000)
        opt += u64(0x1000)
        opt += u32(0)
        opt += u32(16)

        # Data directories
        dirs = [(0, 0)] * 16
        dirs[1] = (self.import_rva, self.import_size)
        for rva, sz in dirs:
            opt += u32(rva)
            opt += u32(sz)

        if len(opt) != 0xF0:
            raise RuntimeError(f"Optional header size mismatch: {len(opt)}")

        # Section headers
        sh = bytearray()
        for s in self.sections:
            nm = s.name.encode('ascii')
            nm = nm + b"\x00" * (8 - len(nm))
            sh += nm
            sh += u32(s.virt_size)
            sh += u32(s.virt_addr)
            sh += u32(s.raw_size)
            sh += u32(s.raw_addr)
            sh += u32(0)
            sh += u32(0)
            sh += u16(0)
            sh += u16(0)
            sh += u32(s.characteristics)

        image = bytearray()
        image += dos
        image += pe
        image += opt
        image += sh
        image = image.ljust(size_headers, b"\x00")

        for s in self.sections:
            blob = bytes(s.data).ljust(s.raw_size, b"\x00")
            if len(image) < s.raw_addr:
                image = image.ljust(s.raw_addr, b"\x00")
            if len(image) == s.raw_addr:
                image += blob
            else:
                image[s.raw_addr:s.raw_addr + len(blob)] = blob

        return bytes(image)


# ============================================================
# Import builder (.idata)
# ============================================================

KERNEL32 = 'kernel32.dll'
MSVCRT = 'msvcrt.dll'


def build_idata(imports: Dict[str, List[str]], base_rva: int) -> Tuple[bytes, int, int, Dict[Tuple[str, str], int]]:
    """Build a minimal `.idata` import section.

    The result contains:
    - Import directory table (IMAGE_IMPORT_DESCRIPTOR + null terminator)
    - Import Lookup Tables (ILT)
    - Import Address Tables (IAT)
    - DLL name strings
    - Hint/Name entries for imported functions

    Args:
        imports: Mapping of DLL name -> list of imported function names.
        base_rva: RVA where the `.idata` section will be placed in the image.

    Returns:
        A tuple ``(idata_bytes, import_dir_rva, idata_total_size, iat_symbol_rva)`` where:
        - ``idata_bytes``: complete `.idata` blob
        - ``import_dir_rva``: RVA of the import directory table
        - ``idata_total_size``: total blob size in bytes
        - ``iat_symbol_rva``: mapping ``(dll, func) -> RVA`` of the function's IAT slot
    """
    dlls = list(imports.keys())
    buf = bytearray()

    desc_count = len(dlls)
    desc_off = 0
    buf += b"\x00" * (20 * (desc_count + 1))

    def cur_rva() -> int:
        return base_rva + len(buf)

    ilt_rva: Dict[str, int] = {}
    iat_rva: Dict[str, int] = {}
    dll_name_rva: Dict[str, int] = {}
    hn_rva: Dict[Tuple[str, str], int] = {}
    iat_symbol_rva: Dict[Tuple[str, str], int] = {}

    # ILT
    for dll in dlls:
        ilt_rva[dll] = cur_rva()
        funcs = imports[dll]
        buf += b"\x00" * (8 * (len(funcs) + 1))

    # IAT
    for dll in dlls:
        iat_rva[dll] = cur_rva()
        funcs = imports[dll]
        base_iat = cur_rva()
        for i, f in enumerate(funcs):
            iat_symbol_rva[(dll, f)] = base_iat + i * 8
        buf += b"\x00" * (8 * (len(funcs) + 1))

    # DLL names
    for dll in dlls:
        dll_name_rva[dll] = cur_rva()
        buf += dll.encode('ascii') + b"\x00"

    # Hint/Name
    for dll in dlls:
        for f in imports[dll]:
            hn_rva[(dll, f)] = cur_rva()
            buf += u16(0) + f.encode('ascii') + b"\x00"
            if len(buf) % 2:
                buf += b"\x00"

    # Patch ILT/IAT entries
    for dll in dlls:
        funcs = imports[dll]
        ilt_start = ilt_rva[dll] - base_rva
        iat_start = iat_rva[dll] - base_rva
        for i, f in enumerate(funcs):
            entry = hn_rva[(dll, f)]
            buf[ilt_start + i * 8: ilt_start + i * 8 + 8] = u64(entry)
            buf[iat_start + i * 8: iat_start + i * 8 + 8] = u64(entry)

    # Import descriptors
    for idx, dll in enumerate(dlls):
        d_off = desc_off + idx * 20
        orig_first_thunk = ilt_rva[dll]
        name_rva = dll_name_rva[dll]
        first_thunk = iat_rva[dll]
        buf[d_off:d_off + 20] = struct.pack('<IIIII', orig_first_thunk, 0, 0, name_rva, first_thunk)

    import_dir_rva = base_rva + desc_off
    # import_dir_size = 20 * (desc_count + 1)

    return bytes(buf), import_dir_rva, len(buf), iat_symbol_rva
