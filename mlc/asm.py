"""
x86-64 machine-code emitter for MiniLang (Windows ABI).

Design goals
- Keep codegen modules free of raw opcode bytes: everything should be expressed
  via Asm methods.
- Provide a *small* generic encoder layer (regs + [base+disp] + SIB addressing)
  so new combinations do not require ad-hoc byte blobs.
- Preserve existing, already-used helper method names for backwards
  compatibility with the current code generator.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .tools import u32, u64


@dataclass(frozen=True)
class GPR:
    """A parsed general-purpose register."""
    id: int  # 0..15 (rax..r15)
    size: int  # 8 / 32 / 64
    force_rex: bool  # needed for spl/bpl/sil/dil


@dataclass(frozen=True)
class TraceEntry:
    """One emitted instruction/span for the optional .asm listing."""
    start: int
    end: int
    text: str
    refs: Tuple[str, ...] = ()


class Asm:
    def __init__(self):
        """Internal encoder/helper used by instruction emitters.
        """
        self.buf = bytearray()
        self.labels: Dict[str, int] = {}
        # patches: (pos_of_disp32, label, kind)
        # kind: 'rel32' (jump/call), 'rip32' (rip-relative address disp32)
        self.patches: List[Tuple[int, str, str]] = []

        # optional listing / trace (for debugging)
        self._listing_path: Optional[str] = None
        self._trace: List[TraceEntry] = []
        self._label_defs: List[Tuple[int, str]] = []
        self._trace_enabled: bool = False
        self._listing_show_addr: bool = True
        self._listing_show_bytes: bool = True
        self._listing_show_text: bool = True

        # -------------------------------------------------------------
        # Peephole optimizer (Step 3)
        # -------------------------------------------------------------
        # Keep this conservative and local (no IR, no cross-label rewrites):
        # - remove self-moves
        # - remove stack adjustments by 0
        # - cancel adjacent push/pop of the same register
        # - cmp reg,0  -> test reg,reg (safe for zero checks)
        self._peephole_enabled: bool = True
        self._peephole_last_push: tuple[bytes, str] | None = None  # (push_bytes, reg)

    # -----------------------------------------------------------------
    # peephole helpers
    # -----------------------------------------------------------------
    def _peephole_trim_tail(self, n: int) -> None:
        """Trim the last `n` bytes from the code buffer (peephole only)."""
        if n <= 0 or n > len(self.buf):
            return
        del self.buf[-n:]

        # If tracing is enabled, also drop a matching trailing trace entry.
        if getattr(self, '_trace_enabled', False):
            try:
                te = self._trace[-1]
                if te.end == (len(self.buf) + n) and te.start == len(self.buf):
                    self._trace.pop()
            except Exception:
                pass

    # -----------------------------------------------------------------
    # optional listing / tracing
    # -----------------------------------------------------------------
    def enable_listing(self, path: str, *, show_addr: bool = True, show_bytes: bool = True,
                       show_text: bool = True, ) -> None:
        """Enable generation of a textual .asm listing into `path`.

        Column toggles:
        - show_addr  : address column
        - show_bytes : opcode bytes column
        - show_text  : pseudo-assembly column
        """
        self._listing_path = path
        self._listing_show_addr = bool(show_addr)
        self._listing_show_bytes = bool(show_bytes)
        self._listing_show_text = bool(show_text)
        self._trace_enabled = True

    def disable_listing(self) -> None:
        """Disable the optional instruction listing/tracing.
        """
        self._trace_enabled = False

    def __getattribute__(self, name: str):
        """Internal encoder/helper used by instruction emitters.

        Args:
            name: Label name.
        """
        # Wrap public instruction helpers so we can reconstruct a readable
        # listing (addr + bytes + pseudo-asm) for debugging.
        attr = object.__getattribute__(self, name)

        # Fast path: no tracing
        try:
            enabled = object.__getattribute__(self, '_trace_enabled')
        except Exception:
            enabled = False
        if not enabled:
            return attr

        # Never wrap internals / low level emitters / listing helpers
        if name.startswith('_') or name in ('emit', 'emit8', 'emit32', 'emit64', 'pos', 'labels', 'patches', 'buf',
                                            'mark', 'finalize', 'enable_listing', 'disable_listing', 'write_listing',):
            return attr

        if not callable(attr):
            return attr

        def wrapped(*args, **kwargs):
            trace = object.__getattribute__(self, '_trace')
            before_n = len(trace)
            start = object.__getattribute__(self, 'pos')
            res = attr(*args, **kwargs)
            end = object.__getattribute__(self, 'pos')

            # Skip outer wrappers when nested calls already produced entries.
            if end > start and len(trace) == before_n:
                fmt = object.__getattribute__(self, '_format_call')
                text, refs = fmt(name, args, kwargs)
                trace.append(TraceEntry(start, end, text, refs))
            return res

        return wrapped

    # ---------------------------------------------------------------------
    # basic output
    # ---------------------------------------------------------------------

    @property
    def pos(self) -> int:
        """Emit instruction/utility helper.
        """
        return len(self.buf)

    def emit(self, b: bytes) -> None:
        """Append raw bytes to the output buffer.

        Args:
            b: Parameter.
        """
        self.buf += b

    def emit8(self, x: int) -> None:
        """Append a single byte to the output buffer.

        Args:
            x: Parameter.
        """
        self.buf.append(x & 0xFF)

    def emit32(self, x: int) -> None:
        """Append a 32-bit little-endian integer to the output buffer.

        Args:
            x: Parameter.
        """
        self.buf += u32(x)

    def emit64(self, x: int) -> None:
        """Append a 64-bit little-endian integer to the output buffer.

        Args:
            x: Parameter.
        """
        self.buf += u64(x)

    # ---------------------------------------------------------------------
    # labels / patching
    # ---------------------------------------------------------------------

    def mark(self, name: str) -> None:
        """Define a label at the current code position.

        Args:
            name: Label name.
        """
        if name in self.labels:
            raise ValueError(f"Label already defined: {name}")
        self._label_defs.append((self.pos, name))
        self.labels[name] = self.pos

    def finalize(self) -> bytes:
        """Patch all pending rel32 / rip32 fixups and return machine code."""
        for p, label, _kind in self.patches:
            if label not in self.labels:
                raise ValueError(f"Unknown label referenced in patch: {label}")
            target = self.labels[label]
            # rel32/rip32 use displacement from *next* instruction
            disp = target - (p + 4)
            self.buf[p:p + 4] = u32(disp)
        return bytes(self.buf)

    # ---------------------------------------------------------------------
    # register tables
    # ---------------------------------------------------------------------

    # Base register ids (same for 8/32/64 forms)
    _RID: Dict[str, int] = {"rax": 0, "rcx": 1, "rdx": 2, "rbx": 3, "rsp": 4, "rbp": 5, "rsi": 6, "rdi": 7, "r8": 8,
                            "r9": 9, "r10": 10, "r11": 11, "r12": 12, "r13": 13, "r14": 14, "r15": 15, }

    # Explicit 32-bit names (for readability in codegen)
    _R32: Dict[str, int] = {"eax": 0, "ecx": 1, "edx": 2, "ebx": 3, "esp": 4, "ebp": 5, "esi": 6, "edi": 7, "r8d": 8,
                            "r9d": 9, "r10d": 10, "r11d": 11, "r12d": 12, "r13d": 13, "r14d": 14, "r15d": 15, }

    # 8-bit names (only low-byte regs; no AH/BH/CH/DH in x86-64 with REX)
    _R8: Dict[str, int] = {"al": 0, "cl": 1, "dl": 2, "bl": 3, "spl": 4, "bpl": 5, "sil": 6, "dil": 7, "r8b": 8,
                           "r9b": 9, "r10b": 10, "r11b": 11, "r12b": 12, "r13b": 13, "r14b": 14, "r15b": 15, }

    XMM: Dict[str, int] = {f"xmm{i}": i for i in range(16)}
    YMM: Dict[str, int] = {f"ymm{i}": i for i in range(16)}

    @classmethod
    def gpr(cls, name: str) -> GPR:
        """Parse a GPR name into (id,size). Supports rax/eax/al, r8/r8d/r8b, etc."""
        if name in cls._R8:
            rid = cls._R8[name]
            # spl/bpl/sil/dil require a REX prefix even though rid<8
            force = name in ("spl", "bpl", "sil", "dil")
            return GPR(rid, 8, force)
        if name in cls._R32:
            return GPR(cls._R32[name], 32, False)
        if name in cls._RID:
            return GPR(cls._RID[name], 64, False)
        raise ValueError(f"Unknown register: {name}")

    @classmethod
    def _rid_any(cls, name: str) -> int:
        """Get base register id (0..15) for any 8/32/64 spelling."""
        if name in cls._RID:
            return cls._RID[name]
        if name in cls._R32:
            return cls._R32[name]
        if name in cls._R8:
            return cls._R8[name]
        raise ValueError(f"Unknown register: {name}")

    # ---------------------------------------------------------------------
    # low-level encoding helpers
    # ---------------------------------------------------------------------

    @staticmethod
    def _rex(w: int = 0, r: int = 0, x: int = 0, b: int = 0, *, force: bool = False) -> bytes:
        """
        Build a REX prefix.

        In x86-64, spl/bpl/sil/dil and r8b..r15b require a REX prefix; for
        spl/bpl/sil/dil the prefix must be present even if all REX bits are 0.
        """
        if (w | r | x | b) == 0 and not force:
            return b""
        return bytes([0x40 | ((w & 1) << 3) | ((r & 1) << 2) | ((x & 1) << 1) | (b & 1)])

    @staticmethod
    def _vex3(*, m: int = 1, w: int = 0, vvvv: Optional[int] = None, l: int = 0, pp: int = 0, r: int = 0, x: int = 0,
              b: int = 0) -> bytes:
        """Build a 3-byte VEX prefix.

        Args:
            m: Opcode-map selector (1 => 0F).
            w: W bit.
            vvvv: Source register encoded in VEX.vvvv (non-inverted value 0..15, None if unused).
            l: Vector length bit (0 => 128, 1 => 256).
            pp: Implied legacy prefix bits (0 none, 1 66, 2 F3, 3 F2).
            r: High bit of ModRM.reg.
            x: High bit of SIB.index.
            b: High bit of ModRM.rm/base.
        """
        b1 = ((0 if r else 1) << 7) | ((0 if x else 1) << 6) | ((0 if b else 1) << 5) | (m & 0x1F)
        if vvvv is None:
            v_field = 0xF
        else:
            v_field = 0xF ^ (vvvv & 0xF)
        b2 = ((w & 1) << 7) | (v_field << 3) | ((l & 1) << 2) | (pp & 0x3)
        return b"\xC4" + bytes([b1, b2])

    @staticmethod
    def _modrm(mod: int, reg: int, rm: int) -> bytes:
        """Build a ModRM byte.

        Args:
            mod: Parameter.
            reg: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            rm: Parameter.
        """
        return bytes([((mod & 3) << 6) | ((reg & 7) << 3) | (rm & 7)])

    @staticmethod
    def _sib(scale: int, index: int, base: int) -> bytes:
        """Build a SIB byte.

        Args:
            scale: Index scale factor (1, 2, 4, or 8).
            index: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            base: Register name (e.g. 'rax', 'r10', 'eax', 'al').
        """
        return bytes([((scale & 3) << 6) | ((index & 7) << 3) | (base & 7)])

    @staticmethod
    def _fits_i8(x: int) -> bool:
        """Return True if a value fits in signed 8-bit immediate form.

        Args:
            x: Parameter.
        """
        return -128 <= x <= 127

    @staticmethod
    def _scale_bits(scale: int) -> int:
        """Internal encoder/helper used by instruction emitters.

        Args:
            scale: Index scale factor (1, 2, 4, or 8).
        """
        m = {1: 0, 2: 1, 4: 2, 8: 3}
        if scale not in m:
            raise ValueError(f"Invalid SIB scale: {scale} (must be 1,2,4,8)")
        return m[scale]

    def _encode_mem(self, reg_field: int, base_id: int, disp: int = 0, *, index_id: Optional[int] = None,
                    scale: int = 1, ) -> Tuple[int, int, bytes]:
        """
        Encode [base + index*scale + disp] as ModRM(+SIB)+disp.

        Returns (rex_x, rex_b, tail_bytes), where tail_bytes starts with ModRM.
        rex_r depends only on reg_field and is handled by the caller.
        """
        base_lo = base_id & 7
        rex_b = 1 if base_id >= 8 else 0

        use_sib = (index_id is not None) or (base_lo == 4)  # rsp/r12 need SIB
        rex_x = 0
        sib = b""

        if use_sib:
            if index_id is None:
                idx_lo = 4  # no index
            else:
                if (index_id & 7) == 4:
                    raise ValueError("SIB index cannot be rsp/r12")
                idx_lo = index_id & 7
                rex_x = 1 if index_id >= 8 else 0

            sib = self._sib(self._scale_bits(scale), idx_lo, base_lo)
            rm_lo = 4  # SIB
        else:
            rm_lo = base_lo

        # Choose displacement width
        if disp == 0 and rm_lo != 5 and base_lo != 5:
            mod = 0
            disp_bytes = b""
        elif self._fits_i8(disp):
            mod = 1
            disp_bytes = bytes([disp & 0xFF])
        else:
            mod = 2
            disp_bytes = u32(disp)

        # base rbp/r13 with disp==0 can't use mod=0
        if disp == 0 and base_lo == 5:
            mod = 1
            disp_bytes = b"\x00"

        modrm = self._modrm(mod, reg_field, rm_lo)
        return rex_x, rex_b, modrm + sib + disp_bytes

    # ---------------------------------------------------------------------
    # misc
    # ---------------------------------------------------------------------

    def nop(self) -> None:
        """Emit instruction/utility helper.
        """
        self.emit(b"\x90")

    # ---------------------------------------------------------------------
    # control flow (rel32)
    # ---------------------------------------------------------------------

    def jmp(self, label: str) -> None:
        """Emit `JMP` instruction.

        Args:
            label: Label name.
        """
        self.emit(b"\xE9")
        p = self.pos
        self.emit32(0)
        self.patches.append((p, label, "rel32"))

    def jcc(self, cc: str, label: str) -> None:
        """Emit instruction/utility helper.

        Args:
            cc: Parameter.
            label: Label name.
        """
        cc_map = {"e": 0x84, "ne": 0x85, "l": 0x8C, "le": 0x8E, "g": 0x8F, "ge": 0x8D, "z": 0x84, "nz": 0x85,
                  # unsigned
                  "b": 0x82, "be": 0x86, "a": 0x87, "ae": 0x83,  # sign flag
                  "s": 0x88, "ns": 0x89,  # parity flag (unordered after ucomisd)
                  "p": 0x8A, "np": 0x8B,  # overflow
                  "o": 0x80, "no": 0x81, }
        if cc not in cc_map:
            raise ValueError(f"Unknown jcc: {cc}")
        self.emit(b"\x0F" + bytes([cc_map[cc]]))
        p = self.pos
        self.emit32(0)
        self.patches.append((p, label, "rel32"))

    # Convenience conditional jump wrappers (Windows-style mnemonics)
    def je(self, label: str) -> None:
        """Emit `JE` conditional jump.

        Args:
            label: Label name.
        """
        self.jcc("e", label)

    def jz(self, label: str) -> None:
        """Emit instruction/utility helper.

        Args:
            label: Label name.
        """
        self.jcc("z", label)

    def jne(self, label: str) -> None:
        """Emit `JNE` conditional jump.

        Args:
            label: Label name.
        """
        self.jcc("ne", label)

    def jnz(self, label: str) -> None:
        """Emit instruction/utility helper.

        Args:
            label: Label name.
        """
        self.jcc("nz", label)

    def jl(self, label: str) -> None:
        """Emit `JL` conditional jump.

        Args:
            label: Label name.
        """
        self.jcc("l", label)

    def jle(self, label: str) -> None:
        """Emit `JLE` conditional jump.

        Args:
            label: Label name.
        """
        self.jcc("le", label)

    def jg(self, label: str) -> None:
        """Emit `JG` conditional jump.

        Args:
            label: Label name.
        """
        self.jcc("g", label)

    def jge(self, label: str) -> None:
        """Emit `JGE` conditional jump.

        Args:
            label: Label name.
        """
        self.jcc("ge", label)

    # unsigned comparisons
    def jb(self, label: str) -> None:
        """Emit `JB` conditional jump.

        Args:
            label: Label name.
        """
        self.jcc("b", label)  # <  (CF=1)

    def jbe(self, label: str) -> None:
        """Emit `JBE` conditional jump.

        Args:
            label: Label name.
        """
        self.jcc("be", label)  # <=

    def ja(self, label: str) -> None:
        """Emit `JA` conditional jump.

        Args:
            label: Label name.
        """
        self.jcc("a", label)  # >

    def jae(self, label: str) -> None:
        """Emit `JAE` conditional jump.

        Args:
            label: Label name.
        """
        self.jcc("ae", label)  # >=

    def call(self, label: str) -> None:
        """Emit `CALL` instruction.

        Args:
            label: Label name.
        """
        # Optional hook used by CodegenCore to track which internal helpers are called
        cb = getattr(self, '_on_call_label', None)
        if cb is not None:
            try:
                cb(label)
            except Exception:
                pass
        self.emit(b"\xE8")
        p = self.pos
        self.emit32(0)
        self.patches.append((p, label, "rel32"))

    def call_rax(self) -> None:
        """Emit `CALL` instruction.
        """
        self.emit(b"\xFF\xD0")

    def call_membase_disp(self, base: str, disp: int = 0) -> None:
        """Emit `call qword [base+disp]`."""
        b = self.gpr(base)
        rex_x, rex_b, tail = self._encode_mem(2, b.id, int(disp))
        self.emit(self._rex(x=rex_x, b=rex_b) + b"\xFF" + tail)

    def call_rip_qword(self, label: str) -> None:
        """Emit `call qword [rip+label]`."""
        self.emit(b"\xFF\x15")
        p = self.pos
        self.emit32(0)
        self.patches.append((p, label, "rip32"))

    def ret(self) -> None:
        """Emit `RET` instruction.
        """
        self.emit(b"\xC3")

    def leave(self) -> None:
        """Emit instruction/utility helper.
        """
        self.emit(b"\xC9")

    # ---------------------------------------------------------------------
    # RIP-relative loads/stores/LEA (disp32 patched)
    # ---------------------------------------------------------------------

    def mov_eax_rip_dword(self, label: str) -> None:
        """Emit `MOV` instruction helper.

        Args:
            label: Label name.
        """
        # mov eax, [rip+disp32]
        self.emit(b"\x8B\x05")
        p = self.pos
        self.emit32(0)
        self.patches.append((p, label, "rip32"))

    def mov_rip_dword_eax(self, label: str) -> None:
        """Emit `MOV` instruction helper.

        Args:
            label: Label name.
        """
        # mov [rip+disp32], eax
        self.emit(b"\x89\x05")
        p = self.pos
        self.emit32(0)
        self.patches.append((p, label, "rip32"))

    def mov_rax_rip_qword(self, label: str) -> None:
        """Emit `MOV` instruction helper.

        Args:
            label: Label name.
        """
        # mov rax, [rip+disp32]
        self.emit(b"\x48\x8B\x05")
        p = self.pos
        self.emit32(0)
        self.patches.append((p, label, "rip32"))

    def mov_rdx_rip_qword(self, label: str) -> None:
        """Emit `MOV` instruction helper.

        Args:
            label: Label name.
        """
        # mov rdx, [rip+disp32]
        # encoding: 48 8B 15 <disp32>
        self.emit(b"\x48\x8B\x15")
        p = self.pos
        self.emit32(0)
        self.patches.append((p, label, "rip32"))

    def mov_rip_qword_rax(self, label: str) -> None:
        """Emit `MOV` instruction helper.

        Args:
            label: Label name.
        """
        # mov [rip+disp32], rax
        self.emit(b"\x48\x89\x05")
        p = self.pos
        self.emit32(0)
        self.patches.append((p, label, "rip32"))

    def mov_rip_qword_rdx(self, label: str) -> None:
        """Emit `MOV` instruction helper.

        Args:
            label: Label name.
        """
        # mov [rip+disp32], rdx
        self.emit(b"\x48\x89\x15")
        p = self.pos
        self.emit32(0)
        self.patches.append((p, label, "rip32"))

    def mov_rip_qword_r11(self, label: str) -> None:
        """Emit `MOV` instruction helper.

        Args:
            label: Label name.
        """
        # mov [rip+disp32], r11
        self.emit(b"\x4C\x89\x1D")
        p = self.pos
        self.emit32(0)
        self.patches.append((p, label, "rip32"))

    def lea_rdx_rip(self, label: str) -> None:
        """Emit `LEA` instruction helper.

        Args:
            label: Label name.
        """
        self.emit(b"\x48\x8D\x15")
        p = self.pos
        self.emit32(0)
        self.patches.append((p, label, "rip32"))

    def lea_rax_rip(self, label: str) -> None:
        """Emit `LEA` instruction helper.

        Args:
            label: Label name.
        """
        self.emit(b"\x48\x8D\x05")
        p = self.pos
        self.emit32(0)
        self.patches.append((p, label, "rip32"))

    def lea_r9_rip(self, label: str) -> None:
        """Emit `LEA` instruction helper.

        Args:
            label: Label name.
        """
        self.emit(b"\x4C\x8D\x0D")
        p = self.pos
        self.emit32(0)
        self.patches.append((p, label, "rip32"))

    def lea_r8_rip(self, label: str) -> None:
        """Emit `LEA` instruction helper.

        Args:
            label: Label name.
        """
        self.emit(b"\x4C\x8D\x05")
        p = self.pos
        self.emit32(0)
        self.patches.append((p, label, "rip32"))

    def lea_r11_rip(self, label: str) -> None:
        """Emit `LEA` instruction helper.

        Args:
            label: Label name.
        """
        self.emit(b"\x4C\x8D\x1D")
        p = self.pos
        self.emit32(0)
        self.patches.append((p, label, "rip32"))

    # ---------------------------------------------------------------------
    # stack / prologue helpers (used heavily by current backend)
    # ---------------------------------------------------------------------

    def sub_rsp_imm8(self, imm: int) -> None:
        """Emit `SUB` instruction helper.

        Args:
            imm: Immediate integer value.
        """
        if getattr(self, '_peephole_enabled', False) and int(imm) == 0:
            return
        self.sub_r64_imm("rsp", imm)

    def add_rsp_imm8(self, imm: int) -> None:
        """Emit `ADD` instruction helper.

        Args:
            imm: Immediate integer value.
        """
        if getattr(self, '_peephole_enabled', False) and int(imm) == 0:
            return
        self.add_r64_imm("rsp", imm)

    def sub_rsp_imm32(self, imm: int) -> None:
        """Emit `SUB` instruction helper.

        Args:
            imm: Immediate integer value.
        """
        if getattr(self, '_peephole_enabled', False) and int(imm) == 0:
            return
        self.sub_r64_imm("rsp", imm)

    def add_rsp_imm32(self, imm: int) -> None:
        """Emit `ADD` instruction helper.

        Args:
            imm: Immediate integer value.
        """
        if getattr(self, '_peephole_enabled', False) and int(imm) == 0:
            return
        self.add_r64_imm("rsp", imm)

    def mov_rax_rsp_disp8(self, disp: int) -> None:
        """Emit `MOV` instruction helper.

        Args:
            disp: Displacement/offset in bytes.
        """
        self.mov_r64_membase_disp("rax", "rsp", disp)

    def mov_rsp_disp8_rax(self, disp: int) -> None:
        """Emit `MOV` instruction helper.

        Args:
            disp: Displacement/offset in bytes.
        """
        self.mov_membase_disp_r64("rsp", disp, "rax")

    def mov_rax_rsp_disp32(self, disp: int) -> None:
        """Emit `MOV` instruction helper.

        Args:
            disp: Displacement/offset in bytes.
        """
        self.mov_r64_membase_disp("rax", "rsp", disp)

    def mov_rsp_disp32_rax(self, disp: int) -> None:
        """Emit `MOV` instruction helper.

        Args:
            disp: Displacement/offset in bytes.
        """
        self.mov_membase_disp_r64("rsp", disp, "rax")

    def push_reg(self, reg: str) -> None:
        """Emit `PUSH` instruction.

        Args:
            reg: Register name (e.g. 'rax', 'r10', 'eax', 'al').
        """
        r = self._rid_any(reg)
        rex_b = 1 if r >= 8 else 0
        b = self._rex(b=rex_b) + bytes([0x50 + (r & 7)])
        self.emit(b)

        if getattr(self, '_peephole_enabled', False):
            # Remember the raw bytes so pop_reg can cancel an adjacent push/pop.
            self._peephole_last_push = (b, str(reg))

    def pop_reg(self, reg: str) -> None:
        """Emit `POP` instruction.

        Args:
            reg: Register name (e.g. 'rax', 'r10', 'eax', 'al').
        """
        if getattr(self, '_peephole_enabled', False):
            last = getattr(self, '_peephole_last_push', None)
            if last is not None:
                push_b, push_reg = last
                # Cancel adjacent `push reg; pop reg`.
                if push_reg == str(reg) and len(self.buf) >= len(push_b) and self.buf[-len(push_b):] == push_b:
                    self._peephole_trim_tail(len(push_b))
                    self._peephole_last_push = None
                    return

        r = self._rid_any(reg)
        rex_b = 1 if r >= 8 else 0
        self.emit(self._rex(b=rex_b) + bytes([0x58 + (r & 7)]))

        # A pop breaks the adjacent-push opportunity.
        if getattr(self, '_peephole_enabled', False):
            self._peephole_last_push = None

    # convenience push/pop used in older codegen
    def push_rbx(self) -> None:
        """Emit `PUSH` instruction.
        """
        self.push_reg("rbx")

    def pop_rbx(self) -> None:
        """Emit `POP` instruction.
        """
        self.pop_reg("rbx")

    def push_r12(self) -> None:
        """Emit `PUSH` instruction.
        """
        self.push_reg("r12")

    def pop_r12(self) -> None:
        """Emit `POP` instruction.
        """
        self.pop_reg("r12")

    def push_r13(self) -> None:
        """Emit `PUSH` instruction.
        """
        self.push_reg("r13")

    def pop_r13(self) -> None:
        """Emit `POP` instruction.
        """
        self.pop_reg("r13")

    def push_r14(self) -> None:
        """Emit `PUSH` instruction.
        """
        self.push_reg("r14")

    def pop_r14(self) -> None:
        """Emit `POP` instruction.
        """
        self.pop_reg("r14")

    def push_r15(self) -> None:
        """Emit `PUSH` instruction.
        """
        self.push_reg("r15")

    def pop_r15(self) -> None:
        """Emit `POP` instruction.
        """
        self.pop_reg("r15")

    def push_rbp(self) -> None:
        """Emit `PUSH` instruction.
        """
        self.push_reg("rbp")

    def pop_rbp(self) -> None:
        """Emit `POP` instruction.
        """
        self.pop_reg("rbp")

    def mov_rbp_rsp(self) -> None:
        """Emit `MOV` instruction helper.
        """
        self.mov_r64_r64("rbp", "rsp")

    # ---------------------------------------------------------------------
    # Generic MOV/LEA (regs + [base+disp] + [base+index*scale+disp])
    # ---------------------------------------------------------------------

    def mov_r64_imm64(self, dst: str, imm: int) -> None:
        """Emit `MOV` instruction helper.

        Args:
            dst: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            imm: Immediate integer value.
        """
        r = self._rid_any(dst)
        rex_b = 1 if r >= 8 else 0
        imm_u = int(imm) & 0xFFFFFFFFFFFFFFFF

        # Prefer shorter encodings when they preserve the final 64-bit value.
        if imm_u <= 0xFFFFFFFF:
            self.emit(self._rex(w=0, b=rex_b) + bytes([0xB8 + (r & 7)]) + u32(imm_u))
            return
        if imm_u >= 0xFFFFFFFF80000000:
            self.emit(self._rex(w=1, b=rex_b) + b"\xC7" + self._modrm(3, 0, r) + u32(imm_u))
            return

        self.emit(self._rex(w=1, b=rex_b) + bytes([0xB8 + (r & 7)]) + u64(imm_u))

    def mov_r32_imm32(self, dst: str, imm: int) -> None:
        """Emit `MOV` instruction helper.

        Args:
            dst: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            imm: Immediate integer value.
        """
        r = self._rid_any(dst)
        rex_b = 1 if r >= 8 else 0
        self.emit(self._rex(w=0, b=rex_b) + bytes([0xB8 + (r & 7)]) + u32(imm))

    def mov_r64_r64(self, dst: str, src: str) -> None:
        """Emit `MOV` instruction helper.

        Args:
            dst: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            src: Register name (e.g. 'rax', 'r10', 'eax', 'al').
        """
        if getattr(self, '_peephole_enabled', False) and str(dst) == str(src):
            return
        d = self._rid_any(dst)
        s = self._rid_any(src)
        rex_r = 1 if d >= 8 else 0
        rex_b = 1 if s >= 8 else 0
        self.emit(self._rex(w=1, r=rex_r, b=rex_b) + b"\x8B" + self._modrm(3, d, s))

    def mov_r32_r32(self, dst: str, src: str) -> None:
        """Emit `MOV` instruction helper.

        Args:
            dst: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            src: Register name (e.g. 'rax', 'r10', 'eax', 'al').
        """
        if getattr(self, '_peephole_enabled', False) and str(dst) == str(src):
            return
        d = self._rid_any(dst)
        s = self._rid_any(src)
        rex_r = 1 if d >= 8 else 0
        rex_b = 1 if s >= 8 else 0
        self.emit(self._rex(w=0, r=rex_r, b=rex_b) + b"\x8B" + self._modrm(3, d, s))

    def mov_r8_r8(self, dst: str, src: str) -> None:
        """Emit `MOV` instruction helper.

        Args:
            dst: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            src: Register name (e.g. 'rax', 'r10', 'eax', 'al').
        """
        if getattr(self, '_peephole_enabled', False) and str(dst) == str(src):
            return
        d = self.gpr(dst)
        s = self.gpr(src)
        if d.size != 8 or s.size != 8:
            raise ValueError("mov_r8_r8 requires 8-bit registers")
        rex_r = 1 if d.id >= 8 else 0
        rex_b = 1 if s.id >= 8 else 0
        force = d.force_rex or s.force_rex
        self.emit(self._rex(w=0, r=rex_r, b=rex_b, force=force) + b"\x8A" + self._modrm(3, d.id, s.id))

    def mov_r64_membase_disp(self, dst: str, base: str, disp: int = 0) -> None:
        """Emit `MOV` instruction helper.

        Args:
            dst: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            base: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            disp: Displacement/offset in bytes.
        """
        d = self._rid_any(dst)
        b = self._rid_any(base)
        rex_r = 1 if d >= 8 else 0
        rex_x, rex_b, tail = self._encode_mem(d, b, disp)
        self.emit(self._rex(w=1, r=rex_r, x=rex_x, b=rex_b) + b"\x8B" + tail)

    def mov_membase_disp_r64(self, base: str, disp: int, src: str) -> None:
        """Emit `MOV` instruction helper.

        Args:
            base: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            disp: Displacement/offset in bytes.
            src: Register name (e.g. 'rax', 'r10', 'eax', 'al').
        """
        s = self._rid_any(src)
        b = self._rid_any(base)
        rex_r = 1 if s >= 8 else 0
        rex_x, rex_b, tail = self._encode_mem(s, b, disp)
        self.emit(self._rex(w=1, r=rex_r, x=rex_x, b=rex_b) + b"\x89" + tail)

    def mov_r32_membase_disp(self, dst: str, base: str, disp: int = 0) -> None:
        """Emit `MOV` instruction helper.

        Args:
            dst: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            base: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            disp: Displacement/offset in bytes.
        """
        d = self._rid_any(dst)
        b = self._rid_any(base)
        rex_r = 1 if d >= 8 else 0
        rex_x, rex_b, tail = self._encode_mem(d, b, disp)
        self.emit(self._rex(w=0, r=rex_r, x=rex_x, b=rex_b) + b"\x8B" + tail)

    def mov_membase_disp_r32(self, base: str, disp: int, src: str) -> None:
        """Emit `MOV` instruction helper.

        Args:
            base: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            disp: Displacement/offset in bytes.
            src: Register name (e.g. 'rax', 'r10', 'eax', 'al').
        """
        s = self._rid_any(src)
        b = self._rid_any(base)
        rex_r = 1 if s >= 8 else 0
        rex_x, rex_b, tail = self._encode_mem(s, b, disp)
        self.emit(self._rex(w=0, r=rex_r, x=rex_x, b=rex_b) + b"\x89" + tail)

    def mov_r8_membase_disp(self, dst: str, base: str, disp: int = 0) -> None:
        """Emit `MOV` instruction helper.

        Args:
            dst: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            base: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            disp: Displacement/offset in bytes.
        """
        d = self.gpr(dst)
        if d.size != 8:
            raise ValueError("mov_r8_membase_disp requires an 8-bit dst register")
        b = self._rid_any(base)
        rex_r = 1 if d.id >= 8 else 0
        rex_x, rex_b, tail = self._encode_mem(d.id, b, disp)
        force = d.force_rex
        self.emit(self._rex(w=0, r=rex_r, x=rex_x, b=rex_b, force=force) + b"\x8A" + tail)

    def mov_membase_disp_r8(self, base: str, disp: int, src: str) -> None:
        """Emit `MOV` instruction helper.

        Args:
            base: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            disp: Displacement/offset in bytes.
            src: Register name (e.g. 'rax', 'r10', 'eax', 'al').
        """
        s = self.gpr(src)
        if s.size != 8:
            raise ValueError("mov_membase_disp_r8 requires an 8-bit src register")
        b = self._rid_any(base)
        rex_r = 1 if s.id >= 8 else 0
        rex_x, rex_b, tail = self._encode_mem(s.id, b, disp)
        force = s.force_rex
        self.emit(self._rex(w=0, r=rex_r, x=rex_x, b=rex_b, force=force) + b"\x88" + tail)

    def mov_membase_disp_imm32(self, base: str, disp: int, imm: int, *, qword: bool = False) -> None:
        """
        mov dword [base+disp], imm32
        mov qword [base+disp], imm32   (sign-extended) if qword=True
        """
        b = self._rid_any(base)
        rex_w = 1 if qword else 0
        rex_x, rex_b, tail = self._encode_mem(0, b, disp)  # /0
        self.emit(self._rex(w=rex_w, x=rex_x, b=rex_b) + b"\xC7" + tail + u32(imm))

    def mov_membase_disp_imm8(self, base: str, disp: int, imm: int) -> None:
        """Emit `MOV` instruction helper.

        Args:
            base: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            disp: Displacement/offset in bytes.
            imm: Immediate integer value.
        """
        # mov byte [base+disp], imm8
        b = self._rid_any(base)
        rex_x, rex_b, tail = self._encode_mem(0, b, disp)  # /0
        self.emit(self._rex(w=0, x=rex_x, b=rex_b) + b"\xC6" + tail + bytes([imm & 0xFF]))

    def mov_r64_mem_bis(self, dst: str, base: str, index: str, scale: int = 8, disp: int = 0) -> None:
        """Emit `MOV` instruction helper.

        Args:
            dst: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            base: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            index: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            scale: Index scale factor (1, 2, 4, or 8).
            disp: Displacement/offset in bytes.
        """
        d = self._rid_any(dst)
        b = self._rid_any(base)
        i = self._rid_any(index)
        rex_r = 1 if d >= 8 else 0
        rex_x, rex_b, tail = self._encode_mem(d, b, disp, index_id=i, scale=scale)
        self.emit(self._rex(w=1, r=rex_r, x=rex_x, b=rex_b) + b"\x8B" + tail)

    def mov_mem_bis_r64(self, base: str, index: str, scale: int, disp: int, src: str) -> None:
        """Emit `MOV` instruction helper.

        Args:
            base: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            index: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            scale: Index scale factor (1, 2, 4, or 8).
            disp: Displacement/offset in bytes.
            src: Register name (e.g. 'rax', 'r10', 'eax', 'al').
        """
        s = self._rid_any(src)
        b = self._rid_any(base)
        i = self._rid_any(index)
        rex_r = 1 if s >= 8 else 0
        rex_x, rex_b, tail = self._encode_mem(s, b, disp, index_id=i, scale=scale)
        self.emit(self._rex(w=1, r=rex_r, x=rex_x, b=rex_b) + b"\x89" + tail)

    def mov_r32_mem_bis(self, dst: str, base: str, index: str, scale: int = 8, disp: int = 0) -> None:
        """Emit `MOV` instruction helper.

        Args:
            dst: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            base: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            index: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            scale: Index scale factor (1, 2, 4, or 8).
            disp: Displacement/offset in bytes.
        """
        d = self._rid_any(dst)
        b = self._rid_any(base)
        i = self._rid_any(index)
        rex_r = 1 if d >= 8 else 0
        rex_x, rex_b, tail = self._encode_mem(d, b, disp, index_id=i, scale=scale)
        self.emit(self._rex(w=0, r=rex_r, x=rex_x, b=rex_b) + b"\x8B" + tail)

    def mov_mem_bis_r32(self, base: str, index: str, scale: int, disp: int, src: str) -> None:
        """Emit `MOV` instruction helper.

        Args:
            base: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            index: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            scale: Index scale factor (1, 2, 4, or 8).
            disp: Displacement/offset in bytes.
            src: Register name (e.g. 'rax', 'r10', 'eax', 'al').
        """
        s = self._rid_any(src)
        b = self._rid_any(base)
        i = self._rid_any(index)
        rex_r = 1 if s >= 8 else 0
        rex_x, rex_b, tail = self._encode_mem(s, b, disp, index_id=i, scale=scale)
        self.emit(self._rex(w=0, r=rex_r, x=rex_x, b=rex_b) + b"\x89" + tail)

    def lea_r64_membase_disp(self, dst: str, base: str, disp: int = 0) -> None:
        """Emit `LEA` instruction helper.

        Args:
            dst: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            base: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            disp: Displacement/offset in bytes.
        """
        d = self._rid_any(dst)
        b = self._rid_any(base)
        rex_r = 1 if d >= 8 else 0
        rex_x, rex_b, tail = self._encode_mem(d, b, disp)
        self.emit(self._rex(w=1, r=rex_r, x=rex_x, b=rex_b) + b"\x8D" + tail)

    def lea_r64_mem_bis(self, dst: str, base: str, index: str, scale: int = 8, disp: int = 0) -> None:
        """Emit `LEA` instruction helper.

        Args:
            dst: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            base: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            index: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            scale: Index scale factor (1, 2, 4, or 8).
            disp: Displacement/offset in bytes.
        """
        d = self._rid_any(dst)
        b = self._rid_any(base)
        i = self._rid_any(index)
        rex_r = 1 if d >= 8 else 0
        rex_x, rex_b, tail = self._encode_mem(d, b, disp, index_id=i, scale=scale)
        self.emit(self._rex(w=1, r=rex_r, x=rex_x, b=rex_b) + b"\x8D" + tail)

    # ---------------------------------------------------------------------
    # Generic arithmetic / logic (regs + imm, 8/32/64)
    # ---------------------------------------------------------------------

    def _grp1_imm(self, size: int, subop: int, rm: GPR, imm: int) -> None:
        """
        Group-1 immediate ops: 80/81/83 /subop
        subop: 0 add, 1 or, 4 and, 5 sub, 6 xor, 7 cmp
        """
        if size not in (8, 32, 64):
            raise ValueError("Unsupported operand size for grp1")
        if size == 8:
            opcode = b"\x80"
            imm_bytes = bytes([imm & 0xFF])
            w = 0
        else:
            if self._fits_i8(imm):
                opcode = b"\x83"
                imm_bytes = bytes([imm & 0xFF])
            else:
                opcode = b"\x81"
                imm_bytes = u32(imm)
            w = 1 if size == 64 else 0

        rex_r = 0  # reg field is subop (0..7)
        rex_b = 1 if rm.id >= 8 else 0
        force = rm.force_rex if size == 8 else False
        self.emit(self._rex(w=w, r=rex_r, b=rex_b, force=force) + opcode + self._modrm(3, subop, rm.id) + imm_bytes)

    def add_r64_imm(self, reg: str, imm: int) -> None:
        """Emit `ADD` instruction helper.

        Args:
            reg: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            imm: Immediate integer value.
        """
        self._grp1_imm(64, 0, self.gpr(reg if reg in self._RID else reg), imm)

    def sub_r64_imm(self, reg: str, imm: int) -> None:
        """Emit `SUB` instruction helper.

        Args:
            reg: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            imm: Immediate integer value.
        """
        self._grp1_imm(64, 5, self.gpr(reg if reg in self._RID else reg), imm)

    def and_r64_imm(self, reg: str, imm: int) -> None:
        """Emit `AND` instruction helper.

        Args:
            reg: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            imm: Immediate integer value.
        """
        self._grp1_imm(64, 4, self.gpr(reg if reg in self._RID else reg), imm)

    def or_r64_imm(self, reg: str, imm: int) -> None:
        """Emit `OR` instruction helper.

        Args:
            reg: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            imm: Immediate integer value.
        """
        self._grp1_imm(64, 1, self.gpr(reg if reg in self._RID else reg), imm)

    def xor_r64_imm(self, reg: str, imm: int) -> None:
        """Emit `XOR` instruction helper.

        Args:
            reg: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            imm: Immediate integer value.
        """
        self._grp1_imm(64, 6, self.gpr(reg if reg in self._RID else reg), imm)

    def cmp_r64_imm(self, reg: str, imm: int) -> None:
        """Emit `CMP` instruction helper.

        Args:
            reg: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            imm: Immediate integer value.
        """
        if getattr(self, '_peephole_enabled', False) and int(imm) == 0:
            self.test_r64_r64(reg, reg)
            return
        self._grp1_imm(64, 7, self.gpr(reg if reg in self._RID else reg), imm)

    # Backwards-compat alias (some codegen paths expect *_imm32 names)
    def cmp_r64_imm32(self, reg: str, imm: int) -> None:
        """Emit `CMP` instruction helper.

        Args:
            reg: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            imm: Immediate integer value.
        """
        self.cmp_r64_imm(reg, imm)

    # Convenience imm8 wrappers (force 83 encoding; fail if out of range)
    def add_r64_imm8(self, reg: str, imm: int) -> None:
        """Emit `ADD` instruction helper.

        Args:
            reg: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            imm: Immediate integer value.
        """
        if not self._fits_i8(imm): raise ValueError("imm8 out of range")
        self.add_r64_imm(reg, imm)

    def sub_r64_imm8(self, reg: str, imm: int) -> None:
        """Emit `SUB` instruction helper.

        Args:
            reg: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            imm: Immediate integer value.
        """
        if not self._fits_i8(imm): raise ValueError("imm8 out of range")
        self.sub_r64_imm(reg, imm)

    def and_r64_imm8(self, reg: str, imm: int) -> None:
        """Emit `AND` instruction helper.

        Args:
            reg: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            imm: Immediate integer value.
        """
        if not self._fits_i8(imm): raise ValueError("imm8 out of range")
        self.and_r64_imm(reg, imm)

    def or_r64_imm8(self, reg: str, imm: int) -> None:
        """Emit `OR` instruction helper.

        Args:
            reg: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            imm: Immediate integer value.
        """
        if not self._fits_i8(imm): raise ValueError("imm8 out of range")
        self.or_r64_imm(reg, imm)

    def xor_r64_imm8(self, reg: str, imm: int) -> None:
        """Emit `XOR` instruction helper.

        Args:
            reg: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            imm: Immediate integer value.
        """
        if not self._fits_i8(imm): raise ValueError("imm8 out of range")
        self.xor_r64_imm(reg, imm)

    def cmp_r64_imm8(self, reg: str, imm: int) -> None:
        """Emit `CMP` instruction helper.

        Args:
            reg: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            imm: Immediate integer value.
        """
        if not self._fits_i8(imm): raise ValueError("imm8 out of range")
        self.cmp_r64_imm(reg, imm)

    def add_r32_imm(self, reg: str, imm: int) -> None:
        """Emit `ADD` instruction helper.

        Args:
            reg: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            imm: Immediate integer value.
        """
        self._grp1_imm(32, 0, self.gpr(reg if reg in self._R32 else reg), imm)

    def sub_r32_imm(self, reg: str, imm: int) -> None:
        """Emit `SUB` instruction helper.

        Args:
            reg: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            imm: Immediate integer value.
        """
        self._grp1_imm(32, 5, self.gpr(reg if reg in self._R32 else reg), imm)

    def and_r32_imm(self, reg: str, imm: int) -> None:
        """Emit `AND` instruction helper.

        Args:
            reg: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            imm: Immediate integer value.
        """
        self._grp1_imm(32, 4, self.gpr(reg if reg in self._R32 else reg), imm)

    def or_r32_imm(self, reg: str, imm: int) -> None:
        """Emit `OR` instruction helper.

        Args:
            reg: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            imm: Immediate integer value.
        """
        self._grp1_imm(32, 1, self.gpr(reg if reg in self._R32 else reg), imm)

    def xor_r32_imm(self, reg: str, imm: int) -> None:
        """Emit `XOR` instruction helper.

        Args:
            reg: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            imm: Immediate integer value.
        """
        self._grp1_imm(32, 6, self.gpr(reg if reg in self._R32 else reg), imm)

    def cmp_r32_imm(self, reg: str, imm: int) -> None:
        """Emit `CMP` instruction helper.

        Args:
            reg: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            imm: Immediate integer value.
        """
        if getattr(self, '_peephole_enabled', False) and int(imm) == 0:
            self.test_r32_r32(reg, reg)
            return
        self._grp1_imm(32, 7, self.gpr(reg if reg in self._R32 else reg), imm)

    # Backwards-compat alias (some codegen paths expect *_imm32 names)
    def cmp_r32_imm32(self, reg: str, imm: int) -> None:
        """Emit `CMP` instruction helper.

        Args:
            reg: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            imm: Immediate integer value.
        """
        self.cmp_r32_imm(reg, imm)

    def and_r8_imm8(self, reg8: str, imm: int) -> None:
        """Emit `AND` instruction helper.

        Args:
            reg8: Parameter.
            imm: Immediate integer value.
        """
        self._grp1_imm(8, 4, self.gpr(reg8), imm)

    def or_r8_imm8(self, reg8: str, imm: int) -> None:
        """Emit `OR` instruction helper.

        Args:
            reg8: Parameter.
            imm: Immediate integer value.
        """
        self._grp1_imm(8, 1, self.gpr(reg8), imm)

    def xor_r8_imm8(self, reg8: str, imm: int) -> None:
        """Emit `XOR` instruction helper.

        Args:
            reg8: Parameter.
            imm: Immediate integer value.
        """
        self._grp1_imm(8, 6, self.gpr(reg8), imm)

    def add_r8_imm8(self, reg8: str, imm: int) -> None:
        """Emit `ADD` instruction helper.

        Args:
            reg8: Parameter.
            imm: Immediate integer value.
        """
        # add r/m8, imm8  => 80 /0 ib
        self._grp1_imm(8, 0, self.gpr(reg8), imm)

    def sub_r8_imm8(self, reg8: str, imm: int) -> None:
        """Emit `SUB` instruction helper.

        Args:
            reg8: Parameter.
            imm: Immediate integer value.
        """
        # sub r/m8, imm8  => 80 /5 ib
        self._grp1_imm(8, 5, self.gpr(reg8), imm)

    def cmp_r8_imm8(self, reg8: str, imm: int) -> None:
        """Emit `CMP` instruction helper.

        Args:
            reg8: Parameter.
            imm: Immediate integer value.
        """
        if getattr(self, '_peephole_enabled', False) and int(imm) == 0:
            self.test_r8_r8(reg8, reg8)
            return
        self._grp1_imm(8, 7, self.gpr(reg8), imm)

    # reg-reg arithmetic
    def add_r64_r64(self, dst: str, src: str) -> None:
        """Emit `ADD` instruction helper.

        Args:
            dst: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            src: Register name (e.g. 'rax', 'r10', 'eax', 'al').
        """
        d = self._rid_any(dst)
        s = self._rid_any(src)
        rex_r = 1 if d >= 8 else 0
        rex_b = 1 if s >= 8 else 0
        self.emit(self._rex(w=1, r=rex_r, b=rex_b) + b"\x03" + self._modrm(3, d, s))

    def sub_r64_r64(self, dst: str, src: str) -> None:
        """Emit `SUB` instruction helper.

        Args:
            dst: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            src: Register name (e.g. 'rax', 'r10', 'eax', 'al').
        """
        d = self._rid_any(dst)
        s = self._rid_any(src)
        rex_r = 1 if d >= 8 else 0
        rex_b = 1 if s >= 8 else 0
        self.emit(self._rex(w=1, r=rex_r, b=rex_b) + b"\x2B" + self._modrm(3, d, s))

    def add_r32_r32(self, dst: str, src: str) -> None:
        """Emit `ADD` instruction helper.

        Args:
            dst: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            src: Register name (e.g. 'rax', 'r10', 'eax', 'al').
        """
        d = self._rid_any(dst)
        s = self._rid_any(src)
        rex_r = 1 if d >= 8 else 0
        rex_b = 1 if s >= 8 else 0
        self.emit(self._rex(w=0, r=rex_r, b=rex_b) + b"\x03" + self._modrm(3, d, s))

    def sub_r32_r32(self, dst: str, src: str) -> None:
        """Emit `SUB` instruction helper.

        Args:
            dst: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            src: Register name (e.g. 'rax', 'r10', 'eax', 'al').
        """
        d = self._rid_any(dst)
        s = self._rid_any(src)
        rex_r = 1 if d >= 8 else 0
        rex_b = 1 if s >= 8 else 0
        self.emit(self._rex(w=0, r=rex_r, b=rex_b) + b"\x2B" + self._modrm(3, d, s))

    def xor_r64_r64(self, dst: str, src: str) -> None:
        """Emit `XOR` instruction helper.

        Args:
            dst: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            src: Register name (e.g. 'rax', 'r10', 'eax', 'al').
        """
        d = self._rid_any(dst)
        s = self._rid_any(src)
        rex_r = 1 if d >= 8 else 0
        rex_b = 1 if s >= 8 else 0
        self.emit(self._rex(w=1, r=rex_r, b=rex_b) + b"\x33" + self._modrm(3, d, s))

    def xor_r32_r32(self, dst: str, src: str) -> None:
        """Emit `XOR` instruction helper.

        Args:
            dst: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            src: Register name (e.g. 'rax', 'r10', 'eax', 'al').
        """
        d = self._rid_any(dst)
        s = self._rid_any(src)
        rex_r = 1 if d >= 8 else 0
        rex_b = 1 if s >= 8 else 0
        self.emit(self._rex(w=0, r=rex_r, b=rex_b) + b"\x33" + self._modrm(3, d, s))

    def and_r64_r64(self, dst: str, src: str) -> None:
        """Emit `AND` instruction helper.

        Args:
            dst: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            src: Register name (e.g. 'rax', 'r10', 'eax', 'al').
        """
        d = self._rid_any(dst)
        s = self._rid_any(src)
        rex_r = 1 if d >= 8 else 0
        rex_b = 1 if s >= 8 else 0
        self.emit(self._rex(w=1, r=rex_r, b=rex_b) + b"\x23" + self._modrm(3, d, s))

    def or_r64_r64(self, dst: str, src: str) -> None:
        """Emit `OR` instruction helper.

        Args:
            dst: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            src: Register name (e.g. 'rax', 'r10', 'eax', 'al').
        """
        d = self._rid_any(dst)
        s = self._rid_any(src)
        rex_r = 1 if d >= 8 else 0
        rex_b = 1 if s >= 8 else 0
        self.emit(self._rex(w=1, r=rex_r, b=rex_b) + b"\x0B" + self._modrm(3, d, s))

    def and_r8_r8(self, dst8: str, src8: str) -> None:
        """Emit `AND` instruction helper.

        Args:
            dst8: Destination register name.
            src8: Source register name.
        """
        d = self.gpr(dst8)
        s = self.gpr(src8)
        if d.size != 8 or s.size != 8:
            raise ValueError("and_r8_r8 requires 8-bit regs")
        rex_r = 1 if d.id >= 8 else 0
        rex_b = 1 if s.id >= 8 else 0
        force = d.force_rex or s.force_rex
        self.emit(self._rex(w=0, r=rex_r, b=rex_b, force=force) + b"\x22" + self._modrm(3, d.id, s.id))

    def or_r8_r8(self, dst8: str, src8: str) -> None:
        """Emit `OR` instruction helper.

        Args:
            dst8: Destination register name.
            src8: Source register name.
        """
        d = self.gpr(dst8)
        s = self.gpr(src8)
        if d.size != 8 or s.size != 8:
            raise ValueError("or_r8_r8 requires 8-bit regs")
        rex_r = 1 if d.id >= 8 else 0
        rex_b = 1 if s.id >= 8 else 0
        force = d.force_rex or s.force_rex
        self.emit(self._rex(w=0, r=rex_r, b=rex_b, force=force) + b"\x0A" + self._modrm(3, d.id, s.id))

    # ---------------------------------------------------------------------
    # shifts (imm8)
    # ---------------------------------------------------------------------

    def shl_r64_imm8(self, reg: str, imm: int) -> None:
        """Emit `SHL` instruction helper.

        Args:
            reg: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            imm: Immediate integer value.
        """
        r = self._rid_any(reg)
        rex_b = 1 if r >= 8 else 0
        self.emit(self._rex(w=1, b=rex_b) + b"\xC1" + self._modrm(3, 4, r) + bytes([imm & 0xFF]))

    def shr_r64_imm8(self, reg: str, imm: int) -> None:
        """Emit `SHR` instruction helper.

        Args:
            reg: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            imm: Immediate integer value.
        """
        r = self._rid_any(reg)
        rex_b = 1 if r >= 8 else 0
        self.emit(self._rex(w=1, b=rex_b) + b"\xC1" + self._modrm(3, 5, r) + bytes([imm & 0xFF]))

    def sar_r64_imm8(self, reg: str, imm: int) -> None:
        """Emit `SAR` instruction helper.

        Args:
            reg: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            imm: Immediate integer value.
        """
        r = self._rid_any(reg)
        rex_b = 1 if r >= 8 else 0
        self.emit(self._rex(w=1, b=rex_b) + b"\xC1" + self._modrm(3, 7, r) + bytes([imm & 0xFF]))

    def shl_r32_imm8(self, reg: str, imm: int) -> None:
        """Emit `SHL` instruction helper.

        Args:
            reg: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            imm: Immediate integer value.
        """
        r = self._rid_any(reg)
        rex_b = 1 if r >= 8 else 0
        self.emit(self._rex(w=0, b=rex_b) + b"\xC1" + self._modrm(3, 4, r) + bytes([imm & 0xFF]))

    def sar_r32_imm8(self, reg: str, imm: int) -> None:
        """Emit `SAR` instruction helper.

        Args:
            reg: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            imm: Immediate integer value.
        """
        r = self._rid_any(reg)
        rex_b = 1 if r >= 8 else 0
        self.emit(self._rex(w=0, b=rex_b) + b"\xC1" + self._modrm(3, 7, r) + bytes([imm & 0xFF]))

    def shr_r32_imm8(self, reg: str, imm: int) -> None:
        """Emit `SHR` instruction helper.

        Args:
            reg: Register name (e.g. 'eax', 'r10d').
            imm: Immediate integer value.
        """
        r = self._rid_any(reg)
        rex_b = 1 if r >= 8 else 0
        self.emit(self._rex(w=0, b=rex_b) + b"\xC1" + self._modrm(3, 5, r) + bytes([imm & 0xFF]))

    # ---------------------------------------------------------------------
    # shifts (CL)
    # ---------------------------------------------------------------------

    def shl_r64_cl(self, reg: str) -> None:
        """shl r/m64, cl  (D3 /4)"""
        r = self._rid_any(reg)
        rex_b = 1 if r >= 8 else 0
        self.emit(self._rex(w=1, b=rex_b) + b"\xD3" + self._modrm(3, 4, r))

    def shr_r64_cl(self, reg: str) -> None:
        """shr r/m64, cl  (D3 /5)"""
        r = self._rid_any(reg)
        rex_b = 1 if r >= 8 else 0
        self.emit(self._rex(w=1, b=rex_b) + b"\xD3" + self._modrm(3, 5, r))

    def sar_r64_cl(self, reg: str) -> None:
        """sar r/m64, cl  (D3 /7)"""
        r = self._rid_any(reg)
        rex_b = 1 if r >= 8 else 0
        self.emit(self._rex(w=1, b=rex_b) + b"\xD3" + self._modrm(3, 7, r))

    # ---------------------------------------------------------------------
    # compare / test
    # ---------------------------------------------------------------------

    def cmp_r64_r64(self, a: str, b: str) -> None:
        """Emit `CMP` instruction helper.

        Args:
            a: Parameter.
            b: Parameter.
        """
        # cmp a, b  (3B /r)
        aa = self._rid_any(a)
        bb = self._rid_any(b)
        rex_r = 1 if aa >= 8 else 0
        rex_b = 1 if bb >= 8 else 0
        self.emit(self._rex(w=1, r=rex_r, b=rex_b) + b"\x3B" + self._modrm(3, aa, bb))

    def cmp_r32_r32(self, a: str, b: str) -> None:
        """Emit `CMP` instruction helper.

        Args:
            a: Parameter.
            b: Parameter.
        """
        aa = self._rid_any(a)
        bb = self._rid_any(b)
        rex_r = 1 if aa >= 8 else 0
        rex_b = 1 if bb >= 8 else 0
        self.emit(self._rex(w=0, r=rex_r, b=rex_b) + b"\x3B" + self._modrm(3, aa, bb))

    def test_r64_r64(self, a: str, b: str) -> None:
        """Emit `TEST` instruction helper.

        Args:
            a: Parameter.
            b: Parameter.
        """
        aa = self._rid_any(a)
        bb = self._rid_any(b)
        rex_r = 1 if aa >= 8 else 0
        rex_b = 1 if bb >= 8 else 0
        self.emit(self._rex(w=1, r=rex_r, b=rex_b) + b"\x85" + self._modrm(3, aa, bb))

    def test_r32_r32(self, a: str, b: str) -> None:
        """Emit `TEST` instruction helper.

        Args:
            a: Parameter.
            b: Parameter.
        """
        aa = self._rid_any(a)
        bb = self._rid_any(b)
        rex_r = 1 if aa >= 8 else 0
        rex_b = 1 if bb >= 8 else 0
        self.emit(self._rex(w=0, r=rex_r, b=rex_b) + b"\x85" + self._modrm(3, aa, bb))

    def test_r64_imm32(self, reg: str, imm: int) -> None:
        """Emit `TEST` instruction helper.

        Args:
            reg: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            imm: Immediate integer value.
        """
        # test r/m64, imm32  => F7 /0 imm32
        r = self._rid_any(reg)
        rex_b = 1 if r >= 8 else 0
        self.emit(self._rex(w=1, b=rex_b) + b"\xF7" + self._modrm(3, 0, r) + u32(imm))

    def cmp_r8_membase_disp(self, reg8: str, base: str, disp: int = 0) -> None:
        """Emit `CMP` instruction helper.

        Args:
            reg8: Parameter.
            base: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            disp: Displacement/offset in bytes.
        """
        # cmp r8, [base+disp]  => 3A /r
        rr = self.gpr(reg8)
        if rr.size != 8:
            raise ValueError("cmp_r8_membase_disp requires an 8-bit reg")
        b = self._rid_any(base)
        rex_r = 1 if rr.id >= 8 else 0
        rex_x, rex_b, tail = self._encode_mem(rr.id, b, disp)
        force = rr.force_rex
        self.emit(self._rex(w=0, r=rex_r, x=rex_x, b=rex_b, force=force) + b"\x3A" + tail)

    def cmp_membase_disp_imm8(self, base: str, disp: int, imm: int) -> None:
        """Emit `CMP` instruction helper.

        Args:
            base: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            disp: Displacement/offset in bytes.
            imm: Immediate integer value.
        """
        # cmp byte [base+disp], imm8  => 80 /7 imm8
        b = self._rid_any(base)
        rex_x, rex_b, tail = self._encode_mem(7, b, disp)  # /7
        self.emit(self._rex(w=0, x=rex_x, b=rex_b) + b"\x80" + tail + bytes([imm & 0xFF]))

    def test_r8_r8(self, a8: str, b8: str) -> None:
        """Emit `TEST` instruction helper.

        Args:
            a8: Parameter.
            b8: Parameter.
        """
        # test r/m8, r8 (84 /r) but for reg-reg we can still use it
        aa = self.gpr(a8)
        bb = self.gpr(b8)
        if aa.size != 8 or bb.size != 8:
            raise ValueError("test_r8_r8 requires 8-bit regs")
        rex_r = 1 if bb.id >= 8 else 0  # ModRM.reg is source
        rex_b = 1 if aa.id >= 8 else 0  # ModRM.rm is dest
        force = aa.force_rex or bb.force_rex
        self.emit(self._rex(w=0, r=rex_r, b=rex_b, force=force) + b"\x84" + self._modrm(3, bb.id, aa.id))

    # ---------------------------------------------------------------------
    # setcc / movzx
    # ---------------------------------------------------------------------

    def setcc_r8(self, dst8: str, cc: str) -> None:
        """
        setcc r/m8 (register form here).
        cc: e, ne, l, le, g, ge, b, be, a, ae, s, ns, p, np, o, no
        """
        cc_map = {"o": 0x90, "no": 0x91, "b": 0x92, "ae": 0x93, "e": 0x94, "ne": 0x95, "be": 0x96, "a": 0x97, "s": 0x98,
                  "ns": 0x99, "p": 0x9A, "np": 0x9B, "l": 0x9C, "ge": 0x9D, "le": 0x9E, "g": 0x9F, }
        if cc not in cc_map:
            raise ValueError(f"Unknown setcc: {cc}")
        r = self.gpr(dst8)
        if r.size != 8:
            raise ValueError("setcc_r8 requires an 8-bit register")
        rex_b = 1 if r.id >= 8 else 0
        self.emit(self._rex(w=0, b=rex_b, force=r.force_rex) + b"\x0F" + bytes([cc_map[cc]]) + self._modrm(3, 0, r.id))

    def movzx_r32_r8(self, dst32: str, src8: str) -> None:
        """Emit `MOVZX` instruction helper.

        Args:
            dst32: Destination register name.
            src8: Source register name.
        """
        d = self.gpr(dst32)
        s = self.gpr(src8)
        if d.size != 32 or s.size != 8:
            raise ValueError("movzx_r32_r8 requires (r32, r8)")
        rex_r = 1 if d.id >= 8 else 0
        rex_b = 1 if s.id >= 8 else 0
        force = s.force_rex
        self.emit(self._rex(w=0, r=rex_r, b=rex_b, force=force) + b"\x0F\xB6" + self._modrm(3, d.id, s.id))

    def movzx_r32_membase_disp(self, dst32: str, base: str, disp: int = 0) -> None:
        """Emit `MOVZX` instruction helper.

        Args:
            dst32: Destination register name.
            base: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            disp: Displacement/offset in bytes.
        """
        # movzx r32, byte [base+disp]
        d = self.gpr(dst32)
        if d.size != 32:
            raise ValueError("movzx_r32_membase_disp requires 32-bit dst")
        b = self._rid_any(base)
        rex_r = 1 if d.id >= 8 else 0
        rex_x, rex_b, tail = self._encode_mem(d.id, b, disp)
        self.emit(self._rex(w=0, r=rex_r, x=rex_x, b=rex_b) + b"\x0F\xB6" + tail)

    def bsf_r32_r32(self, dst32: str, src32: str) -> None:
        """Emit `BSF` instruction helper.

        Args:
            dst32: Destination register name.
            src32: Source register name.
        """
        d = self.gpr(dst32)
        s = self.gpr(src32)
        if d.size != 32 or s.size != 32:
            raise ValueError("bsf_r32_r32 requires (r32, r32)")
        rex_r = 1 if d.id >= 8 else 0
        rex_b = 1 if s.id >= 8 else 0
        self.emit(self._rex(w=0, r=rex_r, b=rex_b) + b"\x0F\xBC" + self._modrm(3, d.id, s.id))

    # ---------------------------------------------------------------------
    # inc/dec/neg, mul/div
    # ---------------------------------------------------------------------

    def inc_r64(self, reg: str) -> None:
        """Emit `INC` instruction helper.

        Args:
            reg: Register name (e.g. 'rax', 'r10', 'eax', 'al').
        """
        r = self._rid_any(reg)
        rex_b = 1 if r >= 8 else 0
        self.emit(self._rex(w=1, b=rex_b) + b"\xFF" + self._modrm(3, 0, r))

    def dec_r64(self, reg: str) -> None:
        """Emit `DEC` instruction helper.

        Args:
            reg: Register name (e.g. 'rax', 'r10', 'eax', 'al').
        """
        r = self._rid_any(reg)
        rex_b = 1 if r >= 8 else 0
        self.emit(self._rex(w=1, b=rex_b) + b"\xFF" + self._modrm(3, 1, r))

    def inc_r32(self, reg: str) -> None:
        """Emit `INC` instruction helper.

        Args:
            reg: Register name (e.g. 'rax', 'r10', 'eax', 'al').
        """
        r = self._rid_any(reg)
        rex_b = 1 if r >= 8 else 0
        self.emit(self._rex(w=0, b=rex_b) + b"\xFF" + self._modrm(3, 0, r))

    def dec_r32(self, reg: str) -> None:
        """Emit `DEC` instruction helper.

        Args:
            reg: Register name (e.g. 'rax', 'r10', 'eax', 'al').
        """
        r = self._rid_any(reg)
        rex_b = 1 if r >= 8 else 0
        self.emit(self._rex(w=0, b=rex_b) + b"\xFF" + self._modrm(3, 1, r))

    def inc_membase_disp_qword(self, base: str, disp: int) -> None:
        """Emit `INC` instruction helper.

        Args:
            base: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            disp: Displacement/offset in bytes.
        """
        b = self._rid_any(base)
        rex_x, rex_b, tail = self._encode_mem(0, b, disp)  # /0
        self.emit(self._rex(w=1, x=rex_x, b=rex_b) + b"\xFF" + tail)

    def dec_membase_disp_qword(self, base: str, disp: int) -> None:
        """Emit `DEC` instruction helper.

        Args:
            base: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            disp: Displacement/offset in bytes.
        """
        b = self._rid_any(base)
        rex_x, rex_b, tail = self._encode_mem(1, b, disp)  # /1
        self.emit(self._rex(w=1, x=rex_x, b=rex_b) + b"\xFF" + tail)

    def neg_r64(self, reg: str) -> None:
        """Emit `NEG` instruction helper.

        Args:
            reg: Register name (e.g. 'rax', 'r10', 'eax', 'al').
        """
        r = self._rid_any(reg)
        rex_b = 1 if r >= 8 else 0
        self.emit(self._rex(w=1, b=rex_b) + b"\xF7" + self._modrm(3, 3, r))

    def imul_r64_r64(self, dst: str, src: str) -> None:
        """Emit `IMUL` instruction helper.

        Args:
            dst: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            src: Register name (e.g. 'rax', 'r10', 'eax', 'al').
        """
        # imul dst, src  (0F AF /r)
        d = self._rid_any(dst)
        s = self._rid_any(src)
        rex_r = 1 if d >= 8 else 0
        rex_b = 1 if s >= 8 else 0
        self.emit(self._rex(w=1, r=rex_r, b=rex_b) + b"\x0F\xAF" + self._modrm(3, d, s))

    def imul_r64_r64_imm(self, dst: str, src: str, imm: int) -> None:
        """Emit `IMUL` instruction helper.

        Args:
            dst: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            src: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            imm: Immediate integer value.
        """
        # imul dst, src, imm8/imm32  (6B /r imm8 or 69 /r imm32)
        d = self._rid_any(dst)
        s = self._rid_any(src)
        rex_r = 1 if d >= 8 else 0
        rex_b = 1 if s >= 8 else 0
        if self._fits_i8(imm):
            self.emit(self._rex(w=1, r=rex_r, b=rex_b) + b"\x6B" + self._modrm(3, d, s) + bytes([imm & 0xFF]))
        else:
            self.emit(self._rex(w=1, r=rex_r, b=rex_b) + b"\x69" + self._modrm(3, d, s) + u32(imm))

    def cqo(self) -> None:
        """Emit `CQO` instruction helper.
        """
        self.emit(b"\x48\x99")

    def idiv_r64(self, src: str) -> None:
        """Emit `IDIV` instruction helper.

        Args:
            src: Register name (e.g. 'rax', 'r10', 'eax', 'al').
        """
        # idiv r/m64  => F7 /7
        s = self._rid_any(src)
        rex_b = 1 if s >= 8 else 0
        self.emit(self._rex(w=1, b=rex_b) + b"\xF7" + self._modrm(3, 7, s))

    # ---------------------------------------------------------------------
    # string ops
    # ---------------------------------------------------------------------

    def div_r64(self, src: str) -> None:
        """Emit `DIV` instruction helper.

        Args:
            src: Register name (e.g. 'rax', 'r10', 'eax', 'al').
        """
        # div r/m64  => F7 /6
        s = self._rid_any(src)
        rex_b = 1 if s >= 8 else 0
        self.emit(self._rex(w=1, b=rex_b) + b"\xF7" + self._modrm(3, 6, s))

    def rep_movsb(self) -> None:
        """Emit instruction/utility helper.
        """
        # rep movsb
        self.emit(b"\xF3\xA4")

    def rep_movsq(self) -> None:
        """Emit instruction/utility helper.
        """
        # rep movsq
        self.emit(b"\xF3\x48\xA5")

    def rep_stosb(self) -> None:
        """Emit instruction/utility helper.
        """
        # rep stosb
        self.emit(b"\xF3\xAA")

    def rep_stosq(self) -> None:
        """Emit instruction/utility helper.
        """
        # rep stosq
        self.emit(b"\xF3\x48\xAB")

    def repe_cmpsb(self) -> None:
        """Emit instruction/utility helper.
        """
        # repe cmpsb
        self.emit(b"\xF3\xA6")

    def cpuid(self) -> None:
        """Emit `CPUID` instruction helper.
        """
        self.emit(b"\x0F\xA2")

    def xgetbv(self) -> None:
        """Emit `XGETBV` instruction helper.
        """
        self.emit(b"\x0F\x01\xD0")

    # ---------------------------------------------------------------------
    # SSE2 helpers (xmm0..xmm15)
    # ---------------------------------------------------------------------

    def movsd_xmm_xmm(self, dst: str, src: str) -> None:
        """Emit `MOVSD` instruction helper.

        Args:
            dst: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            src: Register name (e.g. 'rax', 'r10', 'eax', 'al').
        """
        # F2 0F 10 /r
        if getattr(self, '_peephole_enabled', False) and str(dst) == str(src):
            return
        d = self.XMM[dst]
        s = self.XMM[src]
        rex_r = 1 if d >= 8 else 0
        rex_b = 1 if s >= 8 else 0
        self.emit(b"\xF2" + self._rex(r=rex_r, b=rex_b) + b"\x0F\x10" + self._modrm(3, d, s))

    def movsd_xmm_membase_disp(self, dst: str, base: str, disp: int = 0) -> None:
        """Emit `MOVSD` instruction helper.

        Args:
            dst: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            base: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            disp: Displacement/offset in bytes.
        """
        d = self.XMM[dst]
        b = self._rid_any(base)
        rex_r = 1 if d >= 8 else 0
        rex_x, rex_b, tail = self._encode_mem(d, b, disp)
        self.emit(b"\xF2" + self._rex(r=rex_r, x=rex_x, b=rex_b) + b"\x0F\x10" + tail)

    def movsd_membase_disp_xmm(self, base: str, disp: int, src: str) -> None:
        """Emit `MOVSD` instruction helper.

        Args:
            base: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            disp: Displacement/offset in bytes.
            src: Register name (e.g. 'rax', 'r10', 'eax', 'al').
        """
        s = self.XMM[src]
        b = self._rid_any(base)
        rex_r = 1 if s >= 8 else 0
        rex_x, rex_b, tail = self._encode_mem(s, b, disp)
        self.emit(b"\xF2" + self._rex(r=rex_r, x=rex_x, b=rex_b) + b"\x0F\x11" + tail)

    def addsd_xmm_xmm(self, dst: str, src: str) -> None:
        """Emit `ADDSD` instruction helper.

        Args:
            dst: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            src: Register name (e.g. 'rax', 'r10', 'eax', 'al').
        """
        d = self.XMM[dst]
        s = self.XMM[src]
        rex_r = 1 if d >= 8 else 0
        rex_b = 1 if s >= 8 else 0
        self.emit(b"\xF2" + self._rex(r=rex_r, b=rex_b) + b"\x0F\x58" + self._modrm(3, d, s))

    def subsd_xmm_xmm(self, dst: str, src: str) -> None:
        """Emit `SUBSD` instruction helper.

        Args:
            dst: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            src: Register name (e.g. 'rax', 'r10', 'eax', 'al').
        """
        d = self.XMM[dst]
        s = self.XMM[src]
        rex_r = 1 if d >= 8 else 0
        rex_b = 1 if s >= 8 else 0
        self.emit(b"\xF2" + self._rex(r=rex_r, b=rex_b) + b"\x0F\x5C" + self._modrm(3, d, s))

    def mulsd_xmm_xmm(self, dst: str, src: str) -> None:
        """Emit `MULSD` instruction helper.

        Args:
            dst: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            src: Register name (e.g. 'rax', 'r10', 'eax', 'al').
        """
        d = self.XMM[dst]
        s = self.XMM[src]
        rex_r = 1 if d >= 8 else 0
        rex_b = 1 if s >= 8 else 0
        self.emit(b"\xF2" + self._rex(r=rex_r, b=rex_b) + b"\x0F\x59" + self._modrm(3, d, s))

    def divsd_xmm_xmm(self, dst: str, src: str) -> None:
        """Emit `DIVSD` instruction helper.

        Args:
            dst: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            src: Register name (e.g. 'rax', 'r10', 'eax', 'al').
        """
        d = self.XMM[dst]
        s = self.XMM[src]
        rex_r = 1 if d >= 8 else 0
        rex_b = 1 if s >= 8 else 0
        self.emit(b"\xF2" + self._rex(r=rex_r, b=rex_b) + b"\x0F\x5E" + self._modrm(3, d, s))

    def ucomisd_xmm_xmm(self, a: str, b: str) -> None:
        """Emit instruction/utility helper.

        Args:
            a: Parameter.
            b: Parameter.
        """
        # 66 0F 2E /r
        aa = self.XMM[a]
        bb = self.XMM[b]
        rex_r = 1 if aa >= 8 else 0
        rex_b = 1 if bb >= 8 else 0
        self.emit(b"\x66" + self._rex(r=rex_r, b=rex_b) + b"\x0F\x2E" + self._modrm(3, aa, bb))

    def cvtsi2sd_xmm_r64(self, dst: str, src: str) -> None:
        """Emit `CVTSI2SD` instruction helper.

        Args:
            dst: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            src: Register name (e.g. 'rax', 'r10', 'eax', 'al').
        """
        # F2 0F 2A /r  with REX.W for 64-bit src
        d = self.XMM[dst]
        s = self._rid_any(src)
        rex_r = 1 if d >= 8 else 0
        rex_b = 1 if s >= 8 else 0
        self.emit(b"\xF2" + self._rex(w=1, r=rex_r, b=rex_b) + b"\x0F\x2A" + self._modrm(3, d, s))

    def cvttsd2si_r64_xmm(self, dst: str, src: str) -> None:
        """Emit `CVTTSD2SI` instruction helper.

        Args:
            dst: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            src: Register name (e.g. 'rax', 'r10', 'eax', 'al').
        """
        # F2 0F 2C /r  with REX.W for 64-bit dst
        d = self._rid_any(dst)
        s = self.XMM[src]
        rex_r = 1 if d >= 8 else 0
        rex_b = 1 if s >= 8 else 0
        self.emit(b"\xF2" + self._rex(w=1, r=rex_r, b=rex_b) + b"\x0F\x2C" + self._modrm(3, d, s))

    def cvtsd2ss_xmm_xmm(self, dst: str, src: str) -> None:
        """Emit `CVTSD2SS` instruction helper."""
        d = self.XMM[dst]
        s = self.XMM[src]
        rex_r = 1 if d >= 8 else 0
        rex_b = 1 if s >= 8 else 0
        self.emit(b"\xF2" + self._rex(r=rex_r, b=rex_b) + b"\x0F\x5A" + self._modrm(3, d, s))

    def cvtss2sd_xmm_xmm(self, dst: str, src: str) -> None:
        """Emit `CVTSS2SD` instruction helper."""
        d = self.XMM[dst]
        s = self.XMM[src]
        rex_r = 1 if d >= 8 else 0
        rex_b = 1 if s >= 8 else 0
        self.emit(b"\xF3" + self._rex(r=rex_r, b=rex_b) + b"\x0F\x5A" + self._modrm(3, d, s))

    # Missing-but-needed float helpers (from report)
    def xorpd_xmm_xmm(self, dst: str, src: str) -> None:
        """Emit `XORPD` instruction helper.

        Args:
            dst: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            src: Register name (e.g. 'rax', 'r10', 'eax', 'al').
        """
        # 66 0F 57 /r
        d = self.XMM[dst]
        s = self.XMM[src]
        rex_r = 1 if d >= 8 else 0
        rex_b = 1 if s >= 8 else 0
        self.emit(b"\x66" + self._rex(r=rex_r, b=rex_b) + b"\x0F\x57" + self._modrm(3, d, s))

    def movapd_xmm_xmm(self, dst: str, src: str) -> None:
        """Emit instruction/utility helper.

        Args:
            dst: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            src: Register name (e.g. 'rax', 'r10', 'eax', 'al').
        """
        # 66 0F 28 /r
        if getattr(self, '_peephole_enabled', False) and str(dst) == str(src):
            return
        d = self.XMM[dst]
        s = self.XMM[src]
        rex_r = 1 if d >= 8 else 0
        rex_b = 1 if s >= 8 else 0
        self.emit(b"\x66" + self._rex(r=rex_r, b=rex_b) + b"\x0F\x28" + self._modrm(3, d, s))

    def roundsd_xmm_xmm_imm8(self, dst: str, src: str, imm: int) -> None:
        """Emit instruction/utility helper.

        Args:
            dst: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            src: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            imm: Immediate integer value.
        """
        # 66 0F 3A 0B /r imm8
        d = self.XMM[dst]
        s = self.XMM[src]
        rex_r = 1 if d >= 8 else 0
        rex_b = 1 if s >= 8 else 0
        self.emit(b"\x66" + self._rex(r=rex_r, b=rex_b) + b"\x0F\x3A\x0B" + self._modrm(3, d, s) + bytes([imm & 0xFF]))

    def movq_xmm_r64(self, dst: str, src: str) -> None:
        """Emit instruction/utility helper.

        Args:
            dst: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            src: Register name (e.g. 'rax', 'r10', 'eax', 'al').
        """
        # 66 0F 6E /r  with REX.W => movq xmm, r/m64
        d = self.XMM[dst]
        s = self._rid_any(src)
        rex_r = 1 if d >= 8 else 0
        rex_b = 1 if s >= 8 else 0
        self.emit(b"\x66" + self._rex(w=1, r=rex_r, b=rex_b) + b"\x0F\x6E" + self._modrm(3, d, s))

    def movd_r32_xmm(self, dst: str, src: str) -> None:
        """Emit `MOVD r32, xmm`."""
        d = self._rid_any(dst)
        s = self.XMM[src]
        rex_r = 1 if s >= 8 else 0
        rex_b = 1 if d >= 8 else 0
        self.emit(b"\x66" + self._rex(r=rex_r, b=rex_b) + b"\x0F\x7E" + self._modrm(3, s, d))

    def movdqu_xmm_membase_disp(self, dst: str, base: str, disp: int = 0) -> None:
        """Emit `MOVDQU xmm, [base+disp]`.

        Args:
            dst: XMM destination register.
            base: Base register.
            disp: Displacement in bytes.
        """
        d = self.XMM[dst]
        b = self._rid_any(base)
        rex_r = 1 if d >= 8 else 0
        rex_x, rex_b, tail = self._encode_mem(d, b, disp)
        self.emit(b"\xF3" + self._rex(r=rex_r, x=rex_x, b=rex_b) + b"\x0F\x6F" + tail)

    def movdqu_membase_disp_xmm(self, base: str, disp: int, src: str) -> None:
        """Emit `MOVDQU [base+disp], xmm`.

        Args:
            base: Base register.
            disp: Displacement in bytes.
            src: XMM source register.
        """
        s = self.XMM[src]
        b = self._rid_any(base)
        rex_r = 1 if s >= 8 else 0
        rex_x, rex_b, tail = self._encode_mem(s, b, disp)
        self.emit(b"\xF3" + self._rex(r=rex_r, x=rex_x, b=rex_b) + b"\x0F\x7F" + tail)

    def pxor_xmm_xmm(self, dst: str, src: str) -> None:
        """Emit `PXOR` instruction helper.

        Args:
            dst: XMM destination register.
            src: XMM source register.
        """
        d = self.XMM[dst]
        s = self.XMM[src]
        rex_r = 1 if d >= 8 else 0
        rex_b = 1 if s >= 8 else 0
        self.emit(b"\x66" + self._rex(r=rex_r, b=rex_b) + b"\x0F\xEF" + self._modrm(3, d, s))

    def pcmpeqb_xmm_xmm(self, dst: str, src: str) -> None:
        """Emit `PCMPEQB` instruction helper.

        Args:
            dst: XMM destination register.
            src: XMM source register.
        """
        d = self.XMM[dst]
        s = self.XMM[src]
        rex_r = 1 if d >= 8 else 0
        rex_b = 1 if s >= 8 else 0
        self.emit(b"\x66" + self._rex(r=rex_r, b=rex_b) + b"\x0F\x74" + self._modrm(3, d, s))

    def pcmpeqw_xmm_xmm(self, dst: str, src: str) -> None:
        """Emit `PCMPEQW` instruction helper.

        Args:
            dst: XMM destination register.
            src: XMM source register.
        """
        d = self.XMM[dst]
        s = self.XMM[src]
        rex_r = 1 if d >= 8 else 0
        rex_b = 1 if s >= 8 else 0
        self.emit(b"\x66" + self._rex(r=rex_r, b=rex_b) + b"\x0F\x75" + self._modrm(3, d, s))

    def pmovmskb_r32_xmm(self, dst32: str, src: str) -> None:
        """Emit `PMOVMSKB` instruction helper.

        Args:
            dst32: 32-bit destination register.
            src: XMM source register.
        """
        d = self.gpr(dst32)
        if d.size != 32:
            raise ValueError("pmovmskb_r32_xmm requires 32-bit dst")
        s = self.XMM[src]
        rex_r = 1 if d.id >= 8 else 0
        rex_b = 1 if s >= 8 else 0
        self.emit(b"\x66" + self._rex(r=rex_r, b=rex_b) + b"\x0F\xD7" + self._modrm(3, d.id, s))

    def punpcklqdq_xmm_xmm(self, dst: str, src: str) -> None:
        """Emit `PUNPCKLQDQ` instruction helper.

        Args:
            dst: XMM destination register.
            src: XMM source register.
        """
        d = self.XMM[dst]
        s = self.XMM[src]
        rex_r = 1 if d >= 8 else 0
        rex_b = 1 if s >= 8 else 0
        self.emit(b"\x66" + self._rex(r=rex_r, b=rex_b) + b"\x0F\x6C" + self._modrm(3, d, s))

    def vmovdqu_ymm_membase_disp(self, dst: str, base: str, disp: int = 0) -> None:
        """Emit `VMOVDQU ymm, [base+disp]`.

        Args:
            dst: YMM destination register.
            base: Base register.
            disp: Displacement in bytes.
        """
        d = self.YMM[dst]
        b = self._rid_any(base)
        rex_r = 1 if d >= 8 else 0
        rex_x, rex_b, tail = self._encode_mem(d, b, disp)
        self.emit(self._vex3(m=1, w=0, vvvv=None, l=1, pp=2, r=rex_r, x=rex_x, b=rex_b) + b"\x6F" + tail)

    def vmovdqu_membase_disp_ymm(self, base: str, disp: int, src: str) -> None:
        """Emit `VMOVDQU [base+disp], ymm`.

        Args:
            base: Base register.
            disp: Displacement in bytes.
            src: YMM source register.
        """
        s = self.YMM[src]
        b = self._rid_any(base)
        rex_r = 1 if s >= 8 else 0
        rex_x, rex_b, tail = self._encode_mem(s, b, disp)
        self.emit(self._vex3(m=1, w=0, vvvv=None, l=1, pp=2, r=rex_r, x=rex_x, b=rex_b) + b"\x7F" + tail)

    def vpcmpeqb_ymm_ymm_ymm(self, dst: str, src1: str, src2: str) -> None:
        """Emit `VPCMPEQB` instruction helper.

        Args:
            dst: YMM destination register.
            src1: First YMM source register.
            src2: Second YMM source register.
        """
        d = self.YMM[dst]
        s1 = self.YMM[src1]
        s2 = self.YMM[src2]
        rex_r = 1 if d >= 8 else 0
        rex_b = 1 if s2 >= 8 else 0
        self.emit(self._vex3(m=1, w=0, vvvv=s1, l=1, pp=1, r=rex_r, b=rex_b) + b"\x74" + self._modrm(3, d, s2))

    def vpcmpeqw_ymm_ymm_ymm(self, dst: str, src1: str, src2: str) -> None:
        """Emit `VPCMPEQW` instruction helper.

        Args:
            dst: YMM destination register.
            src1: First YMM source register.
            src2: Second YMM source register.
        """
        d = self.YMM[dst]
        s1 = self.YMM[src1]
        s2 = self.YMM[src2]
        rex_r = 1 if d >= 8 else 0
        rex_b = 1 if s2 >= 8 else 0
        self.emit(self._vex3(m=1, w=0, vvvv=s1, l=1, pp=1, r=rex_r, b=rex_b) + b"\x75" + self._modrm(3, d, s2))

    def vpmovmskb_r32_ymm(self, dst32: str, src: str) -> None:
        """Emit `VPMOVMSKB` instruction helper.

        Args:
            dst32: 32-bit destination register.
            src: YMM source register.
        """
        d = self.gpr(dst32)
        if d.size != 32:
            raise ValueError("vpmovmskb_r32_ymm requires 32-bit dst")
        s = self.YMM[src]
        rex_r = 1 if d.id >= 8 else 0
        rex_b = 1 if s >= 8 else 0
        self.emit(self._vex3(m=1, w=0, vvvv=None, l=1, pp=1, r=rex_r, b=rex_b) + b"\xD7" + self._modrm(3, d.id, s))

    def vpxor_ymm_ymm_ymm(self, dst: str, src1: str, src2: str) -> None:
        """Emit `VPXOR` instruction helper.

        Args:
            dst: YMM destination register.
            src1: First YMM source register.
            src2: Second YMM source register.
        """
        d = self.YMM[dst]
        s1 = self.YMM[src1]
        s2 = self.YMM[src2]
        rex_r = 1 if d >= 8 else 0
        rex_b = 1 if s2 >= 8 else 0
        self.emit(self._vex3(m=1, w=0, vvvv=s1, l=1, pp=1, r=rex_r, b=rex_b) + b"\xEF" + self._modrm(3, d, s2))

    def vzeroupper(self) -> None:
        """Emit `VZEROUPPER` instruction helper.
        """
        self.emit(b"\xC5\xF8\x77")

    # ---------------------------------------------------------------------
    # Backwards-compatible, older fixed helpers (thin wrappers)
    # ---------------------------------------------------------------------

    # old mov helpers
    def mov_rax_imm64(self, imm: int) -> None:
        """Emit `MOV` instruction helper.

        Args:
            imm: Immediate integer value.
        """
        self.mov_r64_imm64("rax", imm)

    def mov_rcx_imm32(self, imm: int) -> None:
        """Emit `MOV` instruction helper.

        Args:
            imm: Immediate integer value.
        """
        self.mov_r32_imm32("ecx", imm)

    def mov_r8d_imm32(self, imm: int) -> None:
        """Emit `MOV` instruction helper.

        Args:
            imm: Immediate integer value.
        """
        self.mov_r32_imm32("r8d", imm)

    def mov_r9d_imm32(self, imm: int) -> None:
        """Emit `MOV` instruction helper.

        Args:
            imm: Immediate integer value.
        """
        self.mov_r32_imm32("r9d", imm)

    def mov_rbx_rax(self) -> None:
        """Emit `MOV` instruction helper.
        """
        self.mov_r64_r64("rbx", "rax")

    def mov_rcx_rbx(self) -> None:
        """Emit `MOV` instruction helper.
        """
        self.mov_r64_r64("rcx", "rbx")

    def mov_rdx_rax(self) -> None:
        """Emit `MOV` instruction helper.
        """
        self.mov_r64_r64("rdx", "rax")

    def mov_r10_rax(self) -> None:
        """Emit `MOV` instruction helper.
        """
        self.mov_r64_r64("r10", "rax")

    def mov_r11_rax(self) -> None:
        """Emit `MOV` instruction helper.
        """
        self.mov_r64_r64("r11", "rax")

    def mov_rax_r10(self) -> None:
        """Emit `MOV` instruction helper.
        """
        self.mov_r64_r64("rax", "r10")

    def mov_rax_r11(self) -> None:
        """Emit `MOV` instruction helper.
        """
        self.mov_r64_r64("rax", "r11")

    # old arithmetic helpers
    def add_rax_r10(self) -> None:
        """Emit `ADD` instruction helper.
        """
        self.add_r64_r64("rax", "r10")

    def sub_rax_r11(self) -> None:
        """Emit `SUB` instruction helper.
        """
        self.sub_r64_r64("rax", "r11")

    def add_rax_imm8(self, imm: int) -> None:
        """Emit `ADD` instruction helper.

        Args:
            imm: Immediate integer value.
        """
        self.add_r64_imm("rax", imm)

    def sub_rax_imm8(self, imm: int) -> None:
        """Emit `SUB` instruction helper.

        Args:
            imm: Immediate integer value.
        """
        self.sub_r64_imm("rax", imm)

    def and_rax_imm8(self, imm: int) -> None:
        """Emit `AND` instruction helper.

        Args:
            imm: Immediate integer value.
        """
        self.and_r64_imm("rax", imm)

    def or_rax_imm8(self, imm: int) -> None:
        """Emit `OR` instruction helper.

        Args:
            imm: Immediate integer value.
        """
        self.or_r64_imm("rax", imm)

    def sar_rax_imm8(self, imm: int) -> None:
        """Emit `SAR` instruction helper.

        Args:
            imm: Immediate integer value.
        """
        self.sar_r64_imm8("rax", imm)

    def shl_rax_imm8(self, imm: int) -> None:
        """Emit `SHL` instruction helper.

        Args:
            imm: Immediate integer value.
        """
        self.shl_r64_imm8("rax", imm)

    def neg_rax(self) -> None:
        """Emit `NEG` instruction helper.
        """
        self.neg_r64("rax")

    def add_rcx_imm8(self, imm: int) -> None:
        """Emit `ADD` instruction helper.

        Args:
            imm: Immediate integer value.
        """
        self.add_r64_imm("rcx", imm)

    def add_rcx_imm32(self, imm: int) -> None:
        """Emit `ADD` instruction helper.

        Args:
            imm: Immediate integer value.
        """
        self.add_r64_imm("rcx", imm)

    # -----------------------------------------------------------------
    # listing writer (debug aid)
    # -----------------------------------------------------------------

    @staticmethod
    def _jcc_mnemonic(cc: str) -> str:
        """Internal encoder/helper used by instruction emitters.

        Args:
            cc: Parameter.
        """
        m = {'e': 'je', 'z': 'je', 'ne': 'jne', 'nz': 'jne', 'l': 'jl', 'le': 'jle', 'g': 'jg', 'ge': 'jge', 'b': 'jb',
             'be': 'jbe', 'a': 'ja', 'ae': 'jae', 's': 'js', 'ns': 'jns', 'p': 'jp', 'np': 'jnp', 'o': 'jo',
             'no': 'jno', }
        return m.get(cc, f'j{cc}')

    @staticmethod
    def _fmt_disp(d: int) -> str:
        """Internal encoder/helper used by instruction emitters.

        Args:
            d: Parameter.
        """
        if d == 0:
            return ''
        if d < 0:
            return f'-0x{(-d):X}'
        return f'+0x{d:X}'

    @classmethod
    def _fmt_mem(cls, base: str, disp: int = 0, size: str | None = None) -> str:
        """Internal encoder/helper used by instruction emitters.

        Args:
            cls: Parameter.
            base: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            disp: Displacement/offset in bytes.
            size: Operand size in bits/bytes depending on context.
        """
        pre = f'{size} ' if size else ''
        return f"{pre}[{base}{cls._fmt_disp(disp)}]"

    @classmethod
    def _fmt_mem_sib(cls, base: str, index: str, scale: int, disp: int = 0, size: str | None = None) -> str:
        """Internal encoder/helper used by instruction emitters.

        Args:
            cls: Parameter.
            base: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            index: Register name (e.g. 'rax', 'r10', 'eax', 'al').
            scale: Index scale factor (1, 2, 4, or 8).
            disp: Displacement/offset in bytes.
            size: Operand size in bits/bytes depending on context.
        """
        pre = f'{size} ' if size else ''
        core = f'{base}+{index}*{scale}'
        if disp:
            core += cls._fmt_disp(disp)
        return f'{pre}[{core}]'

    def _format_call(self, name: str, args: tuple, kwargs: dict) -> Tuple[str, Tuple[str, ...]]:
        """Format a traced method call for the listing output.

        Args:
            name: Label name.
            args: Parameter.
            kwargs: Parameter.
        """
        # Control flow
        if name == 'jmp':
            return f'jmp {args[0]}', (str(args[0]),)
        if name == 'jcc':
            cc, lab = args
            return f"{self._jcc_mnemonic(cc)} {lab}", (str(lab),)
        if name == 'call':
            return f'call {args[0]}', (str(args[0]),)
        if name == 'call_rax':
            return 'call rax', ()
        if name == 'call_membase_disp':
            base, disp = args
            return f'call {self._fmt_mem(base, int(disp), "qword")}', ()
        if name == 'call_rip_qword':
            lab = args[0]
            return f'call qword [rip+{lab}]', (str(lab),)
        if name == 'ret':
            return 'ret', ()
        if name == 'leave':
            return 'leave', ()
        if name == 'nop':
            return 'nop', ()

        # RIP-relative helpers
        if name.startswith('mov_rip_'):
            sz = 'qword' if 'qword' in name else 'dword'
            src = name.split('_')[-1]
            lab = args[0]
            return f'mov {sz} [rip+{lab}], {src}', (str(lab),)
        # load form: mov <reg>, [rip+label]
        if name.startswith('mov_') and '_rip_' in name and not name.startswith('mov_rip_'):
            # e.g. mov_rax_rip_qword / mov_eax_rip_dword
            dst = name.split('_')[1]
            lab = args[0]
            sz = 'qword' if 'qword' in name else 'dword'
            return f'mov {dst}, {sz} [rip+{lab}]', (str(lab),)
        if name.startswith('lea_') and name.endswith('_rip'):
            dst = name.split('_')[1]
            lab = args[0]
            return f'lea {dst}, [rip+{lab}]', (str(lab),)

        # push/pop
        if name == 'push_reg':
            return f'push {args[0]}', ()
        if name == 'pop_reg':
            return f'pop {args[0]}', ()

        # common mov patterns
        if name == 'mov_r64_r64' or name == 'mov_r32_r32' or name == 'mov_r8_r8':
            return f'mov {args[0]}, {args[1]}', ()
        if name == 'mov_r64_imm64' or name == 'mov_r32_imm32':
            dst, imm = args
            return f'mov {dst}, 0x{int(imm) & ((1 << 64) - 1):X}', ()

        if name == 'mov_r64_membase_disp':
            dst, base, disp = args
            return f'mov {dst}, {self._fmt_mem(base, int(disp), "qword")}', ()
        if name == 'mov_membase_disp_r64':
            base, disp, src = args
            return f'mov {self._fmt_mem(base, int(disp), "qword")}, {src}', ()
        if name == 'mov_r32_membase_disp':
            dst, base, disp = args
            return f'mov {dst}, {self._fmt_mem(base, int(disp), "dword")}', ()
        if name == 'mov_membase_disp_r32':
            base, disp, src = args
            return f'mov {self._fmt_mem(base, int(disp), "dword")}, {src}', ()
        if name == 'mov_r8_membase_disp':
            dst, base, disp = args
            return f'mov {dst}, {self._fmt_mem(base, int(disp), "byte")}', ()
        if name == 'mov_membase_disp_r8':
            base, disp, src = args
            return f'mov {self._fmt_mem(base, int(disp), "byte")}, {src}', ()

        # SIB
        if name == 'mov_r64_mem_bis':
            dst, base, index, scale, disp = args
            return f'mov {dst}, {self._fmt_mem_sib(base, index, int(scale), int(disp), "qword")}', ()
        if name == 'mov_mem_bis_r64':
            base, index, scale, disp, src = args
            return f'mov {self._fmt_mem_sib(base, index, int(scale), int(disp), "qword")}, {src}', ()

        # group1 r8, imm8
        if name in ('add_r8_imm8', 'sub_r8_imm8', 'and_r8_imm8', 'or_r8_imm8', 'xor_r8_imm8', 'cmp_r8_imm8'):
            op = name.split('_', 1)[0]
            reg, imm = args
            return f"{op} {reg}, 0x{int(imm) & 0xFF:X}", ()

        # div/idiv
        if name in ('div_r64', 'idiv_r64'):
            op = 'div' if name == 'div_r64' else 'idiv'
            return f"{op} {args[0]}", ()

        # fallback: show method + args
        return f"; {name}({', '.join(map(str, args))})", ()

    def write_listing(self, path: Optional[str] = None, *, base_addr: int = 0,
                      label_addr_map: Optional[Dict[str, int]] = None, show_addr: Optional[bool] = None,
                      show_bytes: Optional[bool] = None, show_text: Optional[bool] = None, ) -> None:
        if path is None:
            path = self._listing_path
        if not path:
            return

        if show_addr is None:
            show_addr = self._listing_show_addr
        if show_bytes is None:
            show_bytes = self._listing_show_bytes
        if show_text is None:
            show_text = self._listing_show_text

        if not (show_addr or show_bytes or show_text):
            show_text = True

        pos_to_labels: Dict[int, List[str]] = {}
        for off, lab in self._label_defs:
            pos_to_labels.setdefault(off, []).append(lab)

        spans = sorted(self._trace, key=lambda e: (e.start, e.end))
        end_pos = len(self.buf)

        def hex_bytes(bs: bytes) -> str:
            return ' '.join(f'{b:02X}' for b in bs)

        def addr(off: int) -> str:
            return f'{(base_addr + off):08X}'

        def emit_labels(f, at: int) -> None:
            if at in pos_to_labels:
                for lab in pos_to_labels[at]:
                    rva = label_addr_map.get(lab) if label_addr_map else None
                    if rva is None:
                        f.write(f'{lab}: ; off=0x{at:X}\n')
                    else:
                        f.write(f'{lab}: ; off=0x{at:X} rva=0x{rva:X}\n')

        def write_span_line(f, off: int, bs: bytes, txt: str) -> None:
            cols: List[str] = []
            if show_addr:
                cols.append(addr(off))
            if show_bytes:
                hb = hex_bytes(bs)
                cols.append(f"{hb:<48}" if show_text else hb)
            if show_text:
                cols.append(txt)
            f.write("  ".join(cols).rstrip() + "\n")

        with open(path, 'w', encoding='utf-8', newline='\n') as f:
            f.write('; MiniLang .text listing (generated)\n')
            f.write(f'; code size: 0x{end_pos:X} bytes\n')
            if base_addr:
                f.write(f'; .text base RVA: 0x{base_addr:X}\n')
            f.write('\n')

            cur = 0
            for e in spans:
                # fill gap
                while cur < e.start:
                    emit_labels(f, cur)
                    chunk = bytes(self.buf[cur:min(e.start, cur + 16)])
                    if not chunk:
                        break
                    write_span_line(f, cur, chunk, "db " + ', '.join('0x%02X' % b for b in chunk))
                    cur += len(chunk)

                emit_labels(f, e.start)
                bs = bytes(self.buf[e.start:e.end])
                txt = e.text
                if label_addr_map and e.refs:
                    ann = [f"{lab}=0x{label_addr_map[lab]:X}" for lab in e.refs if lab in label_addr_map]
                    if ann:
                        txt += '    ; ' + ', '.join(ann)
                write_span_line(f, e.start, bs, txt)
                cur = max(cur, e.end)

            # tail
            while cur < end_pos:
                emit_labels(f, cur)
                chunk = bytes(self.buf[cur:min(end_pos, cur + 16)])
                write_span_line(f, cur, chunk, "db " + ', '.join('0x%02X' % b for b in chunk))
                cur += len(chunk)

            if self.patches:
                f.write('\n; patches\n')
                for p2, lab, kind in self.patches:
                    rva = label_addr_map.get(lab) if label_addr_map else None
                    if rva is None:
                        f.write(f'; +0x{p2:X} {kind} -> {lab}\n')
                    else:
                        f.write(f'; +0x{p2:X} {kind} -> {lab} (0x{rva:X})\n')

    # old cmp/test helpers
    def cmp_rax_r10(self) -> None:
        """Emit `CMP` instruction helper.
        """
        self.cmp_r64_r64("rax", "r10")

    def cmp_rax_imm8(self, imm: int) -> None:
        """Emit `CMP` instruction helper.

        Args:
            imm: Immediate integer value.
        """
        self.cmp_r64_imm("rax", imm)

    def cmp_rax_imm32(self, imm: int) -> None:
        """Emit `CMP` instruction helper.

        Args:
            imm: Immediate integer value.
        """
        self.cmp_r64_imm("rax", imm)

    def test_rax_imm32(self, imm: int) -> None:
        """Emit `TEST` instruction helper.

        Args:
            imm: Immediate integer value.
        """
        self.test_r64_imm32("rax", imm)

    # old setcc/movzx
    def setcc_al(self, cc: str) -> None:
        """Emit instruction/utility helper.

        Args:
            cc: Parameter.
        """
        self.setcc_r8("al", cc)

    def movzx_eax_al(self) -> None:
        """Emit `MOVZX` instruction helper.
        """
        self.movzx_r32_r8("eax", "al")

    # old misc
    def mov_r8d_edx(self) -> None:
        """Emit `MOV` instruction helper.
        """
        self.mov_r32_r32("r8d", "edx")

    def mov_qword_ptr_rsp20_rax_zero(self) -> None:
        """Emit `MOV` instruction helper.
        """
        # xor eax,eax ; mov [rsp+0x20], rax
        self.xor_r32_r32("eax", "eax")
        self.mov_membase_disp_r64("rsp", 0x20, "rax")

    def xor_ecx_ecx(self) -> None:
        """Emit `XOR` instruction helper.
        """
        self.xor_r32_r32("ecx", "ecx")

    def xor_eax_eax(self) -> None:
        """Emit `XOR` instruction helper.
        """
        self.xor_r32_r32("eax", "eax")
