"""Typed symbolic inline x64 assembly lowering.

The source operands are compiler-owned stack slots. No raw source register name
can overwrite a GC root, frame pointer, or live expression temporary.
"""

from __future__ import annotations

import re

from ..constants import TAG_BOOL, TAG_INT
from ..tools import enc_void


_BYTE_STORE = re.compile(r"byte\[([A-Za-z_]\w*)\.data\+([A-Za-z_]\w*)\]", re.I)
_INT = re.compile(r"-?(?:0[xX][0-9A-Fa-f]+|0[bB][01]+|\d+)\Z")
_SCALAR = {"int", "bool", "float"}


def _immediate(value: str) -> int | None:
    if not _INT.fullmatch(value):
        return None
    sign = -1 if value.startswith("-") else 1
    raw = value[1:] if sign < 0 else value
    base = 16 if raw.lower().startswith("0x") else 2 if raw.lower().startswith("0b") else 10
    return sign * int(raw, base)


def emit_inline_asm(cg, expr) -> None:
    """Emit one validated inline x64 block into the current function."""
    a = cg.asm
    ml = cg.ml
    names = list(expr.names)
    types = [str(t) for t in expr.types]
    modes = list(expr.modes)
    optional = list(expr.optional)
    result_type = str(expr.result_type)
    result_optional = bool(expr.result_optional)
    if len(names) > 24:
        raise cg.error("asm supports at most 24 input operands", expr)
    if len(set(names)) != len(names) or len(names) != len(types) or len(names) != len(modes):
        raise cg.error("invalid asm operand declarations", expr)
    if result_type.lower() == "void" and result_optional:
        raise cg.error("asm cannot return void?", expr)

    def kind(ty: str, opt: bool) -> str:
        low = ty.lower()
        return low if low in _SCALAR and not opt else "value"

    symbols = {name: (i, types[i], optional[i], modes[i]) for i, name in enumerate(names)}
    if result_type.lower() != "void":
        symbols["result"] = (len(names), result_type, result_optional, "out")

    def symbol(name: str):
        entry = symbols.get(name)
        if entry is None:
            raise cg.error(f"unknown asm operand '{name}'", expr)
        return entry

    def require_writable(name: str) -> None:
        if symbol(name)[3] not in ("out", "inout"):
            raise cg.error(f"asm operand '{name}' is read-only", expr)

    # Validate every instruction before touching the assembler stream.
    result_written = result_type.lower() == "void"
    for op, operands in expr.instructions:
        if op == "mov" and len(operands) == 2 and _BYTE_STORE.fullmatch(operands[0]):
            if not expr.unsafe:
                raise cg.error("byte memory stores require 'asm unsafe x64'", expr)
            match = _BYTE_STORE.fullmatch(operands[0])
            buf, index = match.group(1), match.group(2)
            if symbol(buf)[1] != "bytes" or symbol(buf)[3] != "inout":
                raise cg.error("byte store requires an inout bytes operand", expr)
            if kind(symbol(index)[1], symbol(index)[2]) != "int" or kind(symbol(operands[1])[1], symbol(operands[1])[2]) != "int":
                raise cg.error("byte index and value must be int operands", expr)
            continue
        if op not in {"mov", "test", "cmp", "cmovz", "cmovnz", "bsf", "add", "sub", "xor", "and", "or",
                      "shl", "shr", "sar", "movsd", "addsd", "subsd", "mulsd", "divsd"}:
            raise cg.error(f"unsupported inline asm instruction '{op}'", expr)
        if len(operands) != 2:
            raise cg.error(f"asm instruction '{op}' expects two operands", expr)
        dst, src = operands
        if src == "result" and not result_written:
            raise cg.error("asm reads 'result' before assigning it", expr)
        if dst == "result" and op in ("test", "cmp") and not result_written:
            raise cg.error("asm reads 'result' before assigning it", expr)
        dst_entry = symbol(dst)
        dst_kind = kind(dst_entry[1], dst_entry[2])
        imm_value = _immediate(src)
        imm = imm_value is not None
        src_kind = "int" if imm else kind(symbol(src)[1], symbol(src)[2])
        if op not in ("test", "cmp"):
            require_writable(dst)
            if dst == "result":
                if op not in ("mov", "movsd", "bsf") and not result_written:
                    raise cg.error("asm reads 'result' before assigning it", expr)
                result_written = True
        if op in ("movsd", "addsd", "subsd", "mulsd", "divsd"):
            if dst_kind != "float" or src_kind != "float" or imm:
                raise cg.error(f"asm instruction '{op}' requires float operands", expr)
        elif op in ("mov", "cmovz", "cmovnz"):
            same_value_type = (dst_entry[1] == symbol(src)[1] and dst_entry[2] == symbol(src)[2]) if not imm else False
            if dst_kind != src_kind or (dst_kind == "value" and not same_value_type) or (imm and dst_kind != "int"):
                raise cg.error(f"asm instruction '{op}' requires matching operand types", expr)
        elif op in ("shl", "shr", "sar"):
            if dst_kind != "int" or not imm:
                raise cg.error(f"asm instruction '{op}' requires an int destination and immediate count", expr)
            if not 0 <= imm_value <= 63:
                raise cg.error("asm shift count must be in 0..63", expr)
        elif op in ("test", "cmp") and dst_kind == "bool" and src_kind == "bool":
            pass
        elif dst_kind != "int" or src_kind != "int":
            raise cg.error(f"asm instruction '{op}' requires int operands", expr)
    if not result_written:
        raise cg.error("asm block must assign 'result'", expr)

    n = len(names)
    frame_size = (2 * n + 1) * 8
    base = cg.alloc_expr_temps(frame_size)

    def raw_off(index: int) -> int:
        return base + (n + index) * 8

    def load_gpr(operand: str, reg: str) -> None:
        imm_value = _immediate(operand)
        if imm_value is not None:
            a.mov_r64_imm64(reg, imm_value)
        else:
            a.mov_r64_membase_disp(reg, "rsp", raw_off(symbol(operand)[0]))

    def store_gpr(operand: str, reg: str) -> None:
        a.mov_membase_disp_r64("rsp", raw_off(symbol(operand)[0]), reg)

    def emit_value(ty: str, opt: bool, off: int) -> None:
        k = kind(ty, opt)
        if k == "float":
            a.movsd_xmm_membase_disp("xmm0", "rsp", off)
            cg.emit_force_xmm0_to_float_value()
        else:
            a.mov_r64_membase_disp("rax", "rsp", off)
            if k == "int":
                a.shl_rax_imm8(3)
                a.or_rax_imm8(TAG_INT)
            elif k == "bool":
                a.test_r64_r64("rax", "rax")
                a.setcc_al("ne")
                a.movzx_r32_r8("eax", "al")
                a.shl_rax_imm8(3)
                a.or_rax_imm8(TAG_BOOL)

    for i, arg in enumerate(expr.args):
        ty = types[i]
        if ty.lower() != "unknown":
            arg = ml.TypeGuard(arg, expr.types[i], optional[i])
        cg.emit_expr(arg)
        a.mov_membase_disp_r64("rsp", base + i * 8, "rax")
        k = kind(ty, optional[i])
        if k == "int":
            a.sar_r64_imm8("rax", 3)
        elif k == "bool":
            a.shr_r64_imm8("rax", 3)
        elif k == "float":
            fail = f"inline_asm_float_fail_{cg.new_label_id()}"
            cg.emit_to_double_xmm(0, fail)
            a.movsd_membase_disp_xmm("rsp", raw_off(i), "xmm0")
            a.mark(fail)  # The preceding type guard makes this path unreachable.
            continue
        a.mov_membase_disp_r64("rsp", raw_off(i), "rax")

    for op, operands in expr.instructions:
        dst, src = operands
        mem = _BYTE_STORE.fullmatch(dst) if op == "mov" else None
        if mem:
            buf, index = mem.group(1), mem.group(2)
            a.mov_r64_membase_disp("r10", "rsp", base + symbol(buf)[0] * 8)
            load_gpr(index, "r11")
            a.lea_r64_mem_bis("r10", "r10", "r11", 1, 8)
            load_gpr(src, "rax")
            a.mov_membase_disp_r8("r10", 0, "al")
            continue
        k = kind(symbol(dst)[1], symbol(dst)[2])
        if op in ("movsd", "addsd", "subsd", "mulsd", "divsd"):
            a.movsd_xmm_membase_disp("xmm0", "rsp", raw_off(symbol(dst)[0]))
            a.movsd_xmm_membase_disp("xmm1", "rsp", raw_off(symbol(src)[0]))
            if op != "movsd":
                getattr(a, op + "_xmm_xmm")("xmm0", "xmm1")
            else:
                a.movsd_xmm_xmm("xmm0", "xmm1")
            a.movsd_membase_disp_xmm("rsp", raw_off(symbol(dst)[0]), "xmm0")
            continue
        load_gpr(dst, "r10")
        if op in ("shl", "shr", "sar"):
            getattr(a, op + "_r64_imm8")("r10", _immediate(src))
            store_gpr(dst, "r10")
            continue
        load_gpr(src, "r11")
        if op == "mov":
            a.mov_r64_r64("r10", "r11")
        elif op == "test":
            a.test_r64_r64("r10", "r11")
        elif op == "cmp":
            a.cmp_r64_r64("r10", "r11")
        elif op in ("cmovz", "cmovnz"):
            a.cmovcc_r64_r64("e" if op == "cmovz" else "ne", "r10", "r11")
        elif op == "bsf":
            a.bsf_r64_r64("r10", "r11")
        else:
            getattr(a, op + "_r64_r64")("r10", "r11")
        if op not in ("test", "cmp"):
            store_gpr(dst, "r10")

    for i, name in enumerate(names):
        if modes[i] == "inout":
            emit_value(types[i], optional[i], raw_off(i))
            cg.emit_store_var(name, expr)
    if result_type.lower() == "void":
        a.mov_rax_imm64(enc_void())
    else:
        emit_value(result_type, result_optional, raw_off(n))
    cg.free_expr_temps(frame_size)
