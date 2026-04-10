#!/usr/bin/env python3
"""Generate / update the golden opcode vectors for mlc/asm.py.

This is a regression-style test asset: it captures the exact bytes emitted by
each public Asm instruction helper for a fixed set of representative operands.

Usage:
  python tests/gen_asm_opcodes_golden.py

Output:
  tests/asm_opcodes_golden.json
"""

from __future__ import annotations

import datetime
import inspect
import json
import re
from pathlib import Path


def main() -> int:
    project_root = Path(__file__).resolve().parents[1]
    # Ensure we can import `mlc` when running from the repository root.
    import sys

    sys.path.insert(0, str(project_root))

    from mlc.asm import Asm

    ignore = {
        "emit",
        "emit8",
        "emit32",
        "emit64",
        "pos",
        "labels",
        "patches",
        "buf",
        "mark",
        "finalize",
        "enable_listing",
        "disable_listing",
        "write_listing",
        "__getattribute__",
    }

    type_tokens = {"xmm", "ymm", "r64", "r32", "r8"}

    def operand_types_from_name(name: str) -> list[str]:
        return [p for p in name.split("_") if p in type_tokens]

    def reg_val(kind: str, i: int) -> str:
        if kind == "r64":
            return "r11" if i == 0 else "r10"
        if kind == "r32":
            return "r11d" if i == 0 else "r10d"
        if kind == "r8":
            return "r11b" if i == 0 else "r10b"
        if kind == "xmm":
            return "xmm9" if i == 0 else "xmm1"
        if kind == "ymm":
            return "ymm9" if i == 0 else "ymm1"
        raise ValueError(kind)

    def choose_int(method_name: str, param_name: str) -> int:
        if param_name == "disp":
            return 0x1234 if "disp32" in method_name else -0x10
        if param_name == "scale":
            return 4
        if param_name in ("imm", "count"):
            if "imm64" in method_name:
                return 0x1122334455667788
            if "imm8" in method_name:
                return 0x7F
            if "imm32" in method_name:
                return 0x11223344
            if any(k in method_name for k in ("shl", "shr", "sar")):
                return 3
            # Default: choose a value that does *not* fit imm8 to exercise the imm32 path
            # for the generic *_imm helpers.
            return 0x11223344
        return 1

    def build_args_kwargs(method_name: str) -> tuple[list, dict]:
        sig = inspect.signature(getattr(Asm, method_name))
        args: list = []
        kwargs: dict = {}
        op_types = operand_types_from_name(method_name)
        op_i = 0
        reg_i = 0

        for p in sig.parameters.values():
            if p.name == "self":
                continue

            if p.kind == inspect.Parameter.KEYWORD_ONLY:
                # Prefer toggling bool keyword-only flags to cover the alternate encoding.
                if p.default in (True, False):
                    kwargs[p.name] = True
                elif p.default is not inspect._empty:
                    kwargs[p.name] = p.default
                else:
                    kwargs[p.name] = None
                continue

            if p.name == "label":
                args.append("L")
                continue
            if p.name == "cc":
                args.append("e")
                continue
            if p.name in ("base", "index"):
                args.append("rbp" if p.name == "base" else "r11")
                continue
            if p.name in ("imm", "disp", "scale", "count"):
                args.append(choose_int(method_name, p.name))
                continue

            # Register-like parameters
            if p.name in ("dst", "src", "reg", "a", "b", "dst8", "src8", "dst32", "src32", "reg8", "dst64", "src64"):
                m = re.search(r"(8|32|64)$", p.name)
                if m:
                    kind = "r" + m.group(1)
                    args.append(reg_val(kind, reg_i))
                    reg_i += 1
                    if op_i < len(op_types) and op_types[op_i] == kind:
                        op_i += 1
                    continue
                if op_i < len(op_types):
                    kind = op_types[op_i]
                    op_i += 1
                    args.append(reg_val(kind, reg_i))
                    reg_i += 1
                    continue
                if "xmm" in method_name:
                    args.append(reg_val("xmm", reg_i))
                    reg_i += 1
                    continue
                if "_r8" in method_name:
                    args.append(reg_val("r8", reg_i))
                    reg_i += 1
                    continue
                if "_r32" in method_name:
                    args.append(reg_val("r32", reg_i))
                    reg_i += 1
                    continue
                args.append(reg_val("r64", reg_i))
                reg_i += 1
                continue

            # Fallback by annotation
            ann = str(p.annotation)
            if "int" in ann:
                args.append(choose_int(method_name, p.name))
                continue
            if "str" in ann:
                kind = op_types[op_i] if op_i < len(op_types) else "r64"
                if op_i < len(op_types):
                    op_i += 1
                args.append(reg_val(kind, reg_i))
                reg_i += 1
                continue

            if p.default is not inspect._empty:
                args.append(p.default)
                continue
            raise RuntimeError(f"Unhandled param {p.name} in {method_name}")

        return args, kwargs

    def emit(method_name: str, args: list, kwargs: dict) -> bytes:
        a = Asm()
        a._peephole_enabled = False
        if "label" in inspect.signature(getattr(Asm, method_name)).parameters:
            a.mark("L")
        getattr(a, method_name)(*args, **kwargs)
        return a.finalize()

    vectors = []
    for name, obj in Asm.__dict__.items():
        if not callable(obj) or name.startswith("_") or name in ignore:
            continue
        args, kwargs = build_args_kwargs(name)
        b = emit(name, args, kwargs)
        try:
            text, _refs = Asm()._format_call(name, tuple(args), kwargs)
        except Exception:
            text = ""
        vectors.append({"name": name, "args": args, "kwargs": kwargs, "hex": b.hex(), "asm": text})

    vectors = sorted(vectors, key=lambda v: v["name"])
    data = {
        "version": 1,
        "generated_utc": datetime.datetime.utcnow().isoformat() + "Z",
        "count": len(vectors),
        "vectors": vectors,
    }

    out_path = Path(__file__).resolve().parent / "asm_opcodes_golden.json"
    out_path.write_text(json.dumps(data, indent=2, sort_keys=False), encoding="utf-8")
    print(f"Wrote: {out_path} ({len(vectors)} vectors)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
