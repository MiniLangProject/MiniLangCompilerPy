"""Structural regression checks shared by the Python and self-hosted backends."""
import argparse
from pathlib import Path
import re
import subprocess
import struct
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("compiler", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    compiler = args.compiler.resolve()
    command = ([sys.executable, str(compiler)] if compiler.suffix == ".py" else [str(compiler)])
    with tempfile.TemporaryDirectory(prefix="ml_codegen_structure_") as temporary:
        output = Path(temporary) / "check.exe"
        listing = Path(temporary) / "check.asm"
        labels_path = Path(temporary) / "check.labels"
        listing_args = (["--asm", "--asm-out", str(listing)] if compiler.suffix == ".py"
                        else ["--dump-labels", str(labels_path)])
        subprocess.run([*command, str(root / "tests/runtime_codegen.ml"), str(output),
                        "-I", str(root), *listing_args],
                       check=True, timeout=120, capture_output=True)
        if compiler.suffix == ".py":
            text = listing.read_text(encoding="utf-8")
        else:
            # Native listings are raw bytes. Combine the label map with exact
            # rel32 call targets to check the same bounded codegen invariants.
            labels = [(name, int(address)) for name, address in re.findall(
                r"\[label\] (\S+) (\d+)", labels_path.read_text(encoding="utf-8"))]
            raw = output.read_bytes()
            pe = struct.unpack_from("<I", raw, 0x3c)[0]
            count = struct.unpack_from("<H", raw, pe + 6)[0]
            optional_size = struct.unpack_from("<H", raw, pe + 20)[0]
            for i in range(count):
                section = pe + 24 + optional_size + 40 * i
                if raw[section:section + 8].rstrip(b"\0") == b".text":
                    rva, size, offset = struct.unpack_from("<III", raw, section + 12)
                    code = raw[offset:offset + size]
                    break
            else:
                raise AssertionError("missing .text")
            targets = {address: name for name, address in labels if name.startswith("fn_")}
            events = [(address, name + ":") for name, address in labels]
            for i in range(len(code) - 4):
                if code[i] == 0xe8:
                    target = rva + i + 5 + struct.unpack_from("<i", code, i + 1)[0]
                    if target in targets:
                        events.append((rva + i, "call " + targets[target]))
            text = "\n".join(value for _, value in sorted(events, key=lambda item: item[0]))
        def function(name):
            match = re.search(r"(?ms)^fn_user_" + re.escape(name) + r":.*?(?=^fn_user_|\Z)", text)
            assert match, name
            return match[0]

        assert "call fn_alloc" not in function("projectedPair"), "temporary allocation remains"
        assert "call fn_alloc" in function("effectfulPair"), "effectful constructor was eliminated"
        dynamic = function("dynamicSum")
        assert "loop_invariant_base_array_" in dynamic, "dynamic array root was not hoisted"
        assert "idx_fast_oob_" in dynamic and "seti_fast_oob_" in dynamic, "dynamic bounds checks lost"
        assert "bounds_elided_" not in dynamic, "unknown length incorrectly proved"
        assert "loop_invariant_base_array_" not in function("reboundLoop"), "mutated target hoisted"
        assert len(re.findall(r"(?m)^fn_make_error_const:", text)) == 1, "cold helper missing/duplicated"
        assert "call fn_make_error_const" in dynamic, "cold path did not use shared helper"
        assert "add_float_" not in function("literalEntry"), "literal inline still dispatches numeric types"
        assert "add_float_" in function("specializedInteger"), "generic callable fallback was specialized"
        # Two stack-homed integer operands load through RAX into R10/R11
        # without publishing/reloading an intermediate expression root.
        load_rax = rb"\x48\x8b(?:\x44\x24.|\x84\x24....)"
        register_pair = load_rax + rb"\x4c\x8b\xd0" + load_rax + rb"\x4c\x8b\xd8"
        assert re.search(register_pair, output.read_bytes(), re.S), "integer RHS register path missing"
    print("CODEGEN STRUCTURE [OK]")


if __name__ == "__main__":
    main()
