"""Check that diagnostic writes/timers follow actual source references.

The self-hosted assembler writes a raw byte listing. For native compiler runs,
prove image parity with a Python reference and inspect that symbolic listing.
"""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", type=Path, default=Path(__file__).resolve().parents[1] / "mlc_win64.py")
    parser.add_argument("--reference-compiler", type=Path, help="Python reference for native image/listing parity")
    parser.add_argument("--target", default="windows-x64" if os.name == "nt" else "linux-x64")
    args = parser.parse_args()
    command = ([sys.executable] if args.compiler.suffix == ".py" else []) + [str(args.compiler.resolve())]
    reference = args.reference_compiler
    if args.compiler.suffix != ".py" and reference is None:
        reference = Path(__file__).resolve().parents[1] / "mlc_win64.py"
        if not reference.is_file():
            reference = Path(__file__).resolve().parents[2] / "MiniLangCompilerPy" / "mlc_win64.py"
    cases = [
        ("absent", '// gc_stat in a comment is not a request.\nfunction main(args)\n value=bytes(1,37)\n print "gc_stat"\n return value[0]-37\nend function\n', False),
        ("direct", 'function main(args)\n value=bytes(1,37)\n print gc_stat(22)\n return 0\nend function\n', True),
        ("default_reference", 'function reader(read=gc_stat)\n return read\nend function\nfunction main(args)\n read=reader()\n print read(22)\n return 0\nend function\n', True),
    ]
    with tempfile.TemporaryDirectory(prefix="minilang-gc-gate-") as temporary:
        root = Path(temporary)
        for name, source, expected in cases:
            for mode in ("--object-pipeline", "--no-object-pipeline"):
                entry=root/(name+".ml"); binary=root/(name+".bin"); assembly=root/(name+".asm")
                entry.write_text(source, encoding="utf-8")
                result=subprocess.run(command+[str(entry),str(binary),"--target",args.target,mode,"--asm","--asm-out",str(assembly)],capture_output=True,text=True)
                if result.returncode:
                    raise RuntimeError(result.stdout+result.stderr)
                if args.compiler.suffix != ".py":
                    expected_binary = root / (name + ".reference.bin")
                    reference_command = [sys.executable, str(reference.resolve()), str(entry), str(expected_binary), "--target", args.target, mode, "--asm", "--asm-out", str(assembly)]
                    result = subprocess.run(reference_command, capture_output=True, text=True)
                    if result.returncode:
                        raise RuntimeError(result.stdout + result.stderr)
                    assert binary.read_bytes() == expected_binary.read_bytes(), (name, mode, "Python/native image parity")
                text=assembly.read_text(encoding="utf-8")
                start=text.index("fn_alloc:")
                stop=text.find("\nfn_",start+1)
                allocator=text[start:stop if stop>=0 else len(text)]
                assert "alloc_single_slow" in allocator, (name,mode,"single-thread fast path")
                assert ("gc_object_requests" in allocator)==expected, (name,mode,"request writes")
                assert ("gc_pause_begin_clock" in text)==expected, (name,mode,"collector clock")
                print("[OK]",name,mode)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
