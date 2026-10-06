"""Heap-size, listing and native memory/FFI contract for either compiler.

Run on Windows (with WSL Ubuntu) or Linux. Windows images are compiled for
parity on Linux but can only be executed on Windows. Timing is not a test gate.
"""
import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile

MAX_SIZE = (1 << 60) - 65536

def invoke(command, expected=0):
    result = subprocess.run(command, capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=120)
    if result.returncode != expected:
        raise AssertionError(f"{command!r}: exit {result.returncode}\n{result.stdout}\n{result.stderr}")
    return result.stdout

def execute(image, target, *args):
    if target == "windows-x64":
        return invoke([str(image), *args]) if os.name == "nt" else None
    if os.name != "nt":
        image.chmod(0o755)
        return invoke([str(image), *args])
    linux = invoke(["wsl", "-d", "Ubuntu", "--", "wslpath", "-a", "-u", image.as_posix()]).strip()
    invoke(["wsl", "-d", "Ubuntu", "--", "chmod", "+x", linux])
    return invoke(["wsl", "-d", "Ubuntu", "--", "timeout", "90s", linux, *args])

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("compiler", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    compiler = args.compiler.resolve()
    command = [sys.executable, str(compiler)] if compiler.suffix == ".py" else [str(compiler)]
    sequence = 0
    with tempfile.TemporaryDirectory(prefix="ml_cli_memory_") as temporary:
        tmp = Path(temporary)
        def build(source, target, pipeline, flags=(), expected=0, image=None):
            nonlocal sequence
            sequence += 1
            image = image or tmp / f"image-{sequence}.exe"
            invoke([*command, str(root / "tests" / source), str(image), "-I", str(root),
                    "--target", target, pipeline, *flags], expected)
            if expected:
                assert not image.exists(), "Invalid CLI unexpectedly produced an image"
            return image
        for target in ("windows-x64", "linux-x64"):
            for pipeline in ("--no-object-pipeline", "--object-pipeline"):
                base = ["--heap-reserve", "40m", "--heap-commit", "32m", "--heap-grow"]
                reference = None
                for size in ("40m", "40MB", "40mib", "40960kib", "41_943_040b", " 40m\t", "\v \f40m\v \f"):
                    image = build("memory_heap_ceiling.ml", target, pipeline, [*base, size])
                    digest = hashlib.sha256(image.read_bytes()).digest()
                    if reference is None:
                        reference = digest
                    assert digest == reference, f"Different size alias: {size}"
                    output = execute(image, target, "full-reserve")
                    assert output is None or "MEMORY CEILING [OK]" in output
                for size in ("1t", "1tb", "1tib", str(MAX_SIZE), "0" * 100 + "41943040"):
                    image = build("memory_heap_ceiling.ml", target, pipeline, [*base, size])
                    output = execute(image, target, "full-reserve")
                    assert output is None or "MEMORY CEILING [OK]" in output
                for flag in ("--heap-reserve", "--heap-commit", "--heap-grow", "--heap-shrink-min", "--gc-limit"):
                    for size in ("", "0", "-1", "1.5m", "40mbx", "4\v0m", "４０m", "1\u212a", str(MAX_SIZE + 1), "1048576t", "9" * 100):
                        build("memory_heap_ceiling.ml", target, pipeline, [flag, size], expected=2)

                # Check both relocated listing paths, default names and disabling.
                for filename in ("listed.elf", "extensionless", ".hidden"):
                    image = tmp / (target + "-" + pipeline[2:]) / filename
                    image.parent.mkdir(exist_ok=True)
                    listing = image.with_suffix(".asm") if image.suffix else Path(str(image) + ".asm")
                    build("memory_heap_ceiling.ml", target, pipeline, ["--asm", "--asm-data"], image=image)
                    text = listing.read_text(encoding="utf-8")
                    assert ".text" in text and ".rdata" in text and ".data" in text
                    listing.unlink()  # Only this fixture's disposable generated listing.
                    build("memory_heap_ceiling.ml", target, pipeline, ["--no-asm", "--asm-out", str(listing)], image=image)
                    assert not listing.exists()
                explicit = tmp / f"explicit-{target}-{pipeline[2:]}.asm"
                build("memory_heap_ceiling.ml", target, pipeline, ["--asm", "--asm-out", str(explicit)])
                assert ".text" in explicit.read_text(encoding="utf-8")
                build("memory_heap_ceiling.ml", target, pipeline, ["--asm", "--no-asm"], expected=2)
                # A listing write error must be reported, never silent success.
                invoke([*command, str(root / "tests/memory_heap_ceiling.ml"),
                        str(tmp / "write-error.exe"), "--target", target, pipeline,
                        "--asm", "--asm-out", str(tmp / "absent" / "listing.asm")], expected=2)

                for fixture, marker in (("gc_bitmap_words.ml", "GC BITMAP WORDS [OK]"),
                                        ("ffi_cstr_return.ml", "FFI CSTR RETURN [OK]")):
                    flags = ["--heap-shrink", "--heap-shrink-min", "64k", "--heap-commit", "64k", "--heap-grow", "64k", "--gc-limit", "1m"]
                    image = build(fixture, target, pipeline, flags)
                    output = execute(image, target)
                    assert output is None or marker in output
                print(f"[OK] {target} {pipeline}: size/listing/bitmap/cstr contract", flush=True)
    print("CLI MEMORY CONTRACT [OK]")

if __name__ == "__main__":
    main()
