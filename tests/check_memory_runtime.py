"""Cross-target GC policy, purge and pipeline regressions for either compiler."""
import argparse
from pathlib import Path
import os
import subprocess
import sys
import tempfile

def run(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise AssertionError(f"{args}: exit {result.returncode}\n{result.stdout}\n{result.stderr}")
    return result.stdout

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("compiler", type=Path)
    args = parser.parse_args()
    compiler = args.compiler.resolve()
    root = Path(__file__).resolve().parents[1]
    command = [sys.executable, str(compiler)] if compiler.suffix == ".py" else [str(compiler)]
    cases = [
        ("memory_management.ml", [], [], "MEMORY MANAGEMENT [OK]"),
        ("memory_stats_indirect.ml", [], [], "MEMORY INDIRECT [OK]"),
        ("memory_purge.ml", ["--heap-shrink", "--heap-shrink-min", "1m"], [], "MEMORY PURGE [OK]"),
        ("memory_policy.ml", ["--gc-limit", "1m"], ["fixed"], "MEMORY POLICY [OK]"),
        ("memory_policy.ml", ["--no-gc-periodic"], ["disabled"], "MEMORY POLICY [OK]"),
        ("memory_policy.ml", ["--gc-limit", "1m", "--no-gc-periodic"], ["disabled"], "MEMORY POLICY [OK]"),
        ("tlab_shared_heap.ml", ["--heap-shrink", "--heap-shrink-min", "1m"], [], "[OK]"),
        ("gc_back_to_back_safepoint.ml", [], [], "[OK]"),
    ]
    with tempfile.TemporaryDirectory(prefix="ml_memory_matrix_") as temporary:
        for target in ("windows-x64", "linux-x64"):
            for number, (fixture, flags, arguments, marker) in enumerate(cases):
                images = []
                for pipeline in ("--no-object-pipeline", "--object-pipeline"):
                    image = Path(temporary) / f"{target}-{number}-{pipeline[2:]}.exe"
                    run([*command, str(root / "tests" / fixture), str(image),
                         "-I", str(root), "--target", target, pipeline, *flags])
                    images.append(image.read_bytes())
                    if target == "windows-x64":
                        if os.name != "nt":
                            continue
                        output = run([str(image), *arguments])
                    elif os.name == "nt":
                        linux = run(["wsl", "-d", "Ubuntu", "--", "wslpath", "-a", "-u", image.as_posix()]).strip()
                        run(["wsl", "-d", "Ubuntu", "--", "chmod", "+x", linux])
                        output = run(["wsl", "-d", "Ubuntu", "--", "timeout", "90s", linux, *arguments])
                    else:
                        image.chmod(0o755)
                        output = run([str(image), *arguments])
                    assert marker in output, output
                assert images[0] == images[1], f"Pipeline mismatch: {target} {fixture}"
                print(f"[OK] {target}: {fixture} {flags}, normal/object parity")
    print("MEMORY MATRIX [OK]")

if __name__ == "__main__":
    main()
