"""Cross-target GC policy, purge and pipeline regressions for either compiler."""
import argparse
from pathlib import Path
import os
import re
import subprocess
import sys
import tempfile

def run(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise AssertionError(f"{args}: exit {result.returncode}\n{result.stdout}\n{result.stderr}")
    return result.stdout

def check_long_churn(output, target):
    """Detect progressive retention after repeated mixed-size allocations."""
    rows = []
    for line in output.splitlines():
        if line.startswith("cycle="):
            rows.append({name: int(value) for name, value in
                         re.findall(r"(\w+)=(\d+)", line)})
    assert [row["cycle"] for row in rows] == list(range(25)), rows
    baseline = rows[0]["live"]
    for row in rows[1:]:
        assert row["live"] <= baseline + 1024 * 1024, row
        assert row["reclaimed"] >= 20 * 1024 * 1024, row
        assert row["committed"] <= 2 * 1024 * 1024, row
        assert row["frontier"] <= 2 * 1024 * 1024, row
    if target == "windows-x64":
        private = [row["private"] for row in rows[4:]]
        assert max(private) - min(private) <= 2 * 1024 * 1024, private
    assert "MEMORY LONG CHURN [OK]" in output, output


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
        ("memory_heap_ceiling.ml", ["--heap-reserve", "40m", "--heap-commit", "32m"], [], "MEMORY CEILING [OK]"),
        ("memory_heap_ceiling.ml", ["--heap-reserve", "40m", "--heap-commit", "32m", "--heap-grow", "128m"], [], "MEMORY CEILING [OK]"),
        ("memory_heap_ceiling.ml", ["--heap-reserve", "40m", "--heap-commit", "32m", "--heap-grow", "4g"], ["full-reserve"], "MEMORY CEILING [OK]"),
        ("memory_heap_ceiling.ml", ["--heap-reserve", "40m", "--heap-commit", "32m", "--heap-grow", "5001"], ["alignment"], "MEMORY CEILING [OK]"),
        ("gc_thread_lifetime.ml", [], [], "GC THREAD LIFETIME [OK]"),
        ("gc_handoff_lifetime.ml", [], [], "GC HANDOFF LIFETIME [OK]"),
        ("memory_gc_metadata.ml", ["--heap-shrink", "--heap-shrink-min", "1m"], [], "GC METADATA [OK]"),
        ("memory_long_churn.ml", ["--heap-reserve", "256m", "--heap-commit", "16m", "--heap-shrink", "--heap-shrink-min", "1m", "--no-gc-periodic"], [], "MEMORY LONG CHURN [OK]"),
        ("memory_fragmentation_cursor.ml", [], [], "MEMORY CURSOR [OK]"),
        ("gc_bitmap_words.ml", ["--heap-shrink", "--heap-shrink-min", "64k", "--gc-limit", "1m"], [], "GC BITMAP WORDS [OK]"),
        ("ffi_cstr_return.ml", ["--heap-shrink", "--heap-shrink-min", "64k", "--gc-limit", "1m"], [], "FFI CSTR RETURN [OK]"),
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
                    # Above-reserve requests must still fail, never silently
                    # overcommit beyond the declared managed-heap reservation.
                    if fixture == "memory_heap_ceiling.ml":
                        if target == "windows-x64" or os.name != "nt":
                            negative_command = [str(image), "overflow"]
                        else:
                            negative_command = ["wsl", "-d", "Ubuntu", "--", "timeout", "90s", linux, "overflow"]
                        negative = subprocess.run(negative_command, capture_output=True, text=True, timeout=120)
                        assert negative.returncode == 1 and "heap exhausted" in negative.stderr, negative
                    assert marker in output, output
                    if fixture == "memory_long_churn.ml":
                        check_long_churn(output, target)
                assert images[0] == images[1], f"Pipeline mismatch: {target} {fixture}"
                print(f"[OK] {target}: {fixture} {flags}, normal/object parity")
    print("MEMORY MATRIX [OK]")

if __name__ == "__main__":
    main()
