#!/usr/bin/env python3
"""Compare memory regressions across Python, Windows ML and Linux ML hosts.

Run on Windows with WSL Ubuntu; each target is checked in both pipelines.
Execution checks live in check_memory_runtime.py; this test checks exact bytes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def run(command):
    result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise RuntimeError(f"{command}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def linux_path(path):
    return run(["wsl", "-d", "Ubuntu", "--", "wslpath", "-a", "-u",
                path.resolve().as_posix()]).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("python_compiler", type=Path)
    parser.add_argument("windows_compiler", type=Path)
    parser.add_argument("linux_compiler", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("Run this three-host comparison on Windows with WSL Ubuntu")
    root = Path(__file__).resolve().parents[1]
    compilers = {
        "python": [sys.executable, str(args.python_compiler.resolve())],
        "windows-ml": [str(args.windows_compiler.resolve())],
        "linux-ml": ["wsl", "-d", "Ubuntu", "--", linux_path(args.linux_compiler)],
    }
    cases = [
        ("memory_management.ml", []),
        ("memory_stats_indirect.ml", []),
        ("memory_purge.ml", ["--heap-shrink", "--heap-shrink-min", "1m"]),
        ("memory_policy.ml", ["--gc-limit", "1m"]),
        ("memory_policy.ml", ["--no-gc-periodic"]),
        ("memory_policy.ml", ["--gc-limit", "1m", "--no-gc-periodic"]),
        ("tlab_shared_heap.ml", ["--heap-shrink", "--heap-shrink-min", "1m"]),
        ("gc_back_to_back_safepoint.ml", []),
    ]
    rows = []
    with tempfile.TemporaryDirectory(prefix="ml_memory_parity_") as temporary:
        for target in ("windows-x64", "linux-x64"):
            for case, (fixture, flags) in enumerate(cases):
                hashes = []
                for host, command in compilers.items():
                    for pipeline in ("--no-object-pipeline", "--object-pipeline"):
                        image = Path(temporary) / f"{target}-{case}-{host}-{pipeline[2:]}.exe"
                        source = root / "tests" / fixture
                        paths = [str(source), str(image), "-I", str(root)]
                        if host == "linux-ml":
                            paths = [linux_path(source), linux_path(image), "-I", linux_path(root)]
                        run([*command, *paths, "--target", target, pipeline, *flags])
                        digest = hashlib.sha256(image.read_bytes()).hexdigest()
                        hashes.append(digest)
                        rows.append(dict(target=target, fixture=fixture, flags=flags,
                                         host=host, pipeline=pipeline, sha256=digest,
                                         size=image.stat().st_size))
                if len(set(hashes)) != 1:
                    raise AssertionError(f"Compiler mismatch: {target} {fixture} {flags}")
                print(f"[OK] {target}: {fixture} {flags}, six-way byte parity")
    args.output.write_text(json.dumps(dict(images=rows), indent=2) + "\n", encoding="utf-8")
    print("MEMORY COMPILER PARITY [OK]")


if __name__ == "__main__":
    main()
