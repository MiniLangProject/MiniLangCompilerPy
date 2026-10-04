#!/usr/bin/env python3
"""Execute random regressions and compare three compiler hosts on Windows/WSL."""
import argparse
import functools
import hashlib
import json
from pathlib import Path
import os
import subprocess
import sys
import tempfile


def run(command):
    result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise RuntimeError(f"{command}\n{result.stdout}\n{result.stderr}")
    return result


@functools.cache
def linux_path(path):
    return run(["wsl", "-d", "Ubuntu", "--", "wslpath", "-a", "-u",
                path.resolve().as_posix()]).stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("python_compiler", type=Path)
    parser.add_argument("windows_compiler", type=Path)
    parser.add_argument("linux_compiler", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("Run this three-host comparison on Windows with WSL Ubuntu")
    root = Path(__file__).resolve().parents[1]
    hosts = {
        "python": [sys.executable, str(args.python_compiler.resolve())],
        "windows-ml": [str(args.windows_compiler.resolve())],
        "linux-ml": ["wsl", "-d", "Ubuntu", "--", linux_path(args.linux_compiler)],
    }
    cases = [
        ("random_auto_seeded.ml", "[OK] auto-seeded random"),
        ("random_seeded_only.ml", "[OK] seeded-only random"),
    ]
    rows = []
    with tempfile.TemporaryDirectory(prefix="ml_random_parity_") as temporary:
        for target in ("windows-x64", "linux-x64"):
            for case, (fixture, marker) in enumerate(cases):
                hashes = []
                for host, command in hosts.items():
                    for pipeline in ("--no-object-pipeline", "--object-pipeline"):
                        image = Path(temporary) / f"{target}-{case}-{host}-{pipeline[2:]}.exe"
                        source = root / "tests" / fixture
                        paths = [str(source), str(image), "-I", str(root)]
                        if host == "linux-ml":
                            paths = [linux_path(source), linux_path(image), "-I", linux_path(root)]
                        run([*command, *paths, "--target", target, pipeline])
                        digest = hashlib.sha256(image.read_bytes()).hexdigest()
                        hashes.append(digest)
                        if target == "windows-x64":
                            result = run([str(image)])
                        else:
                            executable = linux_path(image)
                            run(["wsl", "-d", "Ubuntu", "--", "chmod", "+x", executable])
                            # A deterministic-only program must not initialize OpenSSL.
                            # Unused library names may remain in its ELF string data.
                            result = run(["wsl", "-d", "Ubuntu", "--", "env", "LD_DEBUG=libs",
                                          "timeout", "90s", executable])
                            if case == 1:
                                assert "libcrypto.so" not in result.stderr, result.stderr
                        assert marker in result.stdout and "[FAIL]" not in result.stdout, result.stdout
                        rows.append(dict(target=target, fixture=fixture, host=host,
                                         pipeline=pipeline, sha256=digest, size=image.stat().st_size))
                assert len(set(hashes)) == 1, f"Compiler mismatch: {target} {fixture} {hashes}"
                print(f"[OK] {target}: {fixture}, runtime and six-way byte parity")
    if args.output:
        args.output.write_text(json.dumps(dict(images=rows), indent=2) + "\n", encoding="utf-8")
    print("RANDOM COMPILER PARITY [OK]")


if __name__ == "__main__":
    main()
