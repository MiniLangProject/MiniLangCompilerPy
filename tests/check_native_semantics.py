#!/usr/bin/env python3
"""Compile and execute the shared native semantics regression with either compiler.

Examples (from either repository):
  python tests/check_native_semantics.py --python-compiler ../MiniLangCompilerPy/mlc_win64.py
  python tests/check_native_semantics.py --native-compiler ./mlc_linux
  python tests/check_native_semantics.py --python-compiler ../MiniLangCompilerPy/mlc_win64.py \
      --native-compiler ./mlc_linux --target windows-x64 --compile-only

Both compiler pipelines are checked by default. With multiple compilers, generated
images must be byte-identical for each pipeline. --compile-only explicitly skips
execution for cross-target checks; it does not report runtime tests as passing.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def run(command: list[str], *, cwd: Path, timeout: int) -> subprocess.CompletedProcess[str]:
    """Run one compile or executable and retain diagnostics on failure."""
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"Command failed ({result.returncode}): {command!r}\n"
                           f"{result.stdout}\n{result.stderr}")
    return result


def executable_command(image: Path, target: str) -> list[str]:
    """Choose native execution or Wine, rejecting unavailable target execution."""
    if target == "minux-x64":
        raise RuntimeError("MinUX execution requires a booted guest; use --compile-only for image parity")
    if target == "linux-x64":
        if not sys.platform.startswith("linux"):
            raise RuntimeError("Linux execution requires Linux; use --compile-only for a cross-target check")
        image.chmod(image.stat().st_mode | 0o111)
        return [str(image)]
    if os.name == "nt":
        return [str(image)]
    wine = shutil.which("wine")
    if not wine:
        raise RuntimeError("Windows execution requires Windows or Wine; use --compile-only explicitly")
    return [wine, str(image)]


def main() -> int:
    """Check fixed expected output and compiler parity without changing source trees."""
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--python-compiler", type=Path, help="path to mlc_win64.py")
    parser.add_argument("--native-compiler", type=Path, action="append", default=[],
                        help="native ML compiler executable; repeat to compare bootstrap stages")
    parser.add_argument("--target", choices=("linux-x64", "windows-x64", "minux-x64"),
                        default="windows-x64" if os.name == "nt" else "linux-x64")
    parser.add_argument("--pipeline", choices=("both", "legacy", "object"), default="both")
    parser.add_argument("--compile-only", action="store_true", help="check emitted images without execution")
    parser.add_argument("--compiler-arg", action="append", default=[],
                        help="additional compiler argument; use --compiler-arg=--flag for switches")
    parser.add_argument("--output-dir", type=Path, help="keep generated test executables in this directory")
    args = parser.parse_args()
    if args.python_compiler is None and not args.native_compiler and (root / "mlc_win64.py").is_file():
        args.python_compiler = root / "mlc_win64.py"
    compilers: list[tuple[str, list[str]]] = []
    if args.python_compiler is not None:
        compilers.append(("python", [sys.executable, str(args.python_compiler.resolve())]))
    for index, compiler in enumerate(args.native_compiler):
        compilers.append((f"native-{index + 1}", [str(compiler.resolve())]))
    if not compilers:
        parser.error("specify --python-compiler or --native-compiler")
    pipelines = ("legacy", "object") if args.pipeline == "both" else (args.pipeline,)
    source = root / "tests" / "native_semantics_regression.ml"
    expected = source.with_suffix(".expected.txt").read_text(encoding="utf-8").splitlines()
    executions = 0
    with tempfile.TemporaryDirectory(prefix="minilang-native-semantics-") as temporary:
        output = args.output_dir.resolve() if args.output_dir else Path(temporary)
        output.mkdir(parents=True, exist_ok=True)
        all_digests: list[str] = []
        for pipeline in pipelines:
            hashes: list[str] = []
            flag = "--object-pipeline" if pipeline == "object" else "--no-object-pipeline"
            for name, compiler in compilers:
                extension = ".exe" if args.target == "windows-x64" else ""
                image = output / f"{name}-{args.target}-{pipeline}{extension}"
                command = [*compiler, str(source), str(image), "-I", str(root),
                           "--target", args.target, flag, *args.compiler_arg]
                run(command, cwd=root, timeout=300)
                digest = hashlib.sha256(image.read_bytes()).hexdigest()
                hashes.append(digest)
                all_digests.append(digest)
                if args.compile_only:
                    print(f"[COMPILED] {name} {args.target} {pipeline} sha256={digest}")
                    continue
                result = run(executable_command(image, args.target), cwd=output, timeout=180)
                if result.stdout.splitlines() != expected:
                    raise AssertionError(f"Unexpected output from {name} {pipeline}:\n{result.stdout}\n"
                                         f"Expected: {expected!r}\n{result.stderr}")
                executions += 1
                print(f"[OK] {name} {args.target} {pipeline}: native semantics; sha256={digest}")
            if len(set(hashes)) != 1:
                raise AssertionError(f"Compiler image mismatch: {args.target} {pipeline}")
        if len(set(all_digests)) != 1:
            raise AssertionError(f"Pipeline image mismatch: {args.target}")
    print(f"NATIVE SEMANTICS [OK]: {len(compilers) * len(pipelines)} images, "
          f"{executions} executions, exact byte parity")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
