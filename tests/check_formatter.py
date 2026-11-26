#!/usr/bin/env python3
"""Focused mlfmt regression runner for Python and self-hosted compilers.

Build both native targets, run whichever targets this host supports, and verify
exact fixture bytes, idempotence, runtime output and unchanged generated code.
Example: python tests/check_formatter.py --compiler ./mlc_win64.py
         python tests/check_formatter.py --compiler ./build/mlc-native
"""
from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from contextlib import nullcontext
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"


def checked(label: str, command: list[str], *, cwd: Path = ROOT) -> bytes:
    """Run a checked subprocess, retaining bytes for exact output comparisons."""
    result = subprocess.run(command, cwd=cwd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=240)
    if result.returncode:
        output = (result.stdout + result.stderr).decode("utf-8", "replace")
        raise AssertionError(f"{label} exited {result.returncode}:\n{output[-6000:]}")
    return result.stdout


def equal_bytes(label: str, actual: bytes, expected: bytes) -> None:
    """Show the first differing byte so whitespace failures are actionable."""
    if actual == expected:
        return
    at = next((i for i, pair in enumerate(zip(actual, expected)) if pair[0] != pair[1]),
              min(len(actual), len(expected)))
    raise AssertionError(f"{label} differs at byte {at}; expected {expected[at:at + 100]!r}, "
                         f"got {actual[at:at + 100]!r} (lengths {len(expected)} / {len(actual)})")


def fixture_cases() -> list[tuple[str, bytes, bytes, list[str], bytes]]:
    """Load independent goldens and construct explicit CRLF/blank-line cases."""
    # Normalize checkout EOL conversion before generating deliberate CRLF bytes.
    modern = (TESTS / "formatter_modern_input.ml").read_bytes().replace(b"\r\n", b"\n")
    modern_expected = (TESTS / "formatter_modern_expected.ml").read_bytes().replace(b"\r\n", b"\n")
    edges = (TESTS / "formatter_edges_input.ml").read_bytes().replace(b"\r\n", b"\n")
    edges_expected = (TESTS / "formatter_edges_expected.ml").read_bytes().replace(b"\r\n", b"\n")
    # Convert only the known literal-bearing region. Golden source comparison
    # must retain these CRLF bytes: compiler text readers may normalize them.
    start = edges.index(b's = "hello\n')
    end = edges.index(b'if len(s)', start)
    literal_region = edges[start:end]
    crlf_region = literal_region.replace(b"\n", b"\r\n")
    edges_crlf = edges.replace(literal_region, crlf_region, 1)
    expected_crlf = edges_expected.replace(literal_region, crlf_region, 1)
    assert edges_crlf != edges and expected_crlf != edges_expected
    # --max-blank applies to source layout, never to literal contents. Keep
    # this golden explicit rather than reimplementing the formatter in Python.
    blank_input = (b'function main(args)\n\n\n\ns = "hello\n\n\n\nworld"\n'
                   b'if len(s)!=14 then return 1 end if\n'
                   b'print "[OK] formatter blank lines"\nreturn 0\nend function\n')
    blank_expected = (b'function main(args)\ns = "hello\n\n\n\nworld"\n'
                      b'  if len(s) != 14 then return 1 end if\n'
                      b'  print "[OK] formatter blank lines"\n  return 0\nend function\n')
    return [
        ("modern", modern, modern_expected, [], b"[OK] formatter modern syntax"),
        ("edges", edges, edges_expected, [], b"[OK] formatter lexical edges"),
        ("literal-crlf", edges_crlf, expected_crlf, [], b"[OK] formatter lexical edges"),
        ("max-blank-zero", blank_input, blank_expected, ["--max-blank", "0"],
         b"[OK] formatter blank lines"),
    ]


def run_regressions(compiler: Path, artifacts: Path) -> None:
    """Build both targets and exercise every available native runtime."""
    wine = shutil.which("wine") or shutil.which("wine64")
    wsl = shutil.which("wsl.exe") if os.name == "nt" else None
    native_linux = sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64")
    available = {
        "windows-x64": os.name == "nt" or wine is not None,
        "linux-x64": native_linux or wsl is not None,
    }
    if not any(available.values()):
        raise AssertionError("No Windows/Wine or x64 Linux/WSL runtime is available")
    if compiler.suffix.lower() == ".py":
        compiler_command = [sys.executable, str(compiler)]
    elif compiler.read_bytes()[:2] == b"MZ" and os.name != "nt":
        if wine is None:
            raise AssertionError("The selected Windows compiler requires Wine; select a native compiler")
        compiler_command = [wine, str(compiler)]
    else:
        compiler_command = [str(compiler)]

    def build(source: Path, image: Path, target: str) -> None:
        checked(f"{target} build of {source.name}", compiler_command + [str(source), str(image),
                "-I", str(ROOT), "--target", target])
        magic = b"MZ" if target == "windows-x64" else b"\x7fELF"
        if not image.read_bytes().startswith(magic):
            raise AssertionError(f"{image.name} is not a {target} executable")

    def run(target: str, image: Path, args: list[str] | None = None) -> bytes:
        arguments = args or []
        if target == "windows-x64":
            command = [str(image)] if os.name == "nt" else [str(wine), str(image)]
        elif native_linux:
            image.chmod(image.stat().st_mode | 0o111)
            command = [str(image)]
        else:
            def wsl_path(path: str) -> str:
                return checked("WSL path conversion", [str(wsl), "wslpath", "-a", "-u",
                               path.replace("\\", "/")]).decode().strip()
            linux_image = wsl_path(str(image))
            checked("mark WSL executable", [str(wsl), "chmod", "+x", linux_image])
            command = [str(wsl), "timeout", "240s", linux_image]
            arguments = [wsl_path(arg) if Path(arg).is_absolute() else arg for arg in arguments]
        return checked(f"{target} execution of {image.name}", command + arguments, cwd=image.parent)

    formatters: dict[str, Path] = {}
    for target in available:
        image = artifacts / ("mlfmt.exe" if target == "windows-x64" else "mlfmt-linux")
        build(ROOT / "tools" / "mlfmt.ml", image, target)
        formatters[target] = image
        if not available[target]:
            print(f"[NOTE] {target} runtime unavailable; still checking builds and before/after image bytes.")
    primary = "linux-x64" if native_linux else "windows-x64"
    if not available[primary]:
        primary = next(target for target, supported in available.items() if supported)

    for name, original, expected, options, marker in fixture_cases():
        # Source line numbers are embedded in diagnostic code. Removing
        # layout-only blank lines may legitimately change executable bytes.
        preserve_lines = original.count(b"\n") == expected.count(b"\n")
        case_dir = artifacts / name
        case_dir.mkdir(parents=True, exist_ok=True)
        source = case_dir / "fixture.ml"
        source.write_bytes(original)
        before_images: dict[str, bytes] = {}
        before_output: dict[str, bytes] = {}
        for target, supported in available.items():
            image = case_dir / ("before.exe" if target == "windows-x64" else "before-linux")
            build(source, image, target)
            before_images[target] = image.read_bytes()
            if supported:
                before_output[target] = run(target, image)
                if marker not in before_output[target]:
                    raise AssertionError(f"{name}: {target} unformatted program omitted success marker")
        run(primary, formatters[primary], [str(source), "--inplace"] + options)
        equal_bytes(f"{name} golden source", source.read_bytes(), expected)
        run(primary, formatters[primary], [str(source), "--inplace"] + options)
        equal_bytes(f"{name} idempotence", source.read_bytes(), expected)
        for target, supported in available.items():
            image = case_dir / ("after.exe" if target == "windows-x64" else "after-linux")
            build(source, image, target)
            if preserve_lines:
                equal_bytes(f"{name} {target} executable", image.read_bytes(), before_images[target])
            if supported:
                equal_bytes(f"{name} {target} runtime output", run(target, image), before_output[target])
            if supported and target != primary:
                alternate = case_dir / "alternate.ml"
                alternate.write_bytes(original)
                run(target, formatters[target], [str(alternate), "--inplace"] + options)
                equal_bytes(f"{name} {target} formatter parity", alternate.read_bytes(), expected)
                run(target, formatters[target], [str(alternate), "--inplace"] + options)
                equal_bytes(f"{name} {target} formatter idempotence", alternate.read_bytes(), expected)
        image_check = "image parity" if preserve_lines else "builds (source line numbers changed)"
        print(f"[OK] {name}: exact source, idempotence, runtime output and PE/ELF {image_check}")

    # Directory mode must discover nested sources and use the same formatter.
    for target, supported in available.items():
        if not supported:
            continue
        tree = artifacts / ("tree-" + target)
        nested = tree / "nested" / "tree.ml"
        nested.parent.mkdir(parents=True, exist_ok=True)
        nested.write_bytes(b'function main(args)\nif true then\nprint "tree"\nend if\nreturn 0\nend function\n')
        run(target, formatters[target], [str(tree)])
        equal_bytes(f"{target} directory recursion", nested.read_bytes(),
                    b'function main(args)\n  if true then\n    print "tree"\n  end if\n  return 0\nend function\n')
        print(f"[OK] {target}: recursive directory formatting")


def main() -> int:
    """Accept either compiler and optionally retain reproducible failure artifacts."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", type=Path, required=True,
                        help="Python compiler script or native self-hosted compiler executable")
    parser.add_argument("--artifacts-dir", type=Path,
                        help="retain build artifacts in this directory for diagnosis")
    args = parser.parse_args()
    compiler = args.compiler.resolve()
    if not compiler.is_file():
        parser.error(f"compiler does not exist: {compiler}")
    context = (nullcontext(str(args.artifacts_dir.resolve())) if args.artifacts_dir
               else tempfile.TemporaryDirectory(prefix="minilang-formatter-"))
    try:
        with context as folder:
            artifacts = Path(folder)
            artifacts.mkdir(parents=True, exist_ok=True)
            run_regressions(compiler, artifacts)
    except (AssertionError, OSError, subprocess.TimeoutExpired) as error:
        print(f"[FAIL] formatter: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
