#!/usr/bin/env python3
"""MiniLang unified test suite.

Runs (in one command):
  - language_suite.ml (full language suite)
  - aes128_ecb_nist_kat.ml (AES-128 ECB NIST KAT)
  - namespace/import tests (existing framework if present)
  - import loader tests (cycles/self-import + declaration-only enforcement)

Default backend: native Win64 compiler + run produced .exe.

Usage:
  python run_tests.py

Options:
  --allow-skip   Exit 0 even if some tests were skipped (e.g. cannot run .exe).
  --verbose      Print full stdout/stderr for each test.
  --only PAT     Only run tests whose name contains PAT.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

# -----------------------------
# Console colors (PASS/FAIL)
# -----------------------------


ANSI_RESET = "\x1b[0m"
ANSI_RED = "\x1b[31m"
ANSI_GREEN = "\x1b[32m"
ANSI_YELLOW = "\x1b[33m"


def _enable_windows_vt_mode() -> None:
    """Enable ANSI escape sequences on Windows consoles (best-effort)."""
    if os.name != "nt":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        STD_OUTPUT_HANDLE = -11
        STD_ERROR_HANDLE = -12

        for h in (STD_OUTPUT_HANDLE, STD_ERROR_HANDLE):
            handle = kernel32.GetStdHandle(h)
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)) == 0:
                continue
            kernel32.SetConsoleMode(handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING)
    except Exception:
        # If anything goes wrong, we just fall back to plain output.
        return


def _use_color() -> bool:
    """Return True if colored console output should be used.

    Color is disabled when output is not a TTY or when NO_COLOR is set.
    """
    if os.environ.get("NO_COLOR") is not None:
        return False
    # When output is redirected, don't emit control characters.
    if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
        return False
    return True


def _c(text: str, color: str, enabled: bool) -> str:
    """Wrap a string with an ANSI color sequence (if enabled).

    Args:
        text: Text to colorize.
        color: ANSI color escape sequence.
        enabled: Whether coloring is enabled.

    Returns:
        The colored text, or the original text if coloring is disabled."""
    if not enabled:
        return text
    return f"{color}{text}{ANSI_RESET}"


# -----------------------------
# Small runner utilities
# -----------------------------


@dataclass
class CmdResult:
    """Result of executing a command in the test harness.

    Attributes:
        cmd: Full command (argv) that was executed.
        returncode: Process exit code.
        stdout: Captured stdout.
        stderr: Captured stderr.
    """
    cmd: list[str]
    returncode: int
    stdout: str
    stderr: str


def run_cmd(cmd: list[str], *, cwd: Optional[Path] = None, timeout_s: int = 120) -> CmdResult:
    """Run a subprocess command and capture its output.

    Args:
        cmd: Command and arguments.
        cwd: Optional working directory.
        timeout_s: Optional timeout in seconds.

    Returns:
        CmdResult containing exit code, stdout and stderr."""
    p = subprocess.run(cmd, cwd=str(cwd) if cwd is not None else None, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       text=True, encoding="utf-8", errors="replace", timeout=timeout_s, )
    return CmdResult(cmd=cmd, returncode=p.returncode, stdout=p.stdout, stderr=p.stderr)


def is_windows() -> bool:
    """Return True if running on Windows."""
    return os.name == "nt"


def find_wine() -> Optional[str]:
    """Locate a wine executable on non-Windows systems (if available).

    Returns:
        Path to wine executable or None if not found."""
    return shutil.which("wine")


def can_run_windows_exe() -> tuple[bool, str]:
    """Return True if the current system can execute Windows .exe files.

    On Windows this is always True. On non-Windows, checks for Wine."""
    if is_windows():
        return True, "native"
    w = find_wine()
    if w:
        return True, "wine"
    return False, ""


def tail(s: str, max_lines: int = 80) -> str:
    """Return the last N lines of a text blob.

    Args:
        text: Input text.
        n: Number of lines.

    Returns:
        Tail of the text (joined by newlines)."""
    lines = s.splitlines()
    if len(lines) <= max_lines:
        return s
    return "\n".join(lines[-max_lines:])


def normalize_out(s: str) -> str:
    """Normalize command output for stable comparisons.

    Converts line endings and may trim volatile parts (paths) to keep tests deterministic."""
    # Normalize newlines across Windows/Linux.
    return s.replace("\r\n", "\n").replace("\r", "\n")


# -----------------------------
# Test abstractions
# -----------------------------


@dataclass
class TestResult:
    """Result of a single test.

    Attributes:
        name: Display name.
        ok: True if PASS.
        skipped: True if skipped.
        message: Short summary.
        details: Optional verbose output (e.g. tail of stdout/stderr)."""
    name: str
    status: str  # PASS | FAIL | SKIP
    details: str = ""
    stdout: str = ""
    stderr: str = ""


def find_file_by_name(root: Path, filename: str) -> Optional[Path]:
    """Search recursively for a file with a given name.

    Args:
        root: Root directory to search.
        filename: File name to match.

    Returns:
        Path to the first matching file.

    Raises:
        FileNotFoundError: If no file is found."""
    # Prefer direct hit.
    direct = root / filename
    if direct.exists():
        return direct
    # Otherwise, search.
    hits = list(root.rglob(filename))
    if len(hits) == 1:
        return hits[0]
    # If multiple, pick the shortest path (closest to root).
    if hits:
        hits.sort(key=lambda p: len(p.parts))
        return hits[0]
    return None


def find_ml_containing(root: Path, needle: str) -> Optional[Path]:
    """Find a .ml file containing a given substring.

    Args:
        root: Root directory to search.
        needle: Substring to look for.

    Returns:
        Path to the first matching .ml file, or None if no match is found."""
    for p in root.rglob("*.ml"):
        try:
            txt = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if needle in txt:
            return p
    return None


def locate_mlc_runner(root: Path) -> Optional[Path]:
    """Locate the MiniLang compiler runner script (mlc_win64.py).

    Args:
        root: Project root directory.

    Returns:
        Path to the runner script, or None if it cannot be found."""
    # Default project entrypoint.
    cand = root / "mlc_win64.py"
    if cand.exists():
        return cand
    # Some repos put tools in subfolders.
    cand2 = root / "tools" / "mlc_win64.py"
    if cand2.exists():
        return cand2
    return None


# -----------------------------
# Native compiler helpers
# -----------------------------


def compile_native(mlc_runner: Path, input_ml: Path, output_exe: Path, *, extra_args: Optional[list[str]] = None,
                   timeout_s: int = 180) -> CmdResult:
    """Compile a MiniLang source file to a native Windows x64 executable.

    Args:
        mlc_runner: Path to the compiler runner script (mlc_win64.py).
        input_ml: Path to the input .ml file.
        output_exe: Output executable path.
        extra_args: Optional extra CLI args forwarded to the compiler.
        timeout_s: Timeout in seconds for the compile step.

    Returns:
        CmdResult from the compiler invocation.
    """
    extra = extra_args or []
    # Always include project root as an import path so tests can `import std.*` from anywhere.
    root_inc = str(mlc_runner.parent.resolve())
    extra = ["-I", root_inc] + extra
    cmd = [sys.executable, str(mlc_runner), str(input_ml), str(output_exe)] + extra
    return run_cmd(cmd, cwd=mlc_runner.parent, timeout_s=timeout_s)


def run_exe(exe_path: Path, *, exe_args: Optional[list[str]] = None, timeout_s: int = 180) -> CmdResult:
    """Run a compiled executable and capture its output.

    Args:
        exe_path: Path to the executable.
        exe_args: Optional list of command-line arguments.
        timeout_s: Timeout in seconds for the run step.

    Returns:
        CmdResult containing exit code, stdout and stderr.
    """
    ok, mode = can_run_windows_exe()
    if not ok:
        return CmdResult(cmd=[str(exe_path)], returncode=999, stdout="",
                         stderr="Cannot run Windows .exe (not Windows, and wine not found).")

    args = exe_args or []
    if mode == "native":
        cmd = [str(exe_path)] + args
    else:
        cmd = [find_wine() or "wine", str(exe_path)] + args
    return run_cmd(cmd, cwd=exe_path.parent, timeout_s=timeout_s)


# -----------------------------
# Individual tests
# -----------------------------


def test_program_no_fail(*, name: str, mlc_runner: Path, ml_path: Path, must_contain: list[str],
                         timeout_compile_s: int = 240, timeout_run_s: int = 240, extra_args: Optional[list[str]] = None, ) -> TestResult:
    """Compile and run the full language suite program.

    Returns:
        TestResult indicating PASS/FAIL/SKIP."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        exe = td_path / (ml_path.stem + ".exe")

        cr = compile_native(mlc_runner, ml_path, exe, timeout_s=timeout_compile_s, extra_args=extra_args)
        if cr.returncode != 0:
            return TestResult(name=name, status="FAIL", details=f"compile failed (exit {cr.returncode})",
                              stdout=cr.stdout, stderr=cr.stderr, )

        rr = run_exe(exe, timeout_s=timeout_run_s)
        if rr.returncode == 999:
            return TestResult(name=name, status="SKIP", details=rr.stderr, stdout=cr.stdout, stderr=rr.stderr)
        if rr.returncode != 0:
            return TestResult(name=name, status="FAIL", details=f"runtime failed (exit {rr.returncode})",
                              stdout=rr.stdout, stderr=rr.stderr, )

        out = normalize_out(rr.stdout)
        if "[FAIL]" in out:
            return TestResult(name=name, status="FAIL", details="program printed at least one [FAIL]", stdout=rr.stdout,
                              stderr=rr.stderr, )

        for m in must_contain:
            if m not in out:
                return TestResult(name=name, status="FAIL", details=f"missing expected output marker: {m!r}",
                                  stdout=rr.stdout, stderr=rr.stderr, )

        # Sanity: ensure tests actually executed.
        if "[OK]" not in out:
            return TestResult(name=name, status="FAIL", details="no [OK] markers found (did the test program run?)",
                              stdout=rr.stdout, stderr=rr.stderr, )

        return TestResult(name=name, status="PASS", stdout=rr.stdout, stderr=rr.stderr)


def test_program_expect_exit(*, name: str, mlc_runner: Path, ml_path: Path, expected_exit: int, must_contain: list[str],
                             timeout_compile_s: int = 240, timeout_run_s: int = 240,
                             extra_args: Optional[list[str]] = None, ) -> TestResult:
    """Compile & run a program and assert a specific process exit code and output markers.

    Args:
        extra_args: Optional extra CLI args forwarded to the compiler.
    """
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        exe = td_path / (ml_path.stem + ".exe")

        cr = compile_native(mlc_runner, ml_path, exe, timeout_s=timeout_compile_s, extra_args=extra_args)
        if cr.returncode != 0:
            return TestResult(name=name, status="FAIL", details=f"compile failed (exit {cr.returncode})",
                              stdout=cr.stdout, stderr=cr.stderr, )

        rr = run_exe(exe, timeout_s=timeout_run_s)
        if rr.returncode == 999:
            return TestResult(name=name, status="SKIP", details=rr.stderr, stdout=cr.stdout, stderr=rr.stderr)

        out = normalize_out(rr.stdout)
        if rr.returncode != int(expected_exit):
            return TestResult(name=name, status="FAIL", details=f"expected exit {expected_exit}, got {rr.returncode}",
                              stdout=rr.stdout, stderr=rr.stderr, )

        for m in must_contain:
            if m not in out:
                return TestResult(name=name, status="FAIL", details=f"missing expected output marker: {m!r}",
                                  stdout=rr.stdout, stderr=rr.stderr, )

        return TestResult(name=name, status="PASS", stdout=rr.stdout, stderr=rr.stderr)


def test_aes_kat(*, name: str, mlc_runner: Path, aes_ml: Path) -> TestResult:
    """Compile and run the AES-128 ECB NIST KAT program.

    Returns:
        TestResult indicating PASS/FAIL/SKIP."""
    expected_pt = "00112233445566778899aabbccddeeff"
    expected_ct = "69c4e0d86a7b0430d8cdb78070b4c55a"

    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        exe = td_path / "aes.exe"

        cr = compile_native(mlc_runner, aes_ml, exe, timeout_s=240)
        if cr.returncode != 0:
            return TestResult(name=name, status="FAIL", details=f"compile failed (exit {cr.returncode})",
                              stdout=cr.stdout, stderr=cr.stderr)

        rr = run_exe(exe, timeout_s=240)
        if rr.returncode == 999:
            return TestResult(name=name, status="SKIP", details=rr.stderr, stdout=cr.stdout, stderr=rr.stderr)
        if rr.returncode != 0:
            return TestResult(name=name, status="FAIL", details=f"runtime failed (exit {rr.returncode})",
                              stdout=rr.stdout, stderr=rr.stderr)

        out = normalize_out(rr.stdout)

        # Extract ct/dt lines.
        m_ct = re.search(r"^ct\s*=\s*([0-9a-fA-F]+)\s*$", out, flags=re.MULTILINE)
        m_dt = re.search(r"^dt\s*=\s*([0-9a-fA-F]+)\s*$", out, flags=re.MULTILINE)
        if not m_ct:
            return TestResult(name=name, status="FAIL", details="missing 'ct = ...' line", stdout=rr.stdout,
                              stderr=rr.stderr)
        if not m_dt:
            return TestResult(name=name, status="FAIL", details="missing 'dt = ...' line", stdout=rr.stdout,
                              stderr=rr.stderr)

        ct = m_ct.group(1).lower()
        dt = m_dt.group(1).lower()

        if ct != expected_ct:
            return TestResult(name=name, status="FAIL",
                              details=f"ciphertext mismatch\n  expected: {expected_ct}\n  got:      {ct}",
                              stdout=rr.stdout, stderr=rr.stderr, )
        if dt != expected_pt:
            return TestResult(name=name, status="FAIL",
                              details=f"decrypt mismatch\n  expected: {expected_pt}\n  got:      {dt}",
                              stdout=rr.stdout, stderr=rr.stderr, )

        return TestResult(name=name, status="PASS", stdout=rr.stdout, stderr=rr.stderr)


def test_unhandled_error_top_level(*, name: str, mlc_runner: Path) -> TestResult:
    """Unhandled error at top-level should abort with exit code 1 and print the error."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        ml_path = td_path / "unhandled_top.ml"
        ml_path.write_text("\n".join(
            ['print "=== UNHANDLED ERROR TOP ==="', 'function boom()', '  return error(7, "boom")', 'end function',
             'boom()', 'print "SHOULD NOT REACH"', ]) + "\n", encoding="utf-8", )
        return test_program_expect_exit(name=name, mlc_runner=mlc_runner, ml_path=ml_path, expected_exit=1,
                                        must_contain=["=== UNHANDLED ERROR TOP ===",
                                                      "Error occured: no=7 message=boom", ], timeout_compile_s=180,
                                        timeout_run_s=180, )


def test_unhandled_error_main_return(*, name: str, mlc_runner: Path) -> TestResult:
    """If main(args) returns an error, it should be treated as unhandled and abort."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        ml_path = td_path / "unhandled_main.ml"
        ml_path.write_text("\n".join(
            ['print "=== UNHANDLED ERROR MAIN ==="', 'function main(args)', '  return error(9, "boom main")',
             'end function', ]) + "\n", encoding="utf-8", )
        return test_program_expect_exit(name=name, mlc_runner=mlc_runner, ml_path=ml_path, expected_exit=1,
                                        must_contain=["=== UNHANDLED ERROR MAIN ===",
                                                      "Error occured: no=9 message=boom main", ], timeout_compile_s=180,
                                        timeout_run_s=180, )


def test_unhandled_error_origin_top_level(*, name: str, mlc_runner: Path) -> TestResult:
    """Unhandled error should include callsite origin: script/line/func."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        ml_path = td_path / "unhandled_origin_top.ml"
        # Keep the error call on a stable, known line for the assertion below.
        lines = [
            'print "=== UNHANDLED ORIGIN TOP ==="',
            'function boom()',
            '  x = 123',
            '  return error(7, "boom")',
            'end function',
            'boom()',
        ]
        ml_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        exe = td_path / "unhandled_origin_top.exe"
        cr = compile_native(mlc_runner, ml_path, exe, timeout_s=180)
        if cr.returncode != 0:
            return TestResult(name=name, status="FAIL", details=f"compile failed (exit {cr.returncode})",
                              stdout=cr.stdout, stderr=cr.stderr)

        rr = run_exe(exe, timeout_s=180)
        if rr.returncode == 999:
            return TestResult(name=name, status="SKIP", details=rr.stderr, stdout=cr.stdout, stderr=rr.stderr)

        out = normalize_out(rr.stdout)
        if rr.returncode != 1:
            return TestResult(name=name, status="FAIL", details=f"expected exit 1, got {rr.returncode}",
                              stdout=rr.stdout, stderr=rr.stderr)

        # Must include the base error line.
        for m in ["=== UNHANDLED ORIGIN TOP ===", "Error occured: no=7 message=boom"]:
            if m not in out:
                return TestResult(name=name, status="FAIL", details=f"missing expected output marker: {m!r}",
                                  stdout=rr.stdout, stderr=rr.stderr)

        # And must include an origin line. The script can be absolute, so match by basename.
        expected_line = 4  # 'return error(...)' line above (1-based)
        pat = rf"^\s*at .*unhandled_origin_top\.ml:{expected_line} in boom\s*$"
        if not re.search(pat, out, flags=re.MULTILINE):
            return TestResult(name=name, status="FAIL",
                              details=f"missing/invalid origin line (expected pattern: {pat})",
                              stdout=rr.stdout, stderr=rr.stderr)

        return TestResult(name=name, status="PASS", stdout=rr.stdout, stderr=rr.stderr)


def test_unhandled_error_origin_main_return(*, name: str, mlc_runner: Path) -> TestResult:
    """If main(args) returns an error, the origin should point at the return site inside main."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        ml_path = td_path / "unhandled_origin_main.ml"
        lines = [
            'print "=== UNHANDLED ORIGIN MAIN ==="',
            'function main(args)',
            '  a = 1',
            '  return error(9, "boom main")',
            'end function',
        ]
        ml_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        exe = td_path / "unhandled_origin_main.exe"
        cr = compile_native(mlc_runner, ml_path, exe, timeout_s=180)
        if cr.returncode != 0:
            return TestResult(name=name, status="FAIL", details=f"compile failed (exit {cr.returncode})",
                              stdout=cr.stdout, stderr=cr.stderr)

        rr = run_exe(exe, timeout_s=180)
        if rr.returncode == 999:
            return TestResult(name=name, status="SKIP", details=rr.stderr, stdout=cr.stdout, stderr=rr.stderr)

        out = normalize_out(rr.stdout)
        if rr.returncode != 1:
            return TestResult(name=name, status="FAIL", details=f"expected exit 1, got {rr.returncode}",
                              stdout=rr.stdout, stderr=rr.stderr)

        for m in ["=== UNHANDLED ORIGIN MAIN ===", "Error occured: no=9 message=boom main"]:
            if m not in out:
                return TestResult(name=name, status="FAIL", details=f"missing expected output marker: {m!r}",
                                  stdout=rr.stdout, stderr=rr.stderr)

        expected_line = 4  # 'return error(...)' line above (1-based)
        pat = rf"^\s*at .*unhandled_origin_main\.ml:{expected_line} in main\s*$"
        if not re.search(pat, out, flags=re.MULTILINE):
            return TestResult(name=name, status="FAIL",
                              details=f"missing/invalid origin line (expected pattern: {pat})",
                              stdout=rr.stdout, stderr=rr.stderr)

        return TestResult(name=name, status="PASS", stdout=rr.stdout, stderr=rr.stderr)


def test_unhandled_error_origin_omitted_when_cleared(*, name: str, mlc_runner: Path) -> TestResult:
    """If user code clears origin fields, the runtime must not print an empty/partial 'at' line."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        ml_path = td_path / "unhandled_origin_cleared.ml"
        lines = [
            'print "=== UNHANDLED ORIGIN CLEARED ==="',
            'function boom()',
            '  e = error(11, "boom cleared")',
            '  e.script = ""',
            '  e.func = ""',
            '  e.line = 0',
            '  return e',
            'end function',
            'boom()',
        ]
        ml_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        exe = td_path / "unhandled_origin_cleared.exe"
        cr = compile_native(mlc_runner, ml_path, exe, timeout_s=180)
        if cr.returncode != 0:
            return TestResult(name=name, status="FAIL", details=f"compile failed (exit {cr.returncode})",
                              stdout=cr.stdout, stderr=cr.stderr)

        rr = run_exe(exe, timeout_s=180)
        if rr.returncode == 999:
            return TestResult(name=name, status="SKIP", details=rr.stderr, stdout=cr.stdout, stderr=rr.stderr)

        out = normalize_out(rr.stdout)
        if rr.returncode != 1:
            return TestResult(name=name, status="FAIL", details=f"expected exit 1, got {rr.returncode}",
                              stdout=rr.stdout, stderr=rr.stderr)

        for m in ["=== UNHANDLED ORIGIN CLEARED ===", "Error occured: no=11 message=boom cleared"]:
            if m not in out:
                return TestResult(name=name, status="FAIL", details=f"missing expected output marker: {m!r}",
                                  stdout=rr.stdout, stderr=rr.stderr)

        # Ensure we do NOT print a dangling/empty location line.
        if re.search(r"^\s*at\s*$", out, flags=re.MULTILINE) or "  at " in out:
            return TestResult(name=name, status="FAIL", details="unexpected origin line printed", stdout=rr.stdout,
                              stderr=rr.stderr)

        return TestResult(name=name, status="PASS", stdout=rr.stdout, stderr=rr.stderr)


def test_reserved_identifiers(*, name: str, mlc_runner: Path) -> TestResult:
    """Identifiers 'try' and 'error' must be reserved across declarations and bindings."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        bad = td_path / "reserved_ident.ml"
        bad.write_text("\n".join([  # function name
            'function try(a)', '  return a', 'end function', '', 'function main(args)', '  x = 1', '  error = 2',
            '  return 0', 'end function', ]) + "\n", encoding="utf-8", )

        exe = td_path / "reserved_ident.exe"
        cr = compile_native(mlc_runner, bad, exe, timeout_s=180)
        if cr.returncode == 0:
            return TestResult(name=name, status="FAIL", details="expected compile failure, but compile succeeded",
                              stdout=cr.stdout, stderr=cr.stderr)

        out = (cr.stdout or "") + "\n" + (cr.stderr or "")
        if "reserved" not in out.lower():
            return TestResult(name=name, status="FAIL",
                              details="compile failed, but message did not mention 'reserved'", stdout=cr.stdout,
                              stderr=cr.stderr, )

        return TestResult(name=name, status="PASS", stdout=cr.stdout, stderr=cr.stderr)


def test_keep_going_reports_multiple_errors(*, name: str, mlc_runner: Path) -> TestResult:
    """--keep-going should continue after the first error and report multiple diagnostics.

    We validate this by creating a tiny import graph with two independently-broken imported
    modules. Without --keep-going, the compiler should stop at the first error. With
    --keep-going, it should print errors for *both* broken modules.
    """
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)

        lib1 = td_path / "lib_bad1.ml"
        lib2 = td_path / "lib_bad2.ml"

        # Top-level statements in imported modules are forbidden (declaration-only enforcement).
        lib1.write_text("\n".join([
            'print "BAD1"',
            'function f1()',
            '  return 1',
            'end function',
        ]) + "\n", encoding="utf-8")

        lib2.write_text("\n".join([
            'print "BAD2"',
            'function f2()',
            '  return 2',
            'end function',
        ]) + "\n", encoding="utf-8")

        main_ml = td_path / "main_keepgoing.ml"
        lib1_abs = str(lib1.resolve()).replace("\\", "\\\\")
        lib2_abs = str(lib2.resolve()).replace("\\", "\\\\")
        main_ml.write_text("\n".join([
            f'import "{lib1_abs}"',
            f'import "{lib2_abs}"',
            '',
            'function main(args)',
            '  return 0',
            'end function',
        ]) + "\n", encoding="utf-8")

        exe = td_path / "main_keepgoing.exe"

        # Baseline: should fail and typically only report the *first* module error.
        cr1 = compile_native(mlc_runner, main_ml, exe, timeout_s=120)
        out1 = normalize_out((cr1.stdout or "") + "\n" + (cr1.stderr or ""))
        if cr1.returncode == 0:
            return TestResult(name=name, status="FAIL",
                              details="expected compile failure without --keep-going, but compile succeeded",
                              stdout=cr1.stdout, stderr=cr1.stderr)
        if "Imported module must be declaration-only" not in out1:
            return TestResult(name=name, status="FAIL",
                              details="missing expected error marker without --keep-going",
                              stdout=cr1.stdout, stderr=cr1.stderr)
        if "lib_bad1.ml" not in out1:
            return TestResult(name=name, status="FAIL",
                              details="expected first broken module to be mentioned (lib_bad1.ml)",
                              stdout=cr1.stdout, stderr=cr1.stderr)

        # Now: keep-going should report errors for *both* broken modules.
        cr2 = compile_native(mlc_runner, main_ml, exe, timeout_s=120,
                             extra_args=["--keep-going", "--max-errors", "50"])
        out2 = normalize_out((cr2.stdout or "") + "\n" + (cr2.stderr or ""))
        if cr2.returncode == 0:
            return TestResult(name=name, status="FAIL",
                              details="expected compile failure with --keep-going, but compile succeeded",
                              stdout=cr2.stdout, stderr=cr2.stderr)
        if "Imported module must be declaration-only" not in out2:
            return TestResult(name=name, status="FAIL",
                              details="missing expected error marker with --keep-going",
                              stdout=cr2.stdout, stderr=cr2.stderr)
        if "lib_bad1.ml" not in out2 or "lib_bad2.ml" not in out2:
            return TestResult(name=name, status="FAIL",
                              details="--keep-going did not report both module errors (expected lib_bad1.ml + lib_bad2.ml)",
                              stdout=cr2.stdout, stderr=cr2.stderr)

        return TestResult(name=name, status="PASS", stdout=cr2.stdout, stderr=cr2.stderr)


def test_keep_going_respects_max_errors(*, name: str, mlc_runner: Path) -> TestResult:
    """--max-errors should cap the number of diagnostics reported when using --keep-going."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)

        libs: list[Path] = []
        for i in range(1, 6):
            p = td_path / f"lib_bad_{i}.ml"
            p.write_text("\n".join([
                f'print "BAD{i}"',
                f'function f{i}()',
                f'  return {i}',
                'end function',
            ]) + "\n", encoding="utf-8")
            libs.append(p)

        main_ml = td_path / "main_keepgoing_max.ml"
        imports = []
        for p in libs:
            pa = str(p.resolve()).replace("\\", "\\\\")
            imports.append(f'import "{pa}"')
        main_ml.write_text("\n".join(imports + [
            '',
            'function main(args)',
            '  return 0',
            'end function',
        ]) + "\n", encoding="utf-8")

        exe = td_path / "main_keepgoing_max.exe"
        cr = compile_native(mlc_runner, main_ml, exe, timeout_s=120,
                            extra_args=["--keep-going", "--max-errors", "2"])
        out = normalize_out((cr.stdout or "") + "\n" + (cr.stderr or ""))
        if cr.returncode == 0:
            return TestResult(name=name, status="FAIL",
                              details="expected compile failure with --keep-going, but compile succeeded",
                              stdout=cr.stdout, stderr=cr.stderr)

        # Count how many times the specific marker appears; it should not exceed 2.
        n = len(re.findall(r"Imported module must be declaration-only", out))
        if n == 0:
            return TestResult(name=name, status="FAIL",
                              details="missing expected error marker with --keep-going",
                              stdout=cr.stdout, stderr=cr.stderr)
        if n > 2:
            return TestResult(name=name, status="FAIL",
                              details=f"expected <= 2 diagnostics due to --max-errors 2, but saw {n}",
                              stdout=cr.stdout, stderr=cr.stderr)

        return TestResult(name=name, status="PASS", stdout=cr.stdout, stderr=cr.stderr)


def test_package_basic(*, name: str, mlc_runner: Path) -> TestResult:
    """Basic `package X` smoke test (compile-time qualification in native compiler)."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)

        lib = td_path / "geom_pkg.ml"
        lib.write_text("\n".join(["package geom", "", "function add(a, b)", "  return a + b", "end function", ]) + "\n",
                       encoding="utf-8", )

        main_ml = td_path / "main_pkg.ml"
        lib_abs = str(lib.resolve()).replace("\\", "\\\\")
        main_ml.write_text("\n".join(
            [f'import "{lib_abs}"', "", "import std.assert as t", "", "function assertEq(actual, expected, label)",
             "  return t.assertEq(actual, expected, label)", "end function", "", "print \"=== PACKAGE BASIC ===\"",
             "assertEq(geom.add(2, 3), 5, \"geom.add\")", "print \"=== DONE ===\"", ]) + "\n", encoding="utf-8", )

        exe = td_path / "main_pkg.exe"
        cr = compile_native(mlc_runner, main_ml, exe, timeout_s=180)
        if cr.returncode != 0:
            return TestResult(name=name, status="FAIL", details=f"compile failed (exit {cr.returncode})",
                              stdout=cr.stdout, stderr=cr.stderr, )

        rr = run_exe(exe, timeout_s=180)
        if rr.returncode == 999:
            return TestResult(name=name, status="SKIP", details=rr.stderr, stdout=cr.stdout, stderr=rr.stderr)
        if rr.returncode != 0:
            return TestResult(name=name, status="FAIL", details=f"runtime failed (exit {rr.returncode})",
                              stdout=rr.stdout, stderr=rr.stderr, )

        out = normalize_out(rr.stdout)
        if "[FAIL]" in out:
            return TestResult(name=name, status="FAIL", details="program printed at least one [FAIL]", stdout=rr.stdout,
                              stderr=rr.stderr, )
        if "=== PACKAGE BASIC ===" not in out or "=== DONE ===" not in out or "[OK]" not in out:
            return TestResult(name=name, status="FAIL", details="missing expected output markers", stdout=rr.stdout,
                              stderr=rr.stderr, )

        return TestResult(name=name, status="PASS", stdout=rr.stdout, stderr=rr.stderr)


def test_package_dotted(*, name: str, mlc_runner: Path) -> TestResult:
    """`package a.b` qualifies declarations as `a.b.*`."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)

        lib = td_path / "geom_vec_pkg.ml"
        lib.write_text(
            "\n".join(["package geom.vec", "", "function add(a, b)", "  return a + b", "end function", ]) + "\n",
            encoding="utf-8", )

        main_ml = td_path / "main_pkg_dotted.ml"
        lib_abs = str(lib.resolve()).replace("\\", "\\\\")
        main_ml.write_text("\n".join(
            [f'import "{lib_abs}"', "", "import std.assert as t", "", "function assertEq(actual, expected, label)",
             "  return t.assertEq(actual, expected, label)", "end function", "", "print \"=== PACKAGE DOTTED ===\"",
             "assertEq(geom.vec.add(2, 3), 5, \"geom.vec.add\")", "print \"=== DONE ===\"", ]) + "\n",
                           encoding="utf-8", )

        exe = td_path / "main_pkg_dotted.exe"
        cr = compile_native(mlc_runner, main_ml, exe, timeout_s=180)
        if cr.returncode != 0:
            return TestResult(name=name, status="FAIL", details=f"compile failed (exit {cr.returncode})",
                              stdout=cr.stdout, stderr=cr.stderr, )

        rr = run_exe(exe, timeout_s=180)
        if rr.returncode == 999:
            return TestResult(name=name, status="SKIP", details=rr.stderr, stdout=cr.stdout, stderr=rr.stderr)
        if rr.returncode != 0:
            return TestResult(name=name, status="FAIL", details=f"runtime failed (exit {rr.returncode})",
                              stdout=rr.stdout, stderr=rr.stderr, )

        out = normalize_out(rr.stdout)
        if "[FAIL]" in out:
            return TestResult(name=name, status="FAIL", details="program printed at least one [FAIL]", stdout=rr.stdout,
                              stderr=rr.stderr, )
        if "=== PACKAGE DOTTED ===" not in out or "=== DONE ===" not in out or "[OK]" not in out:
            return TestResult(name=name, status="FAIL", details="missing expected output markers", stdout=rr.stdout,
                              stderr=rr.stderr, )

        return TestResult(name=name, status="PASS", stdout=rr.stdout, stderr=rr.stderr)


def test_import_as_alias(*, name: str, mlc_runner: Path) -> TestResult:
    """`import "file.ml" as alias` should allow using alias.* for the imported package."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)

        lib = td_path / "geom_alias.ml"
        lib.write_text(
            "\n".join(["package geom.vec", "", "function add(a, b)", "  return a + b", "end function", ]) + "\n",
            encoding="utf-8", )

        main_ml = td_path / "main_import_as.ml"
        lib_abs = str(lib.resolve()).replace("\\", "\\\\")
        main_ml.write_text("\n".join(
            [f'import "{lib_abs}" as g', "", "import std.assert as t", "", "function assertEq(actual, expected, label)",
             "  return t.assertEq(actual, expected, label)", "end function", "", "print \"=== IMPORT AS ===\"",
             "assertEq(g.add(2, 3), 5, \"g.add\")", "print \"=== DONE ===\"", ]) + "\n", encoding="utf-8", )

        exe = td_path / "main_import_as.exe"
        cr = compile_native(mlc_runner, main_ml, exe, timeout_s=180)
        if cr.returncode != 0:
            return TestResult(name=name, status="FAIL", details=f"compile failed (exit {cr.returncode})",
                              stdout=cr.stdout, stderr=cr.stderr, )

        rr = run_exe(exe, timeout_s=180)
        if rr.returncode == 999:
            return TestResult(name=name, status="SKIP", details=rr.stderr, stdout=cr.stdout, stderr=rr.stderr)
        if rr.returncode != 0:
            return TestResult(name=name, status="FAIL", details=f"runtime failed (exit {rr.returncode})",
                              stdout=rr.stdout, stderr=rr.stderr, )

        out = normalize_out(rr.stdout)
        if "[FAIL]" in out:
            return TestResult(name=name, status="FAIL", details="program printed at least one [FAIL]", stdout=rr.stdout,
                              stderr=rr.stderr, )
        if "=== IMPORT AS ===" not in out or "=== DONE ===" not in out or "[OK]" not in out:
            return TestResult(name=name, status="FAIL", details="missing expected output markers", stdout=rr.stdout,
                              stderr=rr.stderr, )

        return TestResult(name=name, status="PASS", stdout=rr.stdout, stderr=rr.stderr)


def test_import_module_package_mismatch(*, name: str, mlc_runner: Path) -> TestResult:
    """`import foo.bar` should reject a file that declares a different `package`. (compile-time only)"""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)

        pkg_dir = td_path / "foo"
        pkg_dir.mkdir(parents=True, exist_ok=True)

        lib = pkg_dir / "bar.ml"
        lib.write_text(
            "\n".join(["package other", "", "function add(a, b)", "  return a + b", "end function", ]) + "\n",
            encoding="utf-8", )

        main_ml = td_path / "main_import_mod.ml"
        main_ml.write_text(
            "\n".join(["import foo.bar", "", "function main(args)", "  return 0", "end function", ]) + "\n",
            encoding="utf-8", )

        exe = td_path / "main_import_mod.exe"
        cr = compile_native(mlc_runner, main_ml, exe, timeout_s=180)
        if cr.returncode == 0:
            return TestResult(name=name, status="FAIL", details="expected compile to fail, but it succeeded",
                              stdout=cr.stdout, stderr=cr.stderr, )

        out = (cr.stdout or "") + "\n" + (cr.stderr or "")
        if "declaring package" not in out and "package" not in out:
            return TestResult(name=name, status="FAIL",
                              details="compile failed, but error message did not mention package mismatch",
                              stdout=cr.stdout, stderr=cr.stderr, )

        return TestResult(name=name, status="PASS", stdout=cr.stdout, stderr=cr.stderr)


def test_import_package_path_mismatch(*, name: str, mlc_runner: Path) -> TestResult:
    """If a file declares `package foo.bar`, it must live at foo/bar.ml relative to its import root."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)

        libroot = td_path / "libroot"
        (libroot / "foo").mkdir(parents=True, exist_ok=True)

        # NOTE: file path implies package foo.qux, but it declares foo.bar
        lib = libroot / "foo" / "qux.ml"
        lib.write_text(
            "\n".join(["package foo.bar", "", "function add(a, b)", "  return a + b", "end function", ]) + "\n",
            encoding="utf-8", )

        main_ml = td_path / "main_import_path_pkg_mismatch.ml"
        main_ml.write_text("\n".join(
            ['import "foo/qux.ml"', "", "function main(args)", "  return foo.bar.add(2, 3)", "end function", ]) + "\n",
                           encoding="utf-8", )

        exe = td_path / "main_import_path_pkg_mismatch.exe"
        cr = compile_native(mlc_runner, main_ml, exe, extra_args=["-I", str(libroot)], timeout_s=180)
        out = normalize_out((cr.stdout or "") + "\n" + (cr.stderr or ""))

        if cr.returncode == 0:
            return TestResult(name=name, status="FAIL",
                              details="expected compile to fail due to package/path mismatch, but it succeeded",
                              stdout=cr.stdout, stderr=cr.stderr, )

        if ("declares package" not in out) and ("was found as" not in out):
            return TestResult(name=name, status="FAIL",
                              details="compile failed, but error message did not mention package/path mismatch",
                              stdout=cr.stdout, stderr=cr.stderr, )

        return TestResult(name=name, status="PASS", stdout=cr.stdout, stderr=cr.stderr)


def test_import_ambiguous_include_paths(*, name: str, mlc_runner: Path) -> TestResult:
    """Ensure ambiguous include paths are rejected with a clear error message."""
    # If both the importing directory and an include root provide the same module, the compiler should reject it as ambiguous.
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)

        # Local copy next to main (base_dir/foo/bar.ml)
        local_pkg_dir = td_path / "foo"
        local_pkg_dir.mkdir(parents=True, exist_ok=True)
        local_lib = local_pkg_dir / "bar.ml"
        local_lib.write_text(
            "\n".join(["package foo.bar", "", "function add(a, b)", "  return a + b", "end function", ]) + "\n",
            encoding="utf-8", )

        # Second copy via -I include root (libroot/foo/bar.ml)
        libroot = td_path / "libroot"
        inc_pkg_dir = libroot / "foo"
        inc_pkg_dir.mkdir(parents=True, exist_ok=True)
        inc_lib = inc_pkg_dir / "bar.ml"
        inc_lib.write_text(
            "\n".join(["package foo.bar", "", "function add(a, b)", "  return a + b", "end function", ]) + "\n",
            encoding="utf-8", )

        main_ml = td_path / "main_import_ambig.ml"
        main_ml.write_text("\n".join(
            ["import foo.bar", "", "function main(args)", "  return foo.bar.add(2, 3)", "end function", ]) + "\n",
                           encoding="utf-8", )

        exe = td_path / "main_import_ambig.exe"

        # Without -I it should succeed (resolves to local file).
        cr0 = compile_native(mlc_runner, main_ml, exe, timeout_s=180)
        if cr0.returncode != 0:
            return TestResult(name=name, status="FAIL", details=f"compile failed without -I (exit {cr0.returncode})",
                              stdout=cr0.stdout, stderr=cr0.stderr, )

        # With -I it should fail due to ambiguity.
        cr = compile_native(mlc_runner, main_ml, exe, extra_args=["-I", str(libroot)], timeout_s=180)
        out = normalize_out((cr.stdout or "") + "\n" + (cr.stderr or ""))
        if cr.returncode == 0:
            return TestResult(name=name, status="FAIL",
                              details="expected compile to fail with -I due to ambiguous import, but it succeeded",
                              stdout=cr.stdout, stderr=cr.stderr, )

        if "Ambiguous import" not in out:
            return TestResult(name=name, status="FAIL",
                              details="compile failed, but error message did not mention ambiguous import",
                              stdout=cr.stdout, stderr=cr.stderr, )

        return TestResult(name=name, status="PASS", stdout=cr.stdout, stderr=cr.stderr)


def test_import_include_paths(*, name: str, mlc_runner: Path) -> TestResult:
    """Verify include path search order and successful imports."""
    # `-I/--import-path` should allow resolving module imports outside the main file's directory. (compile-time only)
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)

        libroot = td_path / "libroot"
        pkg_dir = libroot / "foo"
        pkg_dir.mkdir(parents=True, exist_ok=True)

        lib = pkg_dir / "bar.ml"
        lib.write_text(
            "\n".join(["package foo.bar", "", "function add(a, b)", "  return a + b", "end function", ]) + "\n",
            encoding="utf-8", )

        main_ml = td_path / "main_import_I.ml"
        main_ml.write_text("\n".join(
            ["import foo.bar", "", "function main(args)", "  // Reference imported symbol so resolution is required.",
             "  return foo.bar.add(2, 3)", "end function", ]) + "\n", encoding="utf-8", )

        exe = td_path / "main_import_I.exe"

        # Without -I this should fail (foo/bar.ml not next to main).
        cr0 = compile_native(mlc_runner, main_ml, exe, timeout_s=180)
        if cr0.returncode == 0:
            return TestResult(name=name, status="FAIL", details="expected compile to fail without -I, but it succeeded",
                              stdout=cr0.stdout, stderr=cr0.stderr, )

        # With -I it should succeed.
        cr = compile_native(mlc_runner, main_ml, exe, extra_args=["-I", str(libroot)], timeout_s=180)
        if cr.returncode != 0:
            return TestResult(name=name, status="FAIL", details=f"compile failed even with -I (exit {cr.returncode})",
                              stdout=cr.stdout, stderr=cr.stderr, )

        return TestResult(name=name, status="PASS", stdout=cr.stdout, stderr=cr.stderr)


def test_package_not_first(*, name: str, mlc_runner: Path) -> TestResult:
    """Ensure a 'package' statement must be the first statement in a file."""
    # package must be the first statement in a file (before imports/decls).
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        bad = td_path / "pkg_not_first.ml"
        bad.write_text("\n".join(["function foo()", "  return 1", "end function", "", "package nope", ]) + "\n",
                       encoding="utf-8", )

        exe = td_path / "pkg_not_first.exe"
        cr = compile_native(mlc_runner, bad, exe, timeout_s=120)
        out = normalize_out((cr.stdout or "") + "\n" + (cr.stderr or ""))

        if cr.returncode == 0:
            return TestResult(name=name, status="FAIL", details="expected compile failure, but compile succeeded",
                              stdout=cr.stdout, stderr=cr.stderr)

        marker = "'package' must be the first statement in the file"
        if marker not in out:
            return TestResult(name=name, status="FAIL", details=f"expected error marker not found: {marker!r}",
                              stdout=cr.stdout, stderr=cr.stderr)

        return TestResult(name=name, status="PASS", stdout=cr.stdout, stderr=cr.stderr)


def test_package_duplicate(*, name: str, mlc_runner: Path) -> TestResult:
    """Ensure duplicate 'package' statements are rejected."""
    # Only one package directive per file.
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        bad = td_path / "pkg_dup.ml"
        bad.write_text("\n".join(["package a", "package b", "function foo()", "  return 1", "end function", ]) + "\n",
                       encoding="utf-8", )

        exe = td_path / "pkg_dup.exe"
        cr = compile_native(mlc_runner, bad, exe, timeout_s=120)
        out = normalize_out((cr.stdout or "") + "\n" + (cr.stderr or ""))

        if cr.returncode == 0:
            return TestResult(name=name, status="FAIL", details="expected compile failure, but compile succeeded",
                              stdout=cr.stdout, stderr=cr.stderr)

        marker = "'package' may only appear once per file"
        if marker not in out:
            return TestResult(name=name, status="FAIL", details=f"expected error marker not found: {marker!r}",
                              stdout=cr.stdout, stderr=cr.stderr)

        return TestResult(name=name, status="PASS", stdout=cr.stdout, stderr=cr.stderr)


def test_main_in_package(*, name: str, mlc_runner: Path) -> TestResult:
    """Ensure 'main' can be resolved correctly when a package is present."""
    # main(args) must not be qualified by a package prefix.
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        bad = td_path / "main_in_pkg.ml"
        bad.write_text("\n".join(["package p", "function main(args)", "  return 0", "end function", ]) + "\n",
                       encoding="utf-8", )

        exe = td_path / "main_in_pkg.exe"
        cr = compile_native(mlc_runner, bad, exe, timeout_s=120)
        out = normalize_out((cr.stdout or "") + "\n" + (cr.stderr or ""))

        if cr.returncode == 0:
            return TestResult(name=name, status="FAIL", details="expected compile failure, but compile succeeded",
                              stdout=cr.stdout, stderr=cr.stderr)

        marker = "main(args) must be declared at top-level"
        if marker not in out:
            return TestResult(name=name, status="FAIL", details=f"expected error marker not found: {marker!r}",
                              stdout=cr.stdout, stderr=cr.stderr)

        return TestResult(name=name, status="PASS", stdout=cr.stdout, stderr=cr.stderr)


def test_namespace_dotted(*, name: str, mlc_runner: Path) -> TestResult:
    """`namespace a.b` qualifies declarations as `a.b.*`."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)

        lib = td_path / "geom_vec_ns.ml"
        lib.write_text("\n".join(
            ["namespace geom.vec", "function add(a, b)", "  return a + b", "end function", "end namespace", ]) + "\n",
                       encoding="utf-8", )

        main_ml = td_path / "main_ns_dotted.ml"
        lib_abs = str(lib.resolve()).replace("\\", "\\\\")
        main_ml.write_text("\n".join(
            [f'import "{lib_abs}"', "", "import std.assert as t", "", "function assertEq(actual, expected, label)",
             "  return t.assertEq(actual, expected, label)", "end function", "", 'print "=== NAMESPACE DOTTED ==="',
             'assertEq(geom.vec.add(2, 3), 5, "geom.vec.add")', 'print "=== DONE ==="', ]) + "\n", encoding="utf-8", )

        return test_program_no_fail(name=name, mlc_runner=mlc_runner, ml_path=main_ml,
                                    must_contain=["=== NAMESPACE DOTTED ===", "geom.vec.add [OK]", "=== DONE ==="],
                                    timeout_compile_s=180, timeout_run_s=180, )


def test_namespace_nested(*, name: str, mlc_runner: Path) -> TestResult:
    """Nested namespaces should work: namespace a ... namespace b ..."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)

        lib = td_path / "geom_vec_nested_ns.ml"
        lib.write_text("\n".join(
            ["namespace geom", "namespace vec", "function add(a, b)", "  return a + b", "end function", "end namespace",
             "end namespace", ]) + "\n", encoding="utf-8", )

        main_ml = td_path / "main_ns_nested.ml"
        lib_abs = str(lib.resolve()).replace("\\", "\\\\")
        main_ml.write_text("\n".join(
            [f'import "{lib_abs}"', "", "import std.assert as t", "", "function assertEq(actual, expected, label)",
             "  return t.assertEq(actual, expected, label)", "end function", "", 'print "=== NAMESPACE NESTED ==="',
             'assertEq(geom.vec.add(2, 3), 5, "geom.vec.add")', 'print "=== DONE ==="', ]) + "\n", encoding="utf-8", )

        return test_program_no_fail(name=name, mlc_runner=mlc_runner, ml_path=main_ml,
                                    must_contain=["=== NAMESPACE NESTED ===", "geom.vec.add [OK]", "=== DONE ==="],
                                    timeout_compile_s=180, timeout_run_s=180, )


def test_compile_expected_fail(*, name: str, mlc_runner: Path, entry_ml: Path, must_contain_err: str,
                               timeout_compile_s: int = 120, ) -> TestResult:
    """Compile a snippet that is expected to fail and validate the error marker."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        exe = Path(td) / (entry_ml.stem + ".exe")
        cr = compile_native(mlc_runner, entry_ml, exe, timeout_s=timeout_compile_s)
        out = normalize_out((cr.stdout or "") + "\n" + (cr.stderr or ""))
        if cr.returncode == 0:
            return TestResult(name=name, status="FAIL", details="expected compile failure, but compile succeeded",
                              stdout=cr.stdout, stderr=cr.stderr)
        if must_contain_err not in out:
            return TestResult(name=name, status="FAIL",
                              details=f"compile failed, but error output did not contain expected marker: {must_contain_err!r}",
                              stdout=cr.stdout, stderr=cr.stderr, )
        return TestResult(name=name, status="PASS", stdout=cr.stdout, stderr=cr.stderr)


def test_import_cycle_allowed(*, name: str, mlc_runner: Path) -> TestResult:
    """A <-> B import cycles should load once and compile successfully."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)

        cyc_dir = td_path / "cyc"
        cyc_dir.mkdir(parents=True, exist_ok=True)

        a_ml = cyc_dir / "a.ml"
        b_ml = cyc_dir / "b.ml"
        main_ml = td_path / "main_cycle_ok.ml"

        a_ml.write_text("\n".join([
            "package cyc.a",
            "import cyc.b",
            "function a()",
            "  return 11",
            "end function",
        ]) + "\n", encoding="utf-8")

        b_ml.write_text("\n".join([
            "package cyc.b",
            "import cyc.a",
            "function b()",
            "  return 22",
            "end function",
        ]) + "\n", encoding="utf-8")

        main_ml.write_text("\n".join([
            "import cyc.a",
            "import std.assert as t",
            'print "=== IMPORT CYCLE OK ==="',
            't.assertEq(cyc.a.a(), 11, "cyc.a.a")',
            't.assertEq(cyc.b.b(), 22, "cyc.b.b")',
            'print "=== DONE ==="',
        ]) + "\n", encoding="utf-8")

        exe = td_path / "main_cycle_ok.exe"
        cr = compile_native(mlc_runner, main_ml, exe, timeout_s=180)
        if cr.returncode != 0:
            return TestResult(name=name, status="FAIL", details=f"compile failed (exit {cr.returncode})",
                              stdout=cr.stdout, stderr=cr.stderr)

        rr = run_exe(exe, timeout_s=180)
        if rr.returncode == 999:
            return TestResult(name=name, status="SKIP", details=rr.stderr, stdout=cr.stdout, stderr=rr.stderr)
        if rr.returncode != 0:
            return TestResult(name=name, status="FAIL", details=f"runtime failed (exit {rr.returncode})",
                              stdout=rr.stdout, stderr=rr.stderr)

        out = normalize_out(rr.stdout)
        if "[FAIL]" in out:
            return TestResult(name=name, status="FAIL", details="program printed at least one [FAIL]",
                              stdout=rr.stdout, stderr=rr.stderr)
        if "=== IMPORT CYCLE OK ===" not in out or "=== DONE ===" not in out:
            return TestResult(name=name, status="FAIL", details="missing expected output markers",
                              stdout=rr.stdout, stderr=rr.stderr)

        return TestResult(name=name, status="PASS", stdout=rr.stdout, stderr=rr.stderr)


def test_import_self_ignored(*, name: str, mlc_runner: Path) -> TestResult:
    """A module importing itself should be treated as a no-op by the loader."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)

        doom_dir = td_path / "doom"
        doom_dir.mkdir(parents=True, exist_ok=True)

        mod_ml = doom_dir / "doomdef.ml"
        mod_ml.write_text("\n".join([
            "package doom.doomdef",
            "import doom.doomdef",
            "function answer()",
            "  return 42",
            "end function",
        ]) + "\n", encoding="utf-8")

        main_ml = td_path / "main_self_import_ok.ml"
        main_ml.write_text("\n".join([
            "import doom.doomdef",
            "import std.assert as t",
            'print "=== SELF IMPORT OK ==="',
            't.assertEq(doom.doomdef.answer(), 42, "doom.doomdef.answer")',
            'print "=== DONE ==="',
        ]) + "\n", encoding="utf-8")

        exe = td_path / "main_self_import_ok.exe"
        cr = compile_native(mlc_runner, main_ml, exe, timeout_s=180)
        if cr.returncode != 0:
            return TestResult(name=name, status="FAIL", details=f"compile failed (exit {cr.returncode})",
                              stdout=cr.stdout, stderr=cr.stderr)

        rr = run_exe(exe, timeout_s=180)
        if rr.returncode == 999:
            return TestResult(name=name, status="SKIP", details=rr.stderr, stdout=cr.stdout, stderr=rr.stderr)
        if rr.returncode != 0:
            return TestResult(name=name, status="FAIL", details=f"runtime failed (exit {rr.returncode})",
                              stdout=rr.stdout, stderr=rr.stderr)

        out = normalize_out(rr.stdout)
        if "[FAIL]" in out:
            return TestResult(name=name, status="FAIL", details="program printed at least one [FAIL]",
                              stdout=rr.stdout, stderr=rr.stderr)
        if "=== SELF IMPORT OK ===" not in out or "=== DONE ===" not in out:
            return TestResult(name=name, status="FAIL", details="missing expected output markers",
                              stdout=rr.stdout, stderr=rr.stderr)

        return TestResult(name=name, status="PASS", stdout=rr.stdout, stderr=rr.stderr)


def test_module_init_order(*, name: str, mlc_runner: Path) -> TestResult:
    """Imported module initializers should run before dependent modules and before main()."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)

        mod_dir = td_path / "mod"
        mod_dir.mkdir(parents=True, exist_ok=True)

        b_ml = mod_dir / "b.ml"
        a_ml = mod_dir / "a.ml"
        main_ml = td_path / "main_modinit_order.ml"

        b_ml.write_text("\n".join([
            "package mod.b",
            "value = 10",
            "function getValue()",
            "  return value",
            "end function",
        ]) + "\n", encoding="utf-8")

        a_ml.write_text("\n".join([
            "package mod.a",
            "import mod.b",
            "value = mod.b.getValue() + 1",
            "function getValue()",
            "  return value",
            "end function",
        ]) + "\n", encoding="utf-8")

        main_ml.write_text("\n".join([
            "import mod.a",
            "import std.assert as t",
            'print "=== MODULE INIT ORDER ==="',
            't.assertEq(mod.b.getValue(), 10, "mod.b.getValue")',
            't.assertEq(mod.a.getValue(), 11, "mod.a.getValue")',
            'print "=== DONE ==="',
        ]) + "\n", encoding="utf-8")

        return test_program_no_fail(
            name=name,
            mlc_runner=mlc_runner,
            ml_path=main_ml,
            must_contain=["=== MODULE INIT ORDER ===", "mod.b.getValue [OK]", "mod.a.getValue [OK]", "=== DONE ==="],
            timeout_compile_s=180,
            timeout_run_s=180,
        )



def test_module_init_once_in_cycle(*, name: str, mlc_runner: Path) -> TestResult:
    """Cyclic imports should still run each module initializer exactly once."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)

        cyc_dir = td_path / "cyc"
        cyc_dir.mkdir(parents=True, exist_ok=True)

        a_ml = cyc_dir / "a.ml"
        b_ml = cyc_dir / "b.ml"
        main_ml = td_path / "main_modinit_once_cycle.ml"

        a_ml.write_text("\n".join([
            "package cyc.a",
            "import cyc.b",
            "initCount = 0",
            "initCount = initCount + 1",
            "function getInitCount()",
            "  return initCount",
            "end function",
        ]) + "\n", encoding="utf-8")

        b_ml.write_text("\n".join([
            "package cyc.b",
            "import cyc.a",
            "initCount = 0",
            "initCount = initCount + 1",
            "function getInitCount()",
            "  return initCount",
            "end function",
        ]) + "\n", encoding="utf-8")

        main_ml.write_text("\n".join([
            "import cyc.a",
            "import std.assert as t",
            'print "=== MODULE INIT ONCE CYCLE ==="',
            't.assertEq(cyc.a.getInitCount(), 1, "cyc.a init once")',
            't.assertEq(cyc.b.getInitCount(), 1, "cyc.b init once")',
            'print "=== DONE ==="',
        ]) + "\n", encoding="utf-8")

        return test_program_no_fail(
            name=name,
            mlc_runner=mlc_runner,
            ml_path=main_ml,
            must_contain=["=== MODULE INIT ONCE CYCLE ===", "cyc.a init once [OK]", "cyc.b init once [OK]", "=== DONE ==="],
            timeout_compile_s=180,
            timeout_run_s=180,
        )


def test_import_decl_only_violation(*, name: str, mlc_runner: Path, lib_bad: Path) -> TestResult:
    """Ensure 'declaration-only' imports cannot be used at runtime."""
    # Write a tiny main that imports lib_bad.ml (which contains a top-level print).
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        main_bad = td_path / "main_bad.ml"

        # Use absolute import path so it works no matter where the test is run from.
        lib_bad_abs = str(lib_bad.resolve()).replace("\\", "\\\\")  # keep Windows paths safe in string literal

        main_bad.write_text("\n".join([f'import "{lib_bad_abs}"', "print \"should not reach\"", ]) + "\n",
                            encoding="utf-8", )

        exe = td_path / "main_bad.exe"
        cr = compile_native(mlc_runner, main_bad, exe, timeout_s=120)
        out = normalize_out((cr.stdout or "") + "\n" + (cr.stderr or ""))

        if cr.returncode == 0:
            return TestResult(name=name, status="FAIL", details="expected compile failure, but compile succeeded",
                              stdout=cr.stdout, stderr=cr.stderr)

        marker = "Imported module must be declaration-only"
        if marker not in out:
            return TestResult(name=name, status="FAIL", details=f"expected error marker not found: {marker!r}",
                              stdout=cr.stdout, stderr=cr.stderr)

        return TestResult(name=name, status="PASS", stdout=cr.stdout, stderr=cr.stderr)


def test_call_arity_mismatch(*, name: str, mlc_runner: Path) -> TestResult:
    """Ensure calling a function with wrong arity produces a compile-time error."""
    # Ensure calling a user function with the wrong number of arguments is a compile-time error.
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        main_bad = td_path / "arity_bad.ml"
        main_bad.write_text("\n".join(["function foo()", "  return 1", "end function", "", "print foo(1, 2)", ]) + "\n",
                            encoding="utf-8", )

        exe = td_path / "arity_bad.exe"
        cr = compile_native(mlc_runner, main_bad, exe, timeout_s=120)
        out = normalize_out((cr.stdout or "") + "\n" + (cr.stderr or ""))

        if cr.returncode == 0:
            return TestResult(name=name, status="FAIL", details="expected compile failure, but compile succeeded",
                              stdout=cr.stdout, stderr=cr.stderr)

        marker = "Function foo expects"
        if marker not in out:
            return TestResult(name=name, status="FAIL", details=f"expected error marker not found: {marker!r}",
                              stdout=cr.stdout, stderr=cr.stderr)

        return TestResult(name=name, status="PASS", stdout=cr.stdout, stderr=cr.stderr)


def test_enum_unknown_variant(*, name: str, mlc_runner: Path) -> TestResult:
    """Ensure referencing an unknown enum variant is rejected."""
    # Ensure referencing an unknown enum variant is a compile-time error.
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        main_bad = td_path / "enum_unknown_variant.ml"
        main_bad.write_text("\n".join(["enum Color are", "  Red", "end enum", "", "print Color.Nope", ]) + "\n",
                            encoding="utf-8", )

        exe = td_path / "enum_unknown_variant.exe"
        cr = compile_native(mlc_runner, main_bad, exe, timeout_s=120)
        out = normalize_out((cr.stdout or "") + "\n" + (cr.stderr or ""))

        if cr.returncode == 0:
            return TestResult(name=name, status="FAIL", details="expected compile failure, but compile succeeded",
                              stdout=cr.stdout, stderr=cr.stderr, )

        marker = "has no variant"
        if marker not in out:
            return TestResult(name=name, status="FAIL", details=f"expected error marker not found: {marker!r}",
                              stdout=cr.stdout, stderr=cr.stderr, )

        return TestResult(name=name, status="PASS", stdout=cr.stdout, stderr=cr.stderr)


def test_enum_duplicate_variant(*, name: str, mlc_runner: Path) -> TestResult:
    """Ensure duplicate enum variants are rejected."""
    # Ensure duplicate enum variants are rejected at compile time.
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        main_bad = td_path / "enum_duplicate_variant.ml"
        main_bad.write_text("\n".join(["enum Color are", "  Red", "  Red", "end enum", "", "print 1", ]) + "\n",
                            encoding="utf-8", )

        exe = td_path / "enum_duplicate_variant.exe"
        cr = compile_native(mlc_runner, main_bad, exe, timeout_s=120)
        out = normalize_out((cr.stdout or "") + "\n" + (cr.stderr or ""))

        if cr.returncode == 0:
            return TestResult(name=name, status="FAIL", details="expected compile failure, but compile succeeded",
                              stdout=cr.stdout, stderr=cr.stderr, )

        marker = "duplicate variant"
        if marker not in out:
            return TestResult(name=name, status="FAIL", details=f"expected error marker not found: {marker!r}",
                              stdout=cr.stdout, stderr=cr.stderr, )

        return TestResult(name=name, status="PASS", stdout=cr.stdout, stderr=cr.stderr)

        exe = td_path / "arity_bad.exe"
        cr = compile_native(mlc_runner, main_bad, exe, timeout_s=120)
        out = normalize_out((cr.stdout or "") + "\n" + (cr.stderr or ""))

        if cr.returncode == 0:
            return TestResult(name=name, status="FAIL", details="expected compile failure, but compile succeeded",
                              stdout=cr.stdout, stderr=cr.stderr)

        marker = "Function foo expects"
        if marker not in out:
            return TestResult(name=name, status="FAIL", details=f"expected error marker not found: {marker!r}",
                              stdout=cr.stdout, stderr=cr.stderr)

        return TestResult(name=name, status="PASS", stdout=cr.stdout, stderr=cr.stderr)


# -----------------------------
# regression tests: const / value-enum / constexpr imports
# -----------------------------


def test_const_reassign_rejected(*, name: str, mlc_runner: Path) -> TestResult:
    """Assigning to a `const` binding must be a compile-time error."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        ml_path = td_path / "const_reassign.ml"
        ml_path.write_text(
            "\n".join(['print "=== CONST REASSIGN ==="', 'const a = 1', 'a = 2', 'print "SHOULD NOT REACH"', ]) + "\n",
            encoding="utf-8", )

        exe = td_path / "const_reassign.exe"
        cr = compile_native(mlc_runner, ml_path, exe, timeout_s=120)
        out = normalize_out((cr.stdout or "") + "\n" + (cr.stderr or ""))

        if cr.returncode == 0:
            return TestResult(name=name, status="FAIL", details="expected compile failure, but compile succeeded",
                              stdout=cr.stdout, stderr=cr.stderr, )

        marker = "Cannot assign to const"
        if marker not in out:
            return TestResult(name=name, status="FAIL",
                              details=f"compile failed, but error output did not contain expected marker: {marker!r}",
                              stdout=cr.stdout, stderr=cr.stderr, )

        return TestResult(name=name, status="PASS", stdout=cr.stdout, stderr=cr.stderr)


def test_enum_autoinc_ignores_strings(*, name: str, mlc_runner: Path) -> TestResult:
    """Value-enum auto-fill should ignore explicit string literals for numeric sequencing."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        ml_path = td_path / "enum_autoinc_ignore_strings.ml"
        ml_path.write_text(
            "\n".join(
                [
                    # baseline: int -> string -> auto continues
                    'enum E are',
                    '  A = 1',
                    '  B = "x"',
                    '  C',
                    '  D',
                    'end enum',
                    '',
                    # leading string should NOT affect numeric start (still 0)
                    'enum EHead are',
                    '  A = "x"',
                    '  B',
                    '  C',
                    'end enum',
                    '',
                    # mid string should be ignored for numeric sequencing
                    'enum EMid are',
                    '  A',
                    '  B = "x"',
                    '  C',
                    '  D',
                    'end enum',
                    '',
                    # explicit int then string then auto continues from int
                    'enum EIntStr are',
                    '  A = 5',
                    '  B = "x"',
                    '  C',
                    'end enum',
                    '',
                    # prints (raw values, stable order)
                    'print E.A',
                    'print E.B',
                    'print E.C',
                    'print E.D',
                    'print EHead.A',
                    'print EHead.B',
                    'print EHead.C',
                    'print EMid.A',
                    'print EMid.B',
                    'print EMid.C',
                    'print EMid.D',
                    'print EIntStr.A',
                    'print EIntStr.B',
                    'print EIntStr.C',
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        exe = td_path / "enum_autoinc_ignore_strings.exe"
        cr = compile_native(mlc_runner, ml_path, exe, timeout_s=120)
        if cr.returncode != 0:
            return TestResult(
                name=name,
                status="FAIL",
                details=f"compile failed (exit {cr.returncode})",
                stdout=cr.stdout,
                stderr=cr.stderr,
            )

        rr = run_exe(exe, timeout_s=120)
        if rr.returncode == 999:
            return TestResult(name=name, status="SKIP", details=rr.stderr, stdout=cr.stdout, stderr=rr.stderr)
        if rr.returncode != 0:
            return TestResult(
                name=name,
                status="FAIL",
                details=f"runtime failed (exit {rr.returncode})",
                stdout=rr.stdout,
                stderr=rr.stderr,
            )

        def _norm_line(s: str) -> str:
            s = s.strip()
            if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
                return s[1:-1]
            return s

        out = normalize_out(rr.stdout)
        lines = [_norm_line(ln) for ln in out.splitlines() if ln.strip()]

        expected = ["1", "x", "2", "3", "x", "0", "1", "0", "x", "1", "2", "5", "x", "6"]
        if len(lines) < len(expected):
            return TestResult(
                name=name,
                status="FAIL",
                details=f"expected at least {len(expected)} output lines",
                stdout=rr.stdout,
                stderr=rr.stderr,
            )

        got = lines[-len(expected):]
        if got != expected:
            return TestResult(
                name=name,
                status="FAIL",
                details=f"unexpected output lines: {got!r} (expected {expected!r})",
                stdout=rr.stdout,
                stderr=rr.stderr,
            )

        return TestResult(name=name, status="PASS", stdout=rr.stdout, stderr=rr.stderr)


def test_typequalified_instance_method_uses_this_rejected(*, name: str, mlc_runner: Path) -> TestResult:
    """Calling an instance method via StructName.method(...) must be rejected when the method uses `this`."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        ml_path = td_path / "typequalified_uses_this.ml"
        ml_path.write_text(
            "\n".join(
                [
                    "struct S",
                    "  x",
                    "  function inc()",
                    "    this.x = this.x + 1",
                    "    return this.x",
                    "  end function",
                    "",
                    "  static function run()",
                    "    // illegal: missing receiver, and method uses `this`",
                    "    return S.inc()",
                    "  end function",
                    "end struct",
                    "",
                    "function main(args)",
                    "  print S.run()",
                    "end function",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        return test_compile_expected_fail(
            name=name,
            mlc_runner=mlc_runner,
            entry_ml=ml_path,
            must_contain_err="without receiver because it uses 'this'",
        )


def test_member_call_arity_error_message(*, name: str, mlc_runner: Path) -> TestResult:
    """Member-call arity mismatch should report got/expected in the error message."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        ml_path = td_path / "member_call_arity_diag.ml"
        ml_path.write_text(
            "\n".join(
                [
                    'print "=== CALL ARITY DIAG ==="',
                    "struct Holder",
                    "  f",
                    "end struct",
                    "",
                    "function add2(a, b)",
                    "  return a + b",
                    "end function",
                    "",
                    "h = Holder(add2)",
                    "// wrong: add2 expects 2 args",
                    "h.f(1)",
                    'print "SHOULD NOT REACH"',
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        return test_program_expect_exit(
            name=name,
            mlc_runner=mlc_runner,
            ml_path=ml_path,
            expected_exit=1,
            must_contain=[
                "=== CALL ARITY DIAG ===",
                "Error occured: no=1100 message=Cannot call 'h.f' with 1 args (expected 2)",
            ],
            timeout_compile_s=180,
            timeout_run_s=180,
        )

def test_import_initializer_behavior(*, name: str, mlc_runner: Path, kind: str) -> TestResult:
    """Imported const initializers must stay constexpr; global initializers may run at runtime."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)

        lib = td_path / "lib_ce_bad.ml"
        if kind == "const":
            lib.write_text(
                "\n".join(["package ce.bad", "function foo()", "  return 1", "end function", "const A = foo()", ]) + "\n",
                encoding="utf-8",
            )
            marker = "Imported module const initializer must be constexpr"
        elif kind == "global":
            lib.write_text(
                "\n".join([
                    "package ce.bad",
                    "function foo()",
                    "  return 1",
                    "end function",
                    "x = foo()",
                    "function getX()",
                    "  return x",
                    "end function",
                ]) + "\n",
                encoding="utf-8",
            )
            marker = None
        else:
            return TestResult(name=name, status="FAIL", details=f"internal: unknown kind {kind!r}")

        main_ml = td_path / "main_ce_bad.ml"
        lib_abs = str(lib.resolve()).replace("\\", "\\\\")
        if kind == "const":
            main_ml.write_text(
                "\n".join([f'import "{lib_abs}"', 'print "should not reach"', ]) + "\n",
                encoding="utf-8",
            )
        else:
            main_ml.write_text(
                "\n".join([f'import "{lib_abs}"', 'print ce.bad.getX()', ]) + "\n",
                encoding="utf-8",
            )

        exe = td_path / "main_ce_bad.exe"
        cr = compile_native(mlc_runner, main_ml, exe, timeout_s=120)
        out = normalize_out((cr.stdout or "") + "\n" + (cr.stderr or ""))

        if kind == "const":
            if cr.returncode == 0:
                return TestResult(
                    name=name,
                    status="FAIL",
                    details="expected compile failure, but compile succeeded",
                    stdout=cr.stdout,
                    stderr=cr.stderr,
                )
            if marker not in out:
                return TestResult(
                    name=name,
                    status="FAIL",
                    details=f"compile failed, but error output did not contain expected marker: {marker!r}",
                    stdout=cr.stdout,
                    stderr=cr.stderr,
                )
            return TestResult(name=name, status="PASS", stdout=cr.stdout, stderr=cr.stderr)

        if cr.returncode != 0:
            return TestResult(
                name=name,
                status="FAIL",
                details=f"compile failed (exit {cr.returncode})",
                stdout=cr.stdout,
                stderr=cr.stderr,
            )

        return TestResult(name=name, status="PASS", stdout=cr.stdout, stderr=cr.stderr)


def test_no_newlines_required(*, name: str, mlc_runner: Path) -> TestResult:
    """Block headers should not require physical newlines or ';'.

    This is a formatting feature: a complete program (including block bodies)
    should compile and run even when written as a single line.
    """
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        ml_path = td_path / "no_newlines_required.ml"

        # Intentionally a single-line program (no '\n' in the source).
        src = (
            'enum E are A = 1, B = "x", C end enum '
            'struct S a, b static function sum(x, y) return x + y end function end struct '
            'function main(args) '
            'x = 0; while x < 2 x = x + 1 end while '
            'if x == 2 then print "ok" else print "bad" end if '
            'print E.C; print S.sum(2, 3); print "no-newlines [OK]" '
            'end function'
        )
        ml_path.write_text(src, encoding="utf-8")

        exe = td_path / "no_newlines_required.exe"
        cr = compile_native(mlc_runner, ml_path, exe, timeout_s=120)
        if cr.returncode != 0:
            return TestResult(
                name=name,
                status="FAIL",
                details=f"compile failed (exit {cr.returncode})",
                stdout=cr.stdout,
                stderr=cr.stderr,
            )

        rr = run_exe(exe, timeout_s=120)
        if rr.returncode == 999:
            return TestResult(name=name, status="SKIP", details=rr.stderr, stdout=cr.stdout, stderr=rr.stderr)
        if rr.returncode != 0:
            return TestResult(
                name=name,
                status="FAIL",
                details=f"runtime failed (exit {rr.returncode})",
                stdout=rr.stdout,
                stderr=rr.stderr,
            )

        out = normalize_out(rr.stdout)
        # Strings may be printed with surrounding quotes; we only need markers.
        for must in ("ok", "2", "5", "no-newlines [OK]"):
            if must not in out:
                return TestResult(
                    name=name,
                    status="FAIL",
                    details=f"missing expected output marker: {must!r}",
                    stdout=rr.stdout,
                    stderr=rr.stderr,
                )

        return TestResult(name=name, status="PASS", stdout=rr.stdout, stderr=rr.stderr)


def test_import_constexpr_ok(*, name: str, mlc_runner: Path) -> TestResult:
    """Imported-module constexpr initializers should be accepted (const + globals + enum values)."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)

        lib = td_path / "lib_ce_ok.ml"
        lib.write_text("\n".join(
            ["package ce.ok", "const A = 1 + 2", "x = 0x10 + 1", "enum Flags are", "  Read = 1", "  Write = 2",
             "  All = 3", "end enum", ]) + "\n", encoding="utf-8", )

        main_ml = td_path / "main_ce_ok.ml"
        lib_abs = str(lib.resolve()).replace("\\", "\\\\")
        main_ml.write_text("\n".join(
            [f'import "{lib_abs}"', "import std.assert as t", "function assertEq(actual, expected, label)",
             "  return t.assertEq(actual, expected, label)", "end function", 'print "=== IMPORT CONSTEXPR OK ==="',
             'assertEq(ce.ok.A, 3, "ce.ok.A")', 'assertEq(ce.ok.x, 17, "ce.ok.x")',
             'assertEq(ce.ok.Flags.All, 3, "ce.ok.Flags.All")', 'print "=== DONE ==="', ]) + "\n", encoding="utf-8", )

        return test_program_no_fail(name=name, mlc_runner=mlc_runner, ml_path=main_ml,
                                    must_contain=["=== IMPORT CONSTEXPR OK ===", "=== DONE ==="], timeout_compile_s=180,
                                    timeout_run_s=180, )


def test_main_args_and_exitcode(*, name: str, mlc_runner: Path) -> TestResult:
    """Ensure main(args: string[]) can read args and return an exit code."""
    # Ensure main(args) is called after top-level code, args = argv[1..], and return value sets process exit code.
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        main_ml = td_path / "main_args.ml"
        main_ml.write_text("\n".join(
            ['print "TOP"', "", "function main(args)", '  print "MAIN"', '  print "argc=" + len(args)',
             "  if len(args) > 0 then print args[0] end if", "  if len(args) > 1 then print args[1] end if",
             "  if len(args) > 2 then print args[2] end if", "  return 7", "end function", ]) + "\n",
                           encoding="utf-8", )

        exe = td_path / "main_args.exe"
        cr = compile_native(mlc_runner, main_ml, exe, timeout_s=120)
        if cr.returncode != 0:
            return TestResult(name=name, status="FAIL", details=f"compile failed (exit {cr.returncode})",
                              stdout=cr.stdout, stderr=cr.stderr)

        rr = run_exe(exe, exe_args=["a", "b c", "d"], timeout_s=120)
        if rr.returncode == 999:
            return TestResult(name=name, status="SKIP", details=rr.stderr, stdout=cr.stdout, stderr=rr.stderr)

        out = normalize_out(rr.stdout)

        # return code from main()
        if rr.returncode != 7:
            return TestResult(name=name, status="FAIL", details=f"expected exit code 7, got {rr.returncode}",
                              stdout=rr.stdout, stderr=rr.stderr)

        for marker in ["TOP", "MAIN", "argc=3", "a", "b c", "d"]:
            if marker not in out:
                return TestResult(name=name, status="FAIL", details=f"missing expected output marker: {marker!r}",
                                  stdout=rr.stdout, stderr=rr.stderr)

        return TestResult(name=name, status="PASS", stdout=rr.stdout, stderr=rr.stderr)


def test_main_void_exit0(*, name: str, mlc_runner: Path) -> TestResult:
    """Ensure void main() returns exit code 0 by default."""
    # Ensure main(args) with no return exits with code 0.
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        main_ml = td_path / "main_void.ml"
        main_ml.write_text("\n".join(["function main(args)", '  print "ok"', "end function", ]) + "\n",
                           encoding="utf-8", )

        exe = td_path / "main_void.exe"
        cr = compile_native(mlc_runner, main_ml, exe, timeout_s=120)
        if cr.returncode != 0:
            return TestResult(name=name, status="FAIL", details=f"compile failed (exit {cr.returncode})",
                              stdout=cr.stdout, stderr=cr.stderr)

        rr = run_exe(exe, exe_args=[], timeout_s=120)
        if rr.returncode == 999:
            return TestResult(name=name, status="SKIP", details=rr.stderr, stdout=cr.stdout, stderr=rr.stderr)

        if rr.returncode != 0:
            return TestResult(name=name, status="FAIL", details=f"expected exit code 0, got {rr.returncode}",
                              stdout=rr.stdout, stderr=rr.stderr)

        out = normalize_out(rr.stdout)
        if "ok" not in out:
            return TestResult(name=name, status="FAIL", details="missing expected output marker: 'ok'",
                              stdout=rr.stdout, stderr=rr.stderr)

        return TestResult(name=name, status="PASS", stdout=rr.stdout, stderr=rr.stderr)


def test_main_bad_arity0(*, name: str, mlc_runner: Path) -> TestResult:
    """Ensure main() with unexpected params is rejected."""
    # main(args) expects exactly 1 parameter.
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        main_bad = td_path / "main_arity0.ml"
        main_bad.write_text("\n".join(["function main()", "  return 0", "end function", ]) + "\n", encoding="utf-8", )

        exe = td_path / "main_arity0.exe"
        cr = compile_native(mlc_runner, main_bad, exe, timeout_s=120)
        out = normalize_out((cr.stdout or "") + "\n" + (cr.stderr or ""))

        if cr.returncode == 0:
            return TestResult(name=name, status="FAIL", details="expected compile failure, but compile succeeded",
                              stdout=cr.stdout, stderr=cr.stderr)

        marker = "main(args) expects exactly 1 parameter"
        if marker not in out:
            return TestResult(name=name, status="FAIL", details=f"expected error marker not found: {marker!r}",
                              stdout=cr.stdout, stderr=cr.stderr)

        return TestResult(name=name, status="PASS", stdout=cr.stdout, stderr=cr.stderr)


def test_main_bad_arity2(*, name: str, mlc_runner: Path) -> TestResult:
    """Ensure main with wrong arity is rejected."""
    # main(args) expects exactly 1 parameter.
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        main_bad = td_path / "main_arity2.ml"
        main_bad.write_text("\n".join(["function main(a, b)", "  return 0", "end function", ]) + "\n",
                            encoding="utf-8", )

        exe = td_path / "main_arity2.exe"
        cr = compile_native(mlc_runner, main_bad, exe, timeout_s=120)
        out = normalize_out((cr.stdout or "") + "\n" + (cr.stderr or ""))

        if cr.returncode == 0:
            return TestResult(name=name, status="FAIL", details="expected compile failure, but compile succeeded",
                              stdout=cr.stdout, stderr=cr.stderr)

        marker = "main(args) expects exactly 1 parameter"
        if marker not in out:
            return TestResult(name=name, status="FAIL", details=f"expected error marker not found: {marker!r}",
                              stdout=cr.stdout, stderr=cr.stderr)

        return TestResult(name=name, status="PASS", stdout=cr.stdout, stderr=cr.stderr)


def test_main_in_namespace(*, name: str, mlc_runner: Path) -> TestResult:
    """Ensure main function resolution works with namespaces."""
    # main(args) must be top-level (not inside namespace).
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        main_bad = td_path / "main_in_ns.ml"
        main_bad.write_text("\n".join(
            ["namespace n", "  function main(args)", "    return 0", "  end function", "end namespace", ]) + "\n",
                            encoding="utf-8", )

        exe = td_path / "main_in_ns.exe"
        cr = compile_native(mlc_runner, main_bad, exe, timeout_s=120)
        out = normalize_out((cr.stdout or "") + "\n" + (cr.stderr or ""))

        if cr.returncode == 0:
            return TestResult(name=name, status="FAIL", details="expected compile failure, but compile succeeded",
                              stdout=cr.stdout, stderr=cr.stderr)

        marker = "main(args) must be declared at top-level"
        if marker not in out:
            return TestResult(name=name, status="FAIL", details=f"expected error marker not found: {marker!r}",
                              stdout=cr.stdout, stderr=cr.stderr)

        return TestResult(name=name, status="PASS", stdout=cr.stdout, stderr=cr.stderr)


def test_heap_cli_config_applied(*, name: str, mlc_runner: Path) -> TestResult:
    """Test case: test heap cli config applied."""
    # Ensure --heap-reserve/--heap-commit are parsed and applied to the runtime heap.
    reserve_arg = "48m"
    commit_arg = "24m"
    expected_reserve = 48 * 1024 * 1024
    expected_commit = 24 * 1024 * 1024

    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        main_ml = td_path / "heap_cfg.ml"
        main_ml.write_text("\n".join(["print heap_bytes_reserved()", "print heap_bytes_committed()", ]) + "\n",
                           encoding="utf-8", )

        exe = td_path / "heap_cfg.exe"
        cr = compile_native(mlc_runner, main_ml, exe,
                            extra_args=["--heap-reserve", reserve_arg, "--heap-commit", commit_arg], timeout_s=120, )
        if cr.returncode != 0:
            return TestResult(name=name, status="FAIL", details=f"compile failed (exit {cr.returncode})",
                              stdout=cr.stdout, stderr=cr.stderr, )

        rr = run_exe(exe, exe_args=[], timeout_s=120)
        if rr.returncode == 999:
            return TestResult(name=name, status="SKIP", details=rr.stderr, stdout=cr.stdout, stderr=rr.stderr)

        out = normalize_out(rr.stdout)
        nums = [int(x) for x in re.findall(r"\b\d+\b", out)]
        if len(nums) < 2:
            return TestResult(name=name, status="FAIL",
                              details=f"expected 2 integers in output (reserved, committed), got: {out!r}",
                              stdout=rr.stdout, stderr=rr.stderr, )

        reserved, committed = nums[0], nums[1]

        # reserve aligned up to 64KiB, commit aligned up to 4KiB
        if not (expected_reserve <= reserved <= expected_reserve + 0x10000):
            return TestResult(name=name, status="FAIL",
                              details=f"reserved bytes not in expected range: got {reserved}, expected ~{expected_reserve}",
                              stdout=rr.stdout, stderr=rr.stderr, )
        if not (expected_commit <= committed <= expected_commit + 0x1000):
            return TestResult(name=name, status="FAIL",
                              details=f"committed bytes not in expected range: got {committed}, expected ~{expected_commit}",
                              stdout=rr.stdout, stderr=rr.stderr, )

        return TestResult(name=name, status="PASS", stdout=rr.stdout, stderr=rr.stderr)


def test_heap_cli_invalid_size(*, name: str, mlc_runner: Path) -> TestResult:
    """Test case: test heap cli invalid size."""
    # Ensure invalid size strings are rejected by the CLI parser.
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        main_ml = td_path / "heap_bad.ml"
        main_ml.write_text("print 1\n", encoding="utf-8")
        exe = td_path / "heap_bad.exe"

        cr = compile_native(mlc_runner, main_ml, exe, extra_args=["--heap-reserve", "1z"], timeout_s=120, )
        out = normalize_out((cr.stdout or "") + "\n" + (cr.stderr or ""))

        if cr.returncode == 0:
            return TestResult(name=name, status="FAIL", details="expected compile failure, but compile succeeded",
                              stdout=cr.stdout, stderr=cr.stderr, )

        if ("invalid size" not in out) and ("invalid size suffix" not in out):
            return TestResult(name=name, status="FAIL", details="expected invalid size error marker not found",
                              stdout=cr.stdout, stderr=cr.stderr, )

        return TestResult(name=name, status="PASS", stdout=cr.stdout, stderr=cr.stderr)


def test_ns_struct_optional(*, name: str, mlc_runner: Path, geom_ml: Optional[Path],
                            testlib_ml: Optional[Path]) -> TestResult:
    """Test case: test ns struct optional."""
    if geom_ml is None or testlib_ml is None:
        return TestResult(name=name, status="SKIP", details="geom.ml or testlib.ml not found")

    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        main_geom = td_path / "main_geom.ml"

        geom_abs = str(geom_ml.resolve()).replace("\\", "\\\\")
        testlib_abs = str(testlib_ml.resolve()).replace("\\", "\\\\")

        main_geom.write_text("\n".join(
            [f'import "{testlib_abs}"', f'import "{geom_abs}"', 'print "=== NS/IMPORT STRUCT ==="',
             'p = geom.Point(1, 2)', 'assertEq(p.x, 1, "geom.Point.x")', 'assertEq(p.y, 2, "geom.Point.y")',
             'print "=== DONE ==="', ]) + "\n", encoding="utf-8", )

        # Reuse the generic checker
        return test_program_no_fail(name=name, mlc_runner=mlc_runner, ml_path=main_geom,
                                    must_contain=["=== NS/IMPORT STRUCT ===", "=== DONE ===", "geom.Point.x [OK]",
                                                  "geom.Point.y [OK]"], timeout_compile_s=120, timeout_run_s=120, )


def test_extern_namespaced(*, name: str, mlc_runner: Path) -> TestResult:
    """Verify externs work with namespace qualification and import-as aliasing."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)

        winapi_ml = td_path / "winapi.ml"
        main_ml = td_path / "extern_ns.ml"

        # Module providing an extern via a package name (for import-as aliasing).
        winapi_ml.write_text(
            "\n".join(["package winapi", 'extern function GetTickCount() from "kernel32.dll" returns u32', ]) + "\n",
            encoding="utf-8", )

        winapi_abs = str(winapi_ml.resolve()).replace("\\", "\\\\")
        main_ml.write_text("\n".join([f'import "{winapi_abs}" as w', "", 'function ok(cond, label)', '  if cond then',
                                      '    print label + " [OK]"', '  else', '    print label + " [FAIL]"', '  end if',
                                      'end function', "", 'print "=== EXTERN NAMESPACED ==="', "namespace win32",
                                      '  extern function GetCurrentProcessId() from "kernel32.dll" returns u32',
                                      "end namespace", "", "pid = win32.GetCurrentProcessId()",
                                      'ok(pid > 0, "win32.GetCurrentProcessId > 0")', "", "a = w.GetTickCount()",
                                      "b = w.GetTickCount()", 'ok(b >= a, "w.GetTickCount monotonic")',
                                      'print "=== DONE ==="', ]) + "\n", encoding="utf-8", )

        return test_program_no_fail(name=name, mlc_runner=mlc_runner, ml_path=main_ml,
                                    must_contain=["=== EXTERN NAMESPACED ===", "win32.GetCurrentProcessId > 0 [OK]",
                                                  "w.GetTickCount monotonic [OK]", "=== DONE ===", ],
                                    timeout_compile_s=120, timeout_run_s=120, )


def test_extern_value_runtime(*, name: str, mlc_runner: Path) -> TestResult:
    """Runtime smoke test: extern stubs are first-class values (store/pass/return/call + survive GC)."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        main_ml = td_path / "extern_value_runtime.ml"

        main_ml.write_text("\n".join(
            ['extern function GetTickCount() from "kernel32.dll" returns u32', '', 'function ok(cond, label)',
             '  if cond then', '    print label + " [OK]"', '  else', '    print label + " [FAIL]"', '  end if',
             'end function', '', 'function call0(f)', '  return f()', 'end function', '', 'function make(f)',
             '  return f', 'end function', '', 'struct Box', '  fn', 'end struct', '',
             'print "=== EXTERN VALUE RUNTIME ==="', '', '// capture extern as value', 'f = GetTickCount', 'a = f()',
             'b = f()', 'ok(b >= a, "direct value call")', '', '// store in array and call via index-expression callee',
             'arr = [f]', 'c = arr[0]()', 'd = arr[0]()', 'ok(d >= c, "array element call")', '',
             '// store in struct field (note: bx.fn() is parsed as namespace call; use temp)', 'bx = Box(f)',
             'h = bx.fn', 'e = h()', 'ok(e >= a, "struct field call")', '',
             '// pass as argument / return from function', 'ok(call0(f) >= a, "passed as arg")', 'g = make(f)',
             'ok(g() >= a, "returned value")', '',
             '// allocate many ephemeral objects and run GC repeatedly, then call again', 'for i = 0 to 20000',
             '  tmp = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" + i', '  tmp2 = [tmp, i, [i, tmp]]',
             '  if (i % 200) == 0 then', '    gc_collect()', '  end if', 'end for', 'gc_collect()',
             'ok(arr[0]() >= a, "after gc_collect")', '', 'print "=== DONE ==="', ]) + "\n", encoding="utf-8", )

        return test_program_no_fail(name=name, mlc_runner=mlc_runner, ml_path=main_ml,
                                    must_contain=["=== EXTERN VALUE RUNTIME ===", "direct value call [OK]",
                                                  "array element call [OK]", "struct field call [OK]",
                                                  "passed as arg [OK]", "returned value [OK]", "after gc_collect [OK]",
                                                  "=== DONE ===", ], timeout_compile_s=180, timeout_run_s=180, )


def test_extern_out_value_runtime(*, name: str, mlc_runner: Path) -> TestResult:
    """Runtime regression: first-class extern values keep the full declared ABI arity."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        main_ml = td_path / "extern_out_value_runtime.ml"

        main_ml.write_text("\n".join(
            ['import std.assert as t', '',
             # MulDiv really takes 3 scalar ints; marking the last parameter as `out`
             # exercises the callable-object arity metadata without depending on future
             # out-parameter lowering.
             'extern function MulDiv(a as int, b as int, out c as int) from "kernel32.dll" returns int', '',
             'print "=== EXTERN OUT VALUE RUNTIME ==="',
             't.assertEq(MulDiv(6, 7, 3), 14, "direct out-annotated call")', 'f = MulDiv',
             't.assertEq(f(6, 7, 3), 14, "extern value keeps full arity")', 'print "=== DONE ==="', ]) + "\n",
                           encoding="utf-8", )

        return test_program_no_fail(
            name=name,
            mlc_runner=mlc_runner,
            ml_path=main_ml,
            must_contain=[
                "=== EXTERN OUT VALUE RUNTIME ===",
                "direct out-annotated call [OK]",
                "extern value keeps full arity [OK]",
                "=== DONE ===",
            ],
            timeout_compile_s=180,
            timeout_run_s=180,
        )


def test_array_initializer_builtin(*, name: str, mlc_runner: Path) -> TestResult:
    """Runtime test: array(size[, fill]) supports void/default and custom fill initialization."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        main_ml = td_path / "array_initializer_builtin.ml"

        main_ml.write_text("\n".join([
            'function ok(cond, label)',
            '  if cond then',
            '    print label + " [OK]"',
            '  else',
            '    print label + " [FAIL]"',
            '  end if',
            'end function',
            '',
            'function mk(n, v)',
            '  return array(n, v)',
            'end function',
            '',
            'print "=== ARRAY INIT BUILTIN ==="',
            '',
            'a = array(4)',
            'ok(len(a) == 4, "array(size): len")',
            'ok(typeName(a[0]) == "void", "array(size): fill first void")',
            'ok(typeName(a[3]) == "void", "array(size): fill last void")',
            '',
            'b = array(5, 7)',
            'ok(len(b) == 5, "array(size,fill): len")',
            'ok(b[0] == 7, "array(size,fill): first")',
            'ok(b[4] == 7, "array(size,fill): last")',
            '',
            'c = array(3, "x")',
            'ok(c[1] == "x", "array(fill string)")',
            '',
            'd = [1, 2]',
            'e = array(2, d)',
            'ok(len(e[0]) == 2, "array(fill object): elem0 len")',
            'e[0][0] = 9',
            'ok(e[1][0] == 9, "array(fill object): shared value")',
            '',
            'f = mk(3, 11)',
            'ok(f[2] == 11, "array() inside function")',
            '',
            'n1 = try(array(-1))',
            'ok(typeof(n1) == "error", "array(size): negative -> error")',
            'ok(n1.code == 1307, "array(size): negative error code")',
            '',
            'n2 = try(array("4"))',
            'ok(typeof(n2) == "error", "array(size): non-int -> error")',
            'ok(n2.code == 1307, "array(size): non-int error code")',
            '',
            'n3 = try(array(2147483648))',
            'ok(typeof(n3) == "error", "array(size): too large -> error")',
            'ok(n3.code == 1307, "array(size): too large error code")',
            '',
            'print "=== DONE ==="',
        ]) + "\n", encoding="utf-8")

        return test_program_no_fail(
            name=name,
            mlc_runner=mlc_runner,
            ml_path=main_ml,
            must_contain=[
                "=== ARRAY INIT BUILTIN ===",
                "array(size): len [OK]",
                "array(size): fill first void [OK]",
                "array(size): fill last void [OK]",
                "array(size,fill): len [OK]",
                "array(size,fill): first [OK]",
                "array(size,fill): last [OK]",
                "array(fill string) [OK]",
                "array(fill object): elem0 len [OK]",
                "array(fill object): shared value [OK]",
                "array() inside function [OK]",
                "array(size): negative -> error [OK]",
                "array(size): negative error code [OK]",
                "array(size): non-int -> error [OK]",
                "array(size): non-int error code [OK]",
                "array(size): too large -> error [OK]",
                "array(size): too large error code [OK]",
                "=== DONE ===",
            ],
            timeout_compile_s=180,
            timeout_run_s=180,
        )


def test_callable_values_runtime(*, name: str, mlc_runner: Path) -> TestResult:
    """Runtime smoke test: first-class callables for user functions, struct ctors, and selected builtins, incl. GC."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        main_ml = td_path / "callable_values_runtime.ml"

        main_ml.write_text("\n".join(
            ['function ok(cond, label)', '  if cond then', '    print label + " [OK]"', '  else',
             '    print label + " [FAIL]"', '  end if', 'end function', '', 'function add1(x)', '  return x + 1',
             'end function', '', 'function apply1(f, x)', '  return f(x)', 'end function', '', 'function ident(x)',
             '  return x', 'end function', '', 'struct Pair', '  a', '  b', 'end struct', '',
             'print "=== CALLABLE VALUES RUNTIME ==="', '', '// user function as value', 'f = add1',
             'ok(f(41) == 42, "user fn direct value call")', 'arr = [f]',
             'ok(arr[0](5) == 6, "user fn array element call")', 'ok(apply1(f, 9) == 10, "user fn passed as arg")',
             'g = ident(f)', 'ok(g(7) == 8, "user fn returned value")', '', '// struct constructor as value',
             'ctor = Pair', 'p = ctor(1, 2)', 'ok(p.a == 1, "struct ctor via value (a)")',
             'ok(p.b == 2, "struct ctor via value (b)")', 'arrc = [ctor]', 'q = arrc[0](3, 4)',
             'ok(q.a == 3, "struct ctor array call")', '', '// builtin as value', 'l = len',
             'ok(l([1,2,3]) == 3, "builtin len via value (array)")',
             'ok(l("abc") == 3, "builtin len via value (string)")', 'arrl = [l]',
             'ok(arrl[0]([0,1,2,3]) == 4, "builtin len in array")', '',
             '// GC stress: allocate many temporaries, collect, and re-call values', 'for i = 0 to 20000',
             '  tmp = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" + i', '  tmp2 = [tmp, i, [i, tmp]]',
             '  if (i % 200) == 0 then', '    gc_collect()', '  end if', 'end for', 'gc_collect()',
             'ok(arr[0](41) == 42, "user fn after gc_collect")', 't = arrc[0](7, 8)',
             'ok(t.a == 7, "struct ctor after gc_collect")', 'ok(arrl[0]("abcd") == 4, "builtin len after gc_collect")',
             '', 'print "=== DONE ==="', ]) + "\n", encoding="utf-8", )

        return test_program_no_fail(name=name, mlc_runner=mlc_runner, ml_path=main_ml,
                                    must_contain=["=== CALLABLE VALUES RUNTIME ===", "user fn direct value call [OK]",
                                                  "user fn array element call [OK]", "user fn passed as arg [OK]",
                                                  "user fn returned value [OK]", "struct ctor via value (a) [OK]",
                                                  "struct ctor via value (b) [OK]", "struct ctor array call [OK]",
                                                  "builtin len via value (array) [OK]",
                                                  "builtin len via value (string) [OK]", "builtin len in array [OK]",
                                                  "user fn after gc_collect [OK]", "struct ctor after gc_collect [OK]",
                                                  "builtin len after gc_collect [OK]", "=== DONE ===", ],
                                    timeout_compile_s=180, timeout_run_s=180, )


def test_nested_closure_runtime(*, name: str, mlc_runner: Path) -> TestResult:
    """Runtime test: nested closures, env hops, and cached tiny strings behave across GC."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        main_ml = td_path / "nested_closure_runtime.ml"

        main_ml.write_text("\n".join(
            ['function ok(cond, label)', '  if cond then', '    print label + " [OK]"', '  else',
             '    print label + " [FAIL]"', '  end if', 'end function', '',
             'function makeCounter(seed)',
             '  n = seed',
             '  function step()',
             '    n = n + 1',
             '    return n',
             '  end function',
             '  return step',
             'end function',
             '',
             'function makeAdder(base)',
             '  function mid(delta)',
             '    function inner(z)',
             '      return base + delta + z',
             '    end function',
             '    return inner',
             '  end function',
             '  return mid',
             'end function',
             '',
             'function makePlain()',
             '  function plus1(x)',
             '    return x + 1',
             '  end function',
             '  return plus1',
             'end function',
             '',
             'print "=== NESTED CLOSURE RUNTIME ==="',
             'ctr = makeCounter(10)',
             'ok(ctr() == 11, "counter first call")',
             'ok(ctr() == 12, "counter second call")',
             '',
             'mid = makeAdder(100)',
             'inner = mid(7)',
             'ok(inner(5) == 112, "closure captures parent + local")',
             '',
             'plain = makePlain()',
             'ok(plain(41) == 42, "non-capturing nested fn")',
             '',
             's = "AZ"',
             'ok(s[0] == "A", "string index cached char")',
             'acc = ""',
             'for each ch in s',
             '  acc = acc + ch',
             'end for',
             'ok(acc == "AZ", "string foreach cached chars")',
             '',
             'for i = 0 to 20000',
             '  tmp = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" + i',
             '  tmp2 = [tmp, i, [i, tmp]]',
             '  if (i % 200) == 0 then',
             '    gc_collect()',
             '  end if',
             'end for',
             'gc_collect()',
             'ok(ctr() == 13, "counter after gc_collect")',
             'ok(inner(6) == 113, "closure after gc_collect")',
             'ok(plain(99) == 100, "plain fn after gc_collect")',
             'print "=== DONE ==="', ]) + "\n", encoding="utf-8", )

        return test_program_no_fail(
            name=name,
            mlc_runner=mlc_runner,
            ml_path=main_ml,
            must_contain=[
                "=== NESTED CLOSURE RUNTIME ===",
                "counter first call [OK]",
                "counter second call [OK]",
                "closure captures parent + local [OK]",
                "non-capturing nested fn [OK]",
                "string index cached char [OK]",
                "string foreach cached chars [OK]",
                "counter after gc_collect [OK]",
                "closure after gc_collect [OK]",
                "plain fn after gc_collect [OK]",
                "=== DONE ===",
            ],
            timeout_compile_s=180,
            timeout_run_s=180,
        )


def test_foreach_reentrant_runtime(*, name: str, mlc_runner: Path) -> TestResult:
    """Runtime regression: foreach loop state must stay isolated per activation."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        main_ml = td_path / "foreach_reentrant_runtime.ml"

        main_ml.write_text("\n".join(
            ['import std.assert as t', '',
             'function sumTree(n)', '  total = 0', '  for each x in [1, 2, 3]', '    total = total + x',
             '    if n > 0 and x == 1 then', '      total = total + sumTree(n - 1)', '    end if', '  end for',
             '  return total', 'end function', '',
             'print "=== FOREACH REENTRANT ==="',
             't.assertEq(sumTree(1), 12, "foreach recursion keeps state isolated")', 'print "=== DONE ==="', ]) + "\n",
                           encoding="utf-8", )

        return test_program_no_fail(
            name=name,
            mlc_runner=mlc_runner,
            ml_path=main_ml,
            must_contain=[
                "=== FOREACH REENTRANT ===",
                "foreach recursion keeps state isolated [OK]",
                "=== DONE ===",
            ],
            timeout_compile_s=180,
            timeout_run_s=180,
        )


def test_foreach_gc_root_runtime(*, name: str, mlc_runner: Path) -> TestResult:
    """Runtime regression: foreach must keep temporary iterables alive across GC."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        main_ml = td_path / "foreach_gc_root_runtime.ml"

        main_ml.write_text("\n".join(
            ['import std.assert as t', '',
             'print "=== FOREACH GC ROOT ==="', 'gc_set_limit(65536)', 'sum = 0', 'for each x in [1, 2, 3, 4]',
             '  tmp = array(2000, 123)', '  gc_collect()', '  sum = sum + x', 'end for',
             't.assertEq(sum, 10, "foreach keeps iterable alive across gc")', 'print "=== DONE ==="', ]) + "\n",
                           encoding="utf-8", )

        return test_program_no_fail(
            name=name,
            mlc_runner=mlc_runner,
            ml_path=main_ml,
            must_contain=[
                "=== FOREACH GC ROOT ===",
                "foreach keeps iterable alive across gc [OK]",
                "=== DONE ===",
            ],
            timeout_compile_s=180,
            timeout_run_s=180,
        )


def test_for_reentrant_runtime(*, name: str, mlc_runner: Path) -> TestResult:
    """Runtime regression: for-loop end/step state must stay isolated per activation."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        main_ml = td_path / "for_reentrant_runtime.ml"

        main_ml.write_text("\n".join(
            ['import std.assert as t', '',
             'function sumTree(n)', '  total = 0', '  for i = 1 to n + 2', '    total = total + i',
             '    if n > 0 and i == 1 then', '      total = total + sumTree(n - 1)', '    end if', '  end for',
             '  return total', 'end function', '',
             'print "=== FOR REENTRANT ==="',
             't.assertEq(sumTree(1), 9, "for recursion keeps activation-local end/step state")',
             'print "=== DONE ==="', ]) + "\n",
                           encoding="utf-8", )

        return test_program_no_fail(
            name=name,
            mlc_runner=mlc_runner,
            ml_path=main_ml,
            must_contain=[
                "=== FOR REENTRANT ===",
                "for recursion keeps activation-local end/step state [OK]",
                "=== DONE ===",
            ],
            timeout_compile_s=180,
            timeout_run_s=180,
        )


def test_codegen_plus_minus_one_fastpaths(*, name: str, mlc_runner: Path) -> TestResult:
    """Codegen regression: tagged-int +/-1 should use the immediate fast path in user code."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        main_ml = td_path / "plus_minus_one_fastpaths.ml"
        exe = td_path / "plus_minus_one_fastpaths.exe"
        asm_path = td_path / "plus_minus_one_fastpaths.asm"

        main_ml.write_text("\n".join([
            'function main(args)',
            '  x = 41',
            '  print(x + 1)',
            '  print(x - 1)',
            'end function',
        ]) + "\n", encoding="utf-8")

        cr = compile_native(
            mlc_runner,
            main_ml,
            exe,
            timeout_s=180,
            extra_args=['--asm', '--asm-out', str(asm_path)],
        )
        if cr.returncode != 0:
            return TestResult(name=name, status="FAIL", details=f"compile failed (exit {cr.returncode})",
                              stdout=cr.stdout, stderr=cr.stderr)

        rr = run_exe(exe, timeout_s=180)
        if rr.returncode == 999:
            return TestResult(name=name, status="SKIP", details=rr.stderr, stdout=cr.stdout, stderr=rr.stderr)
        if rr.returncode != 0:
            return TestResult(name=name, status="FAIL", details=f"runtime failed (exit {rr.returncode})",
                              stdout=rr.stdout, stderr=rr.stderr)

        out = normalize_out(rr.stdout).strip().splitlines()
        if out[:2] != ['42', '40']:
            return TestResult(name=name, status="FAIL", details="unexpected runtime output for +/-1 fastpath probe",
                              stdout=rr.stdout, stderr=rr.stderr)

        if not asm_path.exists():
            return TestResult(name=name, status="FAIL", details="compiler did not emit requested .asm listing",
                              stdout=cr.stdout, stderr=cr.stderr)

        asm_lines = normalize_out(asm_path.read_text(encoding="utf-8", errors="replace")).splitlines()
        start = None
        end = len(asm_lines)
        for i, line in enumerate(asm_lines):
            if line.lstrip().startswith("fn_user_main:"):
                start = i
                break
        if start is None:
            return TestResult(name=name, status="FAIL", details="fn_user_main not found in generated .asm listing")
        for i in range(start + 1, len(asm_lines)):
            stripped = asm_lines[i].lstrip()
            if stripped.startswith("fn_") and re.match(r"^[A-Za-z_][A-Za-z0-9_]*:", stripped):
                end = i
                break

        main_asm = "\n".join(asm_lines[start:end])
        required = ["; add_r64_imm(rax, 8)", "; sub_r64_imm(rax, 8)"]
        for marker in required:
            if marker not in main_asm:
                return TestResult(name=name, status="FAIL",
                                  details=f"missing optimized +/-1 codegen marker in fn_user_main: {marker}",
                                  stdout=rr.stdout, stderr=main_asm)

        forbidden = ["; add_r64_r64(rax, r11)", "; sub_rax_r11()"]
        for marker in forbidden:
            if marker in main_asm:
                return TestResult(name=name, status="FAIL",
                                  details=f"unexpected generic int arithmetic remained in fn_user_main: {marker}",
                                  stdout=rr.stdout, stderr=main_asm)

        return TestResult(name=name, status="PASS", stdout=rr.stdout, stderr="")




def test_nested_call_in_binary_expr_runtime(*, name: str, mlc_runner: Path) -> TestResult:
    """Runtime regression: nested helper calls inside binary expressions keep operand values stable."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        main_ml = td_path / "nested_call_in_binary_expr_runtime.ml"

        main_ml.write_text("\n".join([
            'import std.assert as t',
            '',
            'function byte_to_hex(v)',
            '  digits = "0123456789abcdef"',
            '  hi = (v >> 4) & 15',
            '  lo = v & 15',
            '  return digits[hi] + digits[lo]',
            'end function',
            '',
            'print "=== NESTED CALL IN BINARY EXPR ==="',
            'k = [0, 1, 2, 3]',
            'acc = ""',
            'i = 0',
            'while i < len(k)',
            '  acc = acc + byte_to_hex(k[i])',
            '  i = i + 1',
            'end while',
            't.assertEq(acc, "00010203", "nested helper call in + expression")',
            'print "=== DONE ==="',
        ]) + "\n", encoding="utf-8")

        return test_program_no_fail(
            name=name,
            mlc_runner=mlc_runner,
            ml_path=main_ml,
            must_contain=[
                "=== NESTED CALL IN BINARY EXPR ===",
                "nested helper call in + expression [OK]",
                "=== DONE ===",
            ],
            timeout_compile_s=180,
            timeout_run_s=180,
        )


def test_codegen_small_const_for_unroll(*, name: str, mlc_runner: Path) -> TestResult:
    """Codegen regression: tiny constant-trip for-loops should be unrolled."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        main_ml = td_path / "for_unroll_small_const.ml"
        exe = td_path / "for_unroll_small_const.exe"
        asm_path = td_path / "for_unroll_small_const.asm"

        main_ml.write_text("\n".join([
            'function main(args)',
            '  sum1 = 0',
            '  for i = 1 to(4)',
            '    sum1 = sum1 + i',
            '  end for',
            '  sum2 = 0',
            '  for j = 3 to(1)',
            '    sum2 = sum2 + j',
            '  end for',
            '  print(sum1)',
            '  print(sum2)',
            'end function',
        ]) + "\n", encoding="utf-8")

        cr = compile_native(
            mlc_runner,
            main_ml,
            exe,
            timeout_s=180,
            extra_args=['--asm', '--asm-out', str(asm_path)],
        )
        if cr.returncode != 0:
            return TestResult(name=name, status="FAIL", details=f"compile failed (exit {cr.returncode})",
                              stdout=cr.stdout, stderr=cr.stderr)

        rr = run_exe(exe, timeout_s=180)
        if rr.returncode == 999:
            return TestResult(name=name, status="SKIP", details=rr.stderr, stdout=cr.stdout, stderr=rr.stderr)
        if rr.returncode != 0:
            return TestResult(name=name, status="FAIL", details=f"runtime failed (exit {rr.returncode})",
                              stdout=rr.stdout, stderr=rr.stderr)

        out = normalize_out(rr.stdout).strip().splitlines()
        if out[:2] != ['10', '6']:
            return TestResult(name=name, status="FAIL",
                              details="unexpected runtime output for small const for-unroll probe",
                              stdout=rr.stdout, stderr=rr.stderr)

        if not asm_path.exists():
            return TestResult(name=name, status="FAIL", details="compiler did not emit requested .asm listing",
                              stdout=cr.stdout, stderr=cr.stderr)

        asm_lines = normalize_out(asm_path.read_text(encoding="utf-8", errors="replace")).splitlines()
        start = None
        end = len(asm_lines)
        for i, line in enumerate(asm_lines):
            if line.lstrip().startswith("fn_user_main:"):
                start = i
                break
        if start is None:
            return TestResult(name=name, status="FAIL", details="fn_user_main not found in generated .asm listing")
        for i in range(start + 1, len(asm_lines)):
            stripped = asm_lines[i].lstrip()
            if stripped.startswith("fn_") and re.match(r"^[A-Za-z_][A-Za-z0-9_]*:", stripped):
                end = i
                break

        main_asm = "\n".join(asm_lines[start:end])
        forbidden = ["for_top_", "for_cont_", "for_end_", "__for_end_", "__for_step_"]
        for marker in forbidden:
            if marker in main_asm:
                return TestResult(name=name, status="FAIL",
                                  details=f"small constant for-loop was not fully unrolled: found {marker!r} in fn_user_main",
                                  stdout=rr.stdout, stderr=main_asm)

        return TestResult(name=name, status="PASS", stdout=rr.stdout, stderr="")


def test_immediate_array_runtime(*, name: str, mlc_runner: Path) -> TestResult:
    """Runtime regression: immediate arrays stay semantically identical and upgrade on pointer stores."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        main_ml = td_path / "immediate_array_runtime.ml"

        main_ml.write_text("\n".join([
            'import std.assert as t',
            '',
            'print "=== IMMEDIATE ARRAY ==="',
            'a = array(4)',
            't.assertEq(len(a), 4, "array(size) len")',
            't.assertEq(typeName(a[0]), "void", "array(size) default fill")',
            't.assertEq(typeof(a), "array", "array(size) typeof")',
            't.assertEq(typeName(a), "array", "array(size) typeName")',
            'gc_collect()',
            't.assertEq(typeName(a[3]), "void", "array(size) survives gc")',
            '',
            'b = array(3, 7)',
            't.assertEq(b[2], 7, "array(fill int)")',
            'gc_collect()',
            't.assertEq(b[0], 7, "array(fill int) after gc")',
            '',
            'c = [1, 2, 3]',
            't.assertEq(len(c), 3, "literal immediate array len")',
            'gc_collect()',
            't.assertEq(c[1], 2, "literal immediate array after gc")',
            '',
            'd = array(2, 0)',
            'd[1] = "x"',
            'gc_collect()',
            't.assertEq(d[1], "x", "immediate array upgrades on pointer store")',
            '',
            'e = [1, 2] + [3, 4]',
            't.assertEq(len(e), 4, "immediate concat len")',
            'gc_collect()',
            't.assertEq(e[3], 4, "immediate concat after gc")',
            '',
            'f = []',
            'i = 0',
            'while i < 4',
            '  f = f + [i]',
            '  i = i + 1',
            'end while',
            'gc_collect()',
            't.assertEq(len(f), 4, "dynamic concat len")',
            't.assertEq(f[0], 0, "dynamic concat first")',
            't.assertEq(f[3], 3, "dynamic concat last")',
            '',
            'sum = 0',
            'for each x in [1, 2, 3, 4]',
            '  tmp = array(2000, 123)',
            '  gc_collect()',
            '  sum = sum + x',
            'end for',
            't.assertEq(sum, 10, "foreach over immediate array survives gc")',
            'print "=== DONE ==="',
        ]) + "\n", encoding="utf-8")

        return test_program_no_fail(
            name=name,
            mlc_runner=mlc_runner,
            ml_path=main_ml,
            must_contain=[
                "=== IMMEDIATE ARRAY ===",
                "array(size) len [OK]",
                "array(size) default fill [OK]",
                "array(size) typeof [OK]",
                "array(size) typeName [OK]",
                "array(size) survives gc [OK]",
                "array(fill int) [OK]",
                "array(fill int) after gc [OK]",
                "literal immediate array len [OK]",
                "literal immediate array after gc [OK]",
                "immediate array upgrades on pointer store [OK]",
                "immediate concat len [OK]",
                "immediate concat after gc [OK]",
                "dynamic concat len [OK]",
                "dynamic concat first [OK]",
                "dynamic concat last [OK]",
                "foreach over immediate array survives gc [OK]",
                "=== DONE ===",
            ],
            timeout_compile_s=180,
            timeout_run_s=180,
        )


def test_codegen_literal_query_fastpaths(*, name: str, mlc_runner: Path) -> TestResult:
    """Codegen regression: pure literal len/typeof/typeName queries should fold without helper calls."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        main_ml = td_path / "literal_query_fastpaths.ml"
        exe = td_path / "literal_query_fastpaths.exe"
        asm_path = td_path / "literal_query_fastpaths.asm"

        main_ml.write_text("\n".join([
            'function main(args)',
            '  print(len("abcd"))',
            '  print(typeof(1.25))',
            '  print(typeName([1, 2, 3]))',
            'end function',
        ]) + "\n", encoding="utf-8")

        cr = compile_native(
            mlc_runner,
            main_ml,
            exe,
            timeout_s=180,
            extra_args=['--asm', '--asm-out', str(asm_path)],
        )
        if cr.returncode != 0:
            return TestResult(name=name, status="FAIL", details=f"compile failed (exit {cr.returncode})",
                              stdout=cr.stdout, stderr=cr.stderr)

        rr = run_exe(exe, timeout_s=180)
        if rr.returncode == 999:
            return TestResult(name=name, status="SKIP", details=rr.stderr, stdout=cr.stdout, stderr=rr.stderr)
        if rr.returncode != 0:
            return TestResult(name=name, status="FAIL", details=f"runtime failed (exit {rr.returncode})",
                              stdout=rr.stdout, stderr=rr.stderr)

        out = normalize_out(rr.stdout).strip().splitlines()
        if out[:3] != ['4', 'float', 'array']:
            return TestResult(name=name, status="FAIL",
                              details="unexpected runtime output for literal query fastpath probe",
                              stdout=rr.stdout, stderr=rr.stderr)

        if not asm_path.exists():
            return TestResult(name=name, status="FAIL", details="compiler did not emit requested .asm listing",
                              stdout=cr.stdout, stderr=cr.stderr)

        asm_lines = normalize_out(asm_path.read_text(encoding="utf-8", errors="replace")).splitlines()
        start = None
        end = len(asm_lines)
        for i, line in enumerate(asm_lines):
            if line.lstrip().startswith("fn_user_main:"):
                start = i
                break
        if start is None:
            return TestResult(name=name, status="FAIL", details="fn_user_main not found in generated .asm listing")
        for i in range(start + 1, len(asm_lines)):
            stripped = asm_lines[i].lstrip()
            if stripped.startswith("fn_") and re.match(r"^[A-Za-z_][A-Za-z0-9_]*:", stripped):
                end = i
                break

        main_asm = "\n".join(asm_lines[start:end])
        forbidden = ["call fn_builtin_len", "call fn_typeof", "call fn_typeName"]
        for marker in forbidden:
            if marker in main_asm:
                return TestResult(name=name, status="FAIL",
                                  details=f"literal query fastpath still called runtime helper: {marker}",
                                  stdout=rr.stdout, stderr=main_asm)

        return TestResult(name=name, status="PASS", stdout=rr.stdout, stderr="")


def test_codegen_young_gc_heuristic_present(*, name: str, mlc_runner: Path) -> TestResult:
    """Codegen regression: fn_alloc should emit the young-allocation pressure counters."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        main_ml = td_path / "young_gc_heuristic.ml"
        exe = td_path / "young_gc_heuristic.exe"
        asm_path = td_path / "young_gc_heuristic.asm"

        main_ml.write_text("\n".join([
            'function main(args)',
            '  a = array(2, 1)',
            '  print(len(a))',
            'end function',
        ]) + "\n", encoding="utf-8")

        cr = compile_native(
            mlc_runner,
            main_ml,
            exe,
            timeout_s=180,
            extra_args=['--asm', '--asm-out', str(asm_path)],
        )
        if cr.returncode != 0:
            return TestResult(name=name, status="FAIL", details=f"compile failed (exit {cr.returncode})",
                              stdout=cr.stdout, stderr=cr.stderr)

        if not asm_path.exists():
            return TestResult(name=name, status="FAIL", details="compiler did not emit requested .asm listing",
                              stdout=cr.stdout, stderr=cr.stderr)

        asm_txt = normalize_out(asm_path.read_text(encoding="utf-8", errors="replace"))
        required = ["gc_young_bytes_since", "gc_young_bytes_limit"]
        for marker in required:
            if marker not in asm_txt:
                return TestResult(name=name, status="FAIL",
                                  details=f"young-allocation GC heuristic marker missing from asm: {marker}",
                                  stdout=cr.stdout, stderr=asm_txt)

        return TestResult(name=name, status="PASS", stdout=cr.stdout, stderr="")


def test_call_profile_counts(*, name: str, mlc_runner: Path) -> TestResult:
    """Runtime test: --profile-calls instruments user functions and exposes callStats()."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        main_ml = td_path / "call_profile_counts.ml"

        main_ml.write_text("\n".join([
            'import std.assert as t',
            '',
            'function cp_f()',
            '  return 1',
            'end function',
            '',
            'function cp_g()',
            '  // cp_f called twice per cp_g call',
            '  return cp_f() + cp_f()',
            'end function',
            '',
            'print "=== CALL PROFILE ==="',
            'cp_g()',
            'cp_g()',
            '',
            'stats = callStats()',
            'f_calls = 0',
            'g_calls = 0',
            'for each s in stats',
            '  if s.name == "cp_f" then f_calls = s.calls end if',
            '  if s.name == "cp_g" then g_calls = s.calls end if',
            'end for',
            '',
            't.assertEq(f_calls, 4, "callprof: cp_f calls")',
            't.assertEq(g_calls, 2, "callprof: cp_g calls")',
            'print "=== DONE ==="',
        ]) + '\n', encoding='utf-8')

        return test_program_no_fail(
            name=name,
            mlc_runner=mlc_runner,
            ml_path=main_ml,
            must_contain=["=== CALL PROFILE ===", "callprof: cp_f calls [OK]", "callprof: cp_g calls [OK]", "=== DONE ==="],
            timeout_compile_s=180,
            timeout_run_s=180,
            extra_args=['--profile-calls'],
        )


def test_trace_calls_preserves_params(*, name: str, mlc_runner: Path) -> TestResult:
    """Runtime test: --trace-calls must not corrupt incoming argument registers."""
    with tempfile.TemporaryDirectory(prefix="mltests_") as td:
        td_path = Path(td)
        main_ml = td_path / "trace_calls_params.ml"

        main_ml.write_text("\n".join([
            'function add4(a, b, c, d)',
            '  return a + b + c + d',
            'end function',
            '',
            'function gate(level, threshold)',
            '  if level >= threshold then',
            '    return 1',
            '  else',
            '    return 0',
            '  end if',
            'end function',
            '',
            'print add4(1, 2, 3, 4)',
            'print gate(5, 3)',
        ]) + '\n', encoding='utf-8')

        exe = td_path / "trace_calls_params.exe"
        cr = compile_native(mlc_runner, main_ml, exe, timeout_s=180, extra_args=['--trace-calls'])
        if cr.returncode != 0:
            return TestResult(name=name, status="FAIL", details=f"compile failed (exit {cr.returncode})",
                              stdout=cr.stdout, stderr=cr.stderr)

        rr = run_exe(exe, timeout_s=180)
        if rr.returncode == 999:
            return TestResult(name=name, status="SKIP", details=rr.stderr, stdout=cr.stdout, stderr=rr.stderr)
        if rr.returncode != 0:
            return TestResult(name=name, status="FAIL", details=f"run failed (exit {rr.returncode})",
                              stdout=rr.stdout, stderr=rr.stderr)

        out = normalize_out(rr.stdout)
        err = normalize_out(rr.stderr)
        for marker in ['10', '1']:
            if marker not in out:
                return TestResult(name=name, status="FAIL", details=f"missing expected stdout marker: {marker!r}",
                                  stdout=rr.stdout, stderr=rr.stderr)
        for marker in ['main', 'add4', 'gate']:
            if marker not in err:
                return TestResult(name=name, status="FAIL",
                                  details=f"missing expected trace marker in stderr: {marker!r}",
                                  stdout=rr.stdout, stderr=rr.stderr)

        return TestResult(name=name, status="PASS", stdout=rr.stdout, stderr=rr.stderr)

# -----------------------------
# Main
# -----------------------------


def main() -> int:
    """main helper."""
    ap = argparse.ArgumentParser(description="MiniLang unified test suite")
    ap.add_argument("--allow-skip", action="store_true", help="Exit 0 even if some tests are skipped")
    ap.add_argument("--verbose", action="store_true", help="Print full output for each test")
    ap.add_argument("--only", default=None, help="Only run tests whose name contains this substring")
    args = ap.parse_args()

    # Enable ANSI colors (best-effort) and decide whether we should emit them.
    _enable_windows_vt_mode()
    color_enabled = _use_color()

    tests_root = Path(__file__).resolve().parent
    project_root = tests_root.parent

    mlc_runner = locate_mlc_runner(project_root)
    if mlc_runner is None:
        print("[FATAL] Could not find mlc_win64.py (native compiler entrypoint).")
        return 2

    # Locate main test programs
    language_suite_ml = (find_file_by_name(tests_root, "language_suite.ml") or find_ml_containing(tests_root,
                                                                                                  "=== BASIC (INT/BOOL) ==="))
    aes_ml = (find_file_by_name(tests_root, "aes128_ecb_nist_kat.ml") or find_ml_containing(tests_root, "AES-128"))
    std_test_ml = find_file_by_name(tests_root, "stdlib_unit_tests.ml")
    gc_periodic_ml = find_file_by_name(tests_root, "gc_periodic_test.ml")
    ns_main = find_file_by_name(tests_root, "main.ml")
    # Prefer the ns/import main if multiple main.ml exist.
    ns_main = find_ml_containing(tests_root, "=== NS/IMPORT BASIC ===") or ns_main

    # Optional helpers for generated tests
    lib_bad = find_file_by_name(tests_root, "lib_bad.ml")
    geom_ml = find_file_by_name(tests_root, "geom.ml")
    testlib_ml = find_file_by_name(tests_root, "testlib.ml")

    tests: list[Callable[[], TestResult]] = []

    if language_suite_ml is not None:
        tests.append(lambda: test_program_no_fail(name="language_suite.ml (full language suite)", mlc_runner=mlc_runner,
                                                  ml_path=language_suite_ml,
                                                  must_contain=["=== BASIC (INT/BOOL) ===", "=== DONE ==="], ))
    else:
        tests.append(lambda: TestResult(name="language_suite.ml (full language suite)", status="SKIP",
                                        details="language_suite.ml not found"))

    # Stdlib unit tests (std.core/std.assert/native error handling)
    if std_test_ml is not None:
        tests.append(lambda: test_program_no_fail(name="stdlib_unit_tests.ml (stdlib unit)", mlc_runner=mlc_runner,
                                                  ml_path=std_test_ml,
                                                  must_contain=["=== STD (UNIT) ===", "=== DONE ==="],
                                                  timeout_compile_s=120, timeout_run_s=120, ))
    else:
        tests.append(lambda: TestResult(name="stdlib_unit_tests.ml (stdlib unit)", status="SKIP",
                                        details="stdlib_unit_tests.ml not found"))

    # Periodic GC smoke test (allocation-pressure trigger)
    if gc_periodic_ml is not None:
        tests.append(lambda: test_program_no_fail(name="gc_periodic_test.ml (gc periodic)", mlc_runner=mlc_runner,
                                                  ml_path=gc_periodic_ml,
                                                  must_contain=["=== GC PERIODIC ===", "=== DONE ==="],
                                                  timeout_compile_s=120, timeout_run_s=120, ))
    else:
        tests.append(lambda: TestResult(name="gc_periodic_test.ml (gc periodic)", status="SKIP",
                                        details="gc_periodic_test.ml not found"))

    # New error/try semantics (unhandled errors + reserved identifiers)
    tests.append(lambda: test_unhandled_error_top_level(name="unhandled error: top-level abort", mlc_runner=mlc_runner))
    tests.append(lambda: test_unhandled_error_main_return(name="unhandled error: main(args) return abort",
                                                          mlc_runner=mlc_runner))
    tests.append(lambda: test_unhandled_error_origin_top_level(name="unhandled error: origin (top-level)",
                                                               mlc_runner=mlc_runner))
    tests.append(lambda: test_unhandled_error_origin_main_return(name="unhandled error: origin (main return)",
                                                                 mlc_runner=mlc_runner))
    tests.append(lambda: test_unhandled_error_origin_omitted_when_cleared(name="unhandled error: origin omitted",
                                                                          mlc_runner=mlc_runner))
    tests.append(lambda: test_reserved_identifiers(name="reserved identifiers: try/error", mlc_runner=mlc_runner))

    # Diagnostics: keep-going (multi-error reporting)
    tests.append(lambda: test_keep_going_reports_multiple_errors(name="keep-going: reports multiple errors", mlc_runner=mlc_runner))
    tests.append(lambda: test_keep_going_respects_max_errors(name="keep-going: respects --max-errors", mlc_runner=mlc_runner))

    tests.append(lambda: test_member_call_arity_error_message(
        name="diagnostics: member-call arity reports expected", mlc_runner=mlc_runner))

    if aes_ml is not None:
        tests.append(lambda: test_aes_kat(name="aes128_ecb_nist_kat.ml (AES-128 ECB NIST KAT)", mlc_runner=mlc_runner,
                                          aes_ml=aes_ml))
    else:
        tests.append(lambda: TestResult(name="aes128_ecb_nist_kat.ml (AES-128 ECB NIST KAT)", status="SKIP",
                                        details="aes128_ecb_nist_kat.ml not found"))

    if ns_main is not None:
        tests.append(
            lambda: test_program_no_fail(name="ns/import framework (basic)", mlc_runner=mlc_runner, ml_path=ns_main,
                                         must_contain=["=== NS/IMPORT BASIC ===", "fubar.a() [OK]", "fubar.b() [OK]",
                                                       "=== DONE ==="], timeout_compile_s=120, timeout_run_s=120, ))
    else:
        # Fallback: generate a minimal ns/import test if we can find fubar.ml + testlib.ml
        fubar = find_file_by_name(tests_root, "fubar.ml")
        if fubar is not None and testlib_ml is not None:
            def _gen_ns_basic() -> TestResult:
                with tempfile.TemporaryDirectory(prefix="mltests_") as td:
                    td_path = Path(td)
                    main_gen = td_path / "ns_basic.ml"
                    fubar_abs = str(fubar.resolve()).replace("\\", "\\\\")
                    testlib_abs = str(testlib_ml.resolve()).replace("\\", "\\\\")
                    main_gen.write_text("\n".join(
                        [f'import "{testlib_abs}"', f'import "{fubar_abs}"', 'print "=== NS/IMPORT BASIC ==="',
                         'assertEq(fubar.a(), 1, "fubar.a()")', 'assertEq(fubar.b(), 2, "fubar.b()")',
                         'print "=== DONE ==="', ]) + "\n", encoding="utf-8", )
                    return test_program_no_fail(name="ns/import framework (generated basic)", mlc_runner=mlc_runner,
                                                ml_path=main_gen,
                                                must_contain=["=== NS/IMPORT BASIC ===", "fubar.a() [OK]",
                                                              "fubar.b() [OK]", "=== DONE ==="], timeout_compile_s=120,
                                                timeout_run_s=120, )

            tests.append(_gen_ns_basic)
        else:
            tests.append(lambda: TestResult(name="ns/import framework (basic)", status="SKIP",
                                            details="ns import main.ml not found"))

    # package directive (compile-time qualification)
    tests.append(lambda: test_package_basic(name="package directive (basic)", mlc_runner=mlc_runner))
    tests.append(lambda: test_package_dotted(name="package directive (dotted)", mlc_runner=mlc_runner))
    tests.append(lambda: test_import_as_alias(name="import: as alias", mlc_runner=mlc_runner))
    tests.append(lambda: test_import_module_package_mismatch(name="import: module/package mismatch rejected",
                                                             mlc_runner=mlc_runner))
    tests.append(
        lambda: test_import_package_path_mismatch(name="import: package/path mismatch rejected", mlc_runner=mlc_runner))
    tests.append(lambda: test_import_include_paths(name="import: include paths (-I)", mlc_runner=mlc_runner))
    tests.append(lambda: test_import_ambiguous_include_paths(name="import: ambiguous include paths rejected",
                                                             mlc_runner=mlc_runner))
    tests.append(lambda: test_package_not_first(name="package: must be first", mlc_runner=mlc_runner))
    tests.append(lambda: test_package_duplicate(name="package: duplicate rejected", mlc_runner=mlc_runner))
    tests.append(lambda: test_main_in_package(name="package: main(args) forbidden", mlc_runner=mlc_runner))

    # namespace improvements
    tests.append(lambda: test_namespace_dotted(name="namespace: dotted", mlc_runner=mlc_runner))
    tests.append(lambda: test_namespace_nested(name="namespace: nested", mlc_runner=mlc_runner))

    tests.append(lambda: test_import_cycle_allowed(name="import: cycle allowed (a.ml <-> b.ml)",
                                                  mlc_runner=mlc_runner))
    tests.append(lambda: test_import_self_ignored(name="import: self-import ignored", mlc_runner=mlc_runner))
    tests.append(lambda: test_module_init_order(name="module init: import order + before main", mlc_runner=mlc_runner))
    tests.append(lambda: test_module_init_once_in_cycle(name="module init: once per module in cycle", mlc_runner=mlc_runner))

    # Negative: imported module must be declaration-only
    if lib_bad is not None:
        tests.append(
            lambda: test_import_decl_only_violation(name="imported module must be declaration-only (lib_bad.ml)",
                                                    mlc_runner=mlc_runner, lib_bad=lib_bad))
    else:
        tests.append(lambda: TestResult(name="imported module must be declaration-only (lib_bad.ml)", status="SKIP",
                                        details="lib_bad.ml not found"))

    # Negative: user function call must match parameter arity
    tests.append(
        lambda: test_call_arity_mismatch(name="function call arity mismatch (foo expects 0)", mlc_runner=mlc_runner))

    # Negative: unknown enum variant should be a compile-time error
    tests.append(lambda: test_enum_unknown_variant(name="enum: unknown variant (Color.Nope)", mlc_runner=mlc_runner))

    # Negative: duplicate enum variants should be rejected
    tests.append(
        lambda: test_enum_duplicate_variant(name="enum: duplicate variant (Color.Red twice)", mlc_runner=mlc_runner))

    # Const / value-enum / constexpr import regressions
    tests.append(
        lambda: test_import_constexpr_ok(name="import: constexpr initializers accepted", mlc_runner=mlc_runner))
    tests.append(lambda: test_const_reassign_rejected(name="const: reassign rejected", mlc_runner=mlc_runner))
    tests.append(lambda: test_enum_autoinc_ignores_strings(name="enum: auto-increment ignores strings",
                                                           mlc_runner=mlc_runner))
    tests.append(lambda: test_no_newlines_required(name="syntax: newlines not required", mlc_runner=mlc_runner))
    tests.append(lambda: test_typequalified_instance_method_uses_this_rejected(
        name="struct methods: type-qualified call uses this rejected", mlc_runner=mlc_runner))
    tests.append(lambda: test_import_initializer_behavior(name="import: constexpr const initializer required",
                                                    mlc_runner=mlc_runner, kind="const"))
    tests.append(
        lambda: test_import_initializer_behavior(name="import: runtime global initializer allowed",
                                                   mlc_runner=mlc_runner, kind="global"))

    # main(args) entrypoint tests
    tests.append(
        lambda: test_main_args_and_exitcode(name="main(args): argv -> array<string> + exitcode", mlc_runner=mlc_runner))
    tests.append(lambda: test_main_void_exit0(name="main(args): void return exits 0", mlc_runner=mlc_runner))

    # Negative: main signature / placement checks
    tests.append(lambda: test_main_bad_arity0(name="main(args): arity 0 rejected", mlc_runner=mlc_runner))
    tests.append(lambda: test_main_bad_arity2(name="main(args): arity 2 rejected", mlc_runner=mlc_runner))
    tests.append(lambda: test_main_in_namespace(name="main(args): must be top-level", mlc_runner=mlc_runner))

    # Heap CLI config tests (reserve/commit flags)
    tests.append(lambda: test_heap_cli_config_applied(name="heap CLI: reserve/commit applied", mlc_runner=mlc_runner))
    tests.append(lambda: test_heap_cli_invalid_size(name="heap CLI: invalid size rejected", mlc_runner=mlc_runner))

    # Optional: namespace struct constructor
    tests.append(
        lambda: test_ns_struct_optional(name="ns/import struct constructor (geom.Point)", mlc_runner=mlc_runner,
                                        geom_ml=geom_ml, testlib_ml=testlib_ml))

    tests.append(lambda: test_extern_namespaced(name="extern: namespaced + import-as alias", mlc_runner=mlc_runner))

    # Runtime: array(size[, fill]) initializer forms
    tests.append(lambda: test_array_initializer_builtin(
        name="array init: array(size[, fill])", mlc_runner=mlc_runner))

    # Runtime: callable values (user/builtin/struct) + GC
    tests.append(
        lambda: test_callable_values_runtime(name="callables: user+builtin+struct values + GC", mlc_runner=mlc_runner))
    tests.append(lambda: test_nested_closure_runtime(name="closures: nested values + tiny string cache + GC",
                                                     mlc_runner=mlc_runner))

    # Runtime: call profiling (--profile-calls)
    tests.append(lambda: test_call_profile_counts(name="call profile: callStats() + counters", mlc_runner=mlc_runner))

    # Runtime: trace-calls must preserve argument registers
    tests.append(lambda: test_trace_calls_preserves_params(name="trace calls: preserves params", mlc_runner=mlc_runner))

    # Runtime: extern stubs are first-class values
    tests.append(lambda: test_extern_value_runtime(name="extern: value semantics + GC", mlc_runner=mlc_runner))
    tests.append(lambda: test_extern_out_value_runtime(name="extern: out value keeps full arity", mlc_runner=mlc_runner))
    tests.append(lambda: test_for_reentrant_runtime(name="for: reentrant state isolation", mlc_runner=mlc_runner))
    tests.append(lambda: test_foreach_reentrant_runtime(name="foreach: reentrant state isolation", mlc_runner=mlc_runner))
    tests.append(lambda: test_foreach_gc_root_runtime(name="foreach: iterable survives gc", mlc_runner=mlc_runner))
    tests.append(lambda: test_codegen_plus_minus_one_fastpaths(name="codegen: +/-1 fast paths in user main",
                                                              mlc_runner=mlc_runner))
    tests.append(lambda: test_nested_call_in_binary_expr_runtime(name="runtime: nested call inside binary expression",
                                                                 mlc_runner=mlc_runner))
    tests.append(lambda: test_codegen_small_const_for_unroll(name="codegen: small const for loops unrolled",
                                                             mlc_runner=mlc_runner))
    tests.append(lambda: test_immediate_array_runtime(name="arrays: immediate layout + upgrade semantics", mlc_runner=mlc_runner))
    tests.append(lambda: test_codegen_literal_query_fastpaths(name="codegen: literal len/typeof/typeName fast paths",
                                                              mlc_runner=mlc_runner))
    tests.append(lambda: test_codegen_young_gc_heuristic_present(name="codegen: young-allocation gc heuristic emitted",
                                                                 mlc_runner=mlc_runner))

    # Run
    only = (args.only or "").lower() if args.only else None
    results: list[TestResult] = []
    for t in tests:
        r = t()
        if only and only not in r.name.lower():
            continue
        results.append(r)

    # Report
    passed = [r for r in results if r.status == "PASS"]
    failed = [r for r in results if r.status == "FAIL"]
    skipped = [r for r in results if r.status == "SKIP"]

    def print_one(r: TestResult) -> None:
        if r.status == "PASS":
            st = _c(r.status, ANSI_GREEN, color_enabled)
        elif r.status == "FAIL":
            st = _c(r.status, ANSI_RED, color_enabled)
        elif r.status == "SKIP":
            st = _c(r.status, ANSI_YELLOW, color_enabled)
        else:
            st = r.status

        print(f"[{st}] {r.name}")
        if r.details:
            print("  " + r.details.replace("\n", "\n  "))
        if args.verbose and (r.stdout or r.stderr):
            if r.stdout:
                print("  --- stdout ---")
                print("\n".join("  " + ln for ln in normalize_out(r.stdout).splitlines()))
            if r.stderr:
                print("  --- stderr ---")
                print("\n".join("  " + ln for ln in normalize_out(r.stderr).splitlines()))
        elif r.status == "FAIL":
            # Show tail to keep it readable
            blob = normalize_out((r.stdout or "") + "\n" + (r.stderr or ""))
            blob = blob.strip("\n")
            if blob:
                print("  --- output (tail) ---")
                print("\n".join("  " + ln for ln in tail(blob).splitlines()))

    for r in results:
        print_one(r)

    print("\n=== SUMMARY ===")
    print(f"{_c('PASS', ANSI_GREEN, color_enabled)}: {len(passed)}")
    print(f"{_c('FAIL', ANSI_RED, color_enabled)}: {len(failed)}")
    print(f"{_c('SKIP', ANSI_YELLOW, color_enabled)}: {len(skipped)}")

    if failed:
        print("\n" + _c("NOT OK", ANSI_RED, color_enabled))
        return 1
    if skipped and not args.allow_skip:
        print("\n" + _c("NOT OK", ANSI_RED, color_enabled) + " (some tests were skipped; use --allow-skip to ignore)")
        return 1

    print("\n" + _c("OK", ANSI_GREEN, color_enabled))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
