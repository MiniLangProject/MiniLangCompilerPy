#!/usr/bin/env python3
"""Reproduce the untimed Linux x86-64 float-consumer MXCSR comparison.

The bundled C bridge reads/writes MXCSR without floating arithmetic. Its exact
ML input was used in the recorded evaluation; no compiler-test checkout is
needed to generate the input. Each probe captures flags immediately after its
candidate returns and restores the original control state before printing.

Only masked exceptions are exercised. This check compares sticky flags, control
bits, result tags and iteration counts; it does not compare exact numeric
result bits or claim signal/trap behavior. The separate semantic fixture checks
numeric results. An initial development driver could not complete when it tried
to format infinity in the baseline program; the recorded and bundled driver
prints only flags, tags and integer counts and includes all 272 probe/mode pairs.

Requirements: Linux x86-64, Python 3.11+, GCC (or a compatible C compiler), the two
compiler executables and one shared standard-library root.

Example:
  python3 check_consumer_mxcsr.py --before /path/before-compiler \
    --after /path/after-compiler --stdlib /path/MiniLangCompilerPy \
    --work /path/fresh-mxcsr-run

The default input directory is mxcsr/ beside this script. --inputs can select
the same bundled files from another location. The work directory must differ
from the input directory; results never overwrite the published observations.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys


PROBES = (
    "fractional", "integer-child", "integer-chain", "positive-wrap",
    "negative-wrap", "wrap-zero", "nan-child", "quiet-nan-source",
    "signaling-nan-source", "subnormal-left", "subnormal-right", "f32-boundary",
    "infinity-child", "negative-zero", "condition-int", "condition-nan",
    "literal-subnormal",
)
MODES = tuple(0x1F80 | rounding | denormal
              for rounding in (0, 0x2000, 0x4000, 0x6000)
              for denormal in (0, 0x40, 0x8000, 0x8040))
METHOD = {
    "timed": False,
    "numeric_result_bits_compared": False,
    "comparison_fields": [
        "mode", "probe", "mxcsr", "sticky_flags", "result_type", "iteration_count",
    ],
    "control_modes": "Four rounding modes crossed with default, DAZ, FTZ and DAZ+FTZ.",
    "capture": "Prepare inputs, set masked MXCSR control mode, call candidate, read MXCSR, restore initial MXCSR, print only flags/tag/integer counter.",
    "scope": "Sticky exception flags and control bits plus result tags and iteration counts; numerical equality is checked by the separate semantic fixture.",
    "limitations": [
        "Masked exceptions only; signal/trap behavior is not tested.",
        "An initial development driver failed when attempting to format infinity in the baseline program. The recorded driver avoids floating-result formatting and retains all 272 probe/mode pairs.",
    ],
}


def invoke(command, *, env=None):
    result = subprocess.run([str(x) for x in command], capture_output=True,
                            text=True, env=env, timeout=180)
    if result.returncode:
        raise RuntimeError(f"{command}\nexit={result.returncode}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def digest(path):
    with path.open("rb") as handle:
        result = hashlib.file_digest(handle, "sha256")
    return result.hexdigest()


def parse_rows(output):
    rows = []
    for line in output.splitlines():
        mode, name, actual, kind, iterations = line.split(":", 4)
        mode, actual = int(mode), int(actual)
        if actual & ~63 != mode:
            raise AssertionError(f"MXCSR control bits changed: {mode} {actual} {name}")
        rows.append({
            "mode": mode, "probe": name, "mxcsr": actual,
            "sticky_flags": actual & 63, "result_type": kind,
            "iteration_count": int(iterations),
        })
    expected = [(mode, name) for mode in MODES for name in PROBES]
    if [(row["mode"], row["probe"]) for row in rows] != expected:
        raise AssertionError("Missing, duplicated or reordered MXCSR observations")
    return rows


def compiler_command(path):
    return [sys.executable, path] if path.suffix == ".py" else [path]


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--after", type=Path, required=True)
    parser.add_argument("--stdlib", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--inputs", type=Path,
                        default=Path(__file__).resolve().parent / "mxcsr")
    parser.add_argument("--cc", default="gcc",
                        help="C compiler executable for the small MXCSR bridge")
    args = parser.parse_args()
    if not sys.platform.startswith("linux") or platform.machine().lower() not in ("x86_64", "amd64"):
        parser.error("This reproduction requires a Linux x86-64 host.")
    args.before = args.before.resolve()
    args.after = args.after.resolve()
    args.stdlib = args.stdlib.resolve()
    args.work = args.work.resolve()
    args.inputs = args.inputs.resolve()
    if args.work == args.inputs:
        parser.error("--work must differ from the bundled input directory.")
    if not args.stdlib.is_dir() or not args.before.is_file() or not args.after.is_file():
        parser.error("Both compilers and the standard-library root must exist.")
    source_input = args.inputs / "consumer_mxcsr.ml"
    bridge_input = args.inputs / "mxcsr_bridge.c"
    reference = json.loads((args.inputs / "consumer_mxcsr.json").read_text())
    if digest(source_input) != reference["source_sha256"]:
        raise AssertionError("Bundled ML input differs from the recorded source")
    if digest(bridge_input) != reference["bridge_source_sha256"]:
        raise AssertionError("Bundled C bridge differs from the recorded source")
    args.work.mkdir(parents=True, exist_ok=True)
    source = args.work / source_input.name
    bridge = args.work / bridge_input.name
    shutil.copyfile(source_input, source)
    shutil.copyfile(bridge_input, bridge)
    library = args.work / "libphase8_mxcsr.so"
    invoke([args.cc, "-O2", "-fPIC", "-shared", bridge, "-o", library])
    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = str(args.work) + (
        ":" + env["LD_LIBRARY_PATH"] if env.get("LD_LIBRARY_PATH") else "")
    variants = {}
    for variant, compiler in (("before", args.before), ("after", args.after)):
        executable = args.work / variant
        invoke([*compiler_command(compiler), source, executable, "-I", args.stdlib,
                "--target", "linux-x64", "--no-object-pipeline"])
        executable.chmod(executable.stat().st_mode | 0o111)
        output = invoke([executable], env=env)
        (args.work / (variant + ".txt")).write_text(output)
        variants[variant] = {
            "compiler_sha256": digest(compiler),
            "binary_sha256": digest(executable), "rows": parse_rows(output),
        }
    if variants["before"]["rows"] != variants["after"]["rows"]:
        raise AssertionError("MXCSR state, result tags or iteration counts differ")
    report = {
        "success": True, "platform": "linux-x64", "probe_cases": len(PROBES),
        "control_modes": len(MODES), "paired_observations": len(MODES) * len(PROBES),
        "control_bits_preserved": True, "sticky_flags_tags_and_counts_equal": True,
        "masked_exceptions_only": True, "source_sha256": digest(source),
        "bridge_source_sha256": digest(bridge),
        "bridge_binary_sha256": digest(library), "method": METHOD,
        "variants": variants,
    }
    (args.work / "consumer_mxcsr.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"MXCSR PARITY [OK]: {len(MODES) * len(PROBES)} paired observations; controls and flags preserved")


if __name__ == "__main__":
    main()
