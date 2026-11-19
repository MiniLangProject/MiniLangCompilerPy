#!/usr/bin/env python3
"""Compare exact numeric representations and MXCSR for raw float trees and loops.

The bundled driver tests four rounding modes crossed with DAZ/FTZ combinations.
It captures MXCSR before inspecting the result, restores the initial state before
formatting, and reads float payload bits through integer-only C memory copies.
Integer values are compared at their full MiniLang signed61 value; boolean bits
and loop counts are also compared. Only masked exceptions are exercised.

The test compares a frozen native baseline with current native and Python images.
It verifies native/Python byte identity and labelled raw-normalizer instruction
sequences. --inputs defaults to the mxcsr directory beside this public helper.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def invoke(command, env=None):
    result = subprocess.run([str(x) for x in command], capture_output=True,
                            text=True, env=env, timeout=180)
    if result.returncode:
        raise RuntimeError(f"{command}\n{result.returncode}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def parse(output, manifest):
    rows = []
    for line in output.splitlines():
        fields = line.split(":")
        assert len(fields) == 9, line
        mode, probe, actual, kind, tag, low, high, integer, iterations = fields
        mode, actual, tag, low, high, integer, iterations = map(
            int, (mode, actual, tag, low, high, integer, iterations))
        assert actual & ~63 == mode, (mode, actual, probe)
        assert kind in ("float", "int", "bool"), kind
        assert 0 <= low < 2**32 and 0 <= high < 2**32
        if kind == "float":
            assert tag in (0, 5)
            assert tag != 5 or high == 0
        rows.append(dict(mode=mode, probe=probe, mxcsr=actual,
                         sticky_flags=actual & 63, result_type=kind,
                         representation_tag=tag, payload_low=low, payload_high=high,
                         integer_value=integer, iteration_count=iterations))
    assert [(row["mode"], row["probe"]) for row in rows] == [
        (mode, probe) for mode in manifest["modes"] for probe in manifest["probes"]]
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--after", type=Path, required=True)
    parser.add_argument("--python-compiler", type=Path, required=True)
    parser.add_argument("--stdlib", type=Path, required=True)
    parser.add_argument("--inputs", type=Path,
                        default=Path(__file__).resolve().parent / "mxcsr")
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--cc", default="gcc")
    args = parser.parse_args()
    assert sys.platform.startswith("linux") and platform.machine() == "x86_64"
    for name in ("before", "after", "python_compiler", "stdlib", "inputs", "work"):
        setattr(args, name, getattr(args, name).resolve())
    assert args.work != args.inputs
    args.work.mkdir(parents=True, exist_ok=True)
    assert not (args.work / "results.json").exists(), "Do not overwrite recorded results"
    for name in ("float_probe.ml", "probe_bridge.c", "input_manifest.json"):
        shutil.copyfile(args.inputs / name, args.work / name)
    source, bridge = args.work / "float_probe.ml", args.work / "probe_bridge.c"
    manifest = json.loads((args.work / "input_manifest.json").read_text())
    library = args.work / "libphase9_mxcsr.so"
    bridge_command = [args.cc, "-O2", "-fPIC", "-shared", bridge, "-o", library]
    invoke(bridge_command)
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = str(args.work) + ":" + env.get("LD_LIBRARY_PATH", "")
    variants = {}
    for name, compiler in (("before", args.before), ("after", args.after),
                           ("python", args.python_compiler)):
        binary = args.work / name
        command = ([sys.executable, str(compiler)] if compiler.suffix == ".py" else [str(compiler)])
        command += [str(source), str(binary), "--target", "linux-x64",
                    "--no-object-pipeline", "--no-incremental", "-I", str(args.stdlib)]
        if name == "python":
            command += ["--dump-labels", str(args.work / "python.labels")]
        log = invoke(command)
        (args.work / (name + ".build.log")).write_text(log)
        binary.chmod(binary.stat().st_mode | 0o111)
        output = invoke([binary], env)
        (args.work / (name + ".stdout")).write_text(output)
        variants[name] = dict(compiler_sha256=sha(compiler), binary_sha256=sha(binary),
                              command=command, rows=parse(output, manifest))
    assert (args.work / "after").read_bytes() == (args.work / "python").read_bytes()
    assert variants["before"]["rows"] == variants["after"]["rows"] == variants["python"]["rows"]
    labels = dict((name, int(offset)) for name, offset in re.findall(
        r"(?m)^\[label\] ([^ ]+) (\d+)\s*$", (args.work / "python.labels").read_text()))
    image = (args.work / "python").read_bytes()
    normalizers = [(name, offset) for name, offset in labels.items()
                   if re.fullmatch(r"float_tree_normalize_\d+", name)]
    assert normalizers
    for name, offset in normalizers:
        code = image[offset:offset + 28]
        assert code[:16] == bytes.fromhex("f2 48 0f 2c c0 f2 48 0f 2a c8 66 0f 2e c1 0f 84"), name
        assert code[20:] == bytes.fromhex("f2 0f 5a d0 f3 0f 5a da"), name
        assert image[offset + 28:offset + 32] != bytes.fromhex("66 0f 2e c3"), name
    function_coverage = {}
    functions = sorted((offset, name) for name, offset in labels.items() if name.startswith("fn_user_"))
    for i, (start, name) in enumerate(functions):
        end = functions[i + 1][0] if i + 1 < len(functions) else len(image)
        count = sum(start <= offset < end for _name, offset in normalizers)
        if count:
            function_coverage[name] = count
    for name in ("treeLeft", "treeRight", "treeBoth", "treeCompareLeft", "treeCompareRight",
                 "loopLeft", "loopRight", "loopCondition"):
        assert function_coverage.get("fn_user_" + name, 0), name
    report = dict(
        success=True, platform="linux-x64", probe_cases=len(manifest["probes"]),
        control_modes=len(manifest["modes"]), paired_observations=len(variants["before"]["rows"]),
        observed_variants=3, native_python_byte_identical=True,
        exact_numeric_payloads_equal=True, flags_tags_counts_equal=True,
        controls_preserved=True, masked_exceptions_only=True,
        normalizer_sites_checked=len(normalizers), function_coverage=function_coverage,
        source_sha256=sha(source), bridge_source_sha256=sha(bridge),
        bridge_binary_sha256=sha(library), bridge_command=list(map(str, bridge_command)),
        bridge_compiler_version=invoke([args.cc, "--version"]).splitlines()[0],
        helper_sha256=sha(Path(__file__)),
        method=dict(timed=False, exact_numeric_result_bits_compared=True,
                    payload="Float32 immediate bits or float64 box payload, full signed61 integer values, raw boolean value.",
                    capture="Read MXCSR before result inspection; restore initial control state before printing; integer-only C payload loads.",
                    limitation="Masked exceptions only. No signal/trap delivery or exception-handler machine-state equivalence is tested."),
        variants=variants)
    (args.work / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k not in ("variants", "bridge_command")}))


if __name__ == "__main__":
    main()
