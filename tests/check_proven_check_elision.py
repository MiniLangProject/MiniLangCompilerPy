"""Check optimization semantics and Python/native/MLO output parity.

Execute Windows images on Windows and Linux images on Linux x86-64. Other
targets are compiled and compared byte-for-byte; they are never reported as
runtime-tested. An optional baseline compiler checks observable runtime output.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile


FIXTURES = {
    "proven_check_elision": "PROVEN CHECK ELISION [OK]",
    "proven_check_elision_typeof": "PROVEN CHECK TYPEOF [OK]",
    "numeric_typeflow_boxing": "NUMERIC TYPEFLOW BOXING [OK]",
    "numeric_typeflow_typeof": "NUMERIC TYPEFLOW TYPEOF [OK]",
    "numeric_typeflow_tofloat": "NUMERIC TYPEFLOW TOFLOAT [OK]",
    "type_checks": "[OK] exhaustive public is-type categories",
    "language_type_guard_object": "[OK] typed struct field guards",
    "type_query_resolution": "[OK] qualified and shadowed type queries",
    "type_flow_context": "[OK] type-flow function context",
    "type_flow_rebinding": "[OK] callable rebinding type flow",
    "inline_error_boundaries": "[OK] inline error boundaries, effects and monitor cleanup",
    "optimizer_safety": "OPTIMIZER SAFETY [OK]",
    "operator_overloading": "[OK] operator overloading",
    "codegen_bounded_fusion": "[OK] bounded concat and typed scalar replacement",
    "gc_box_float_safepoint": "[OK] gc_box_float_safepoint: PASS",
    "gc_float_call_roots": "[OK] gc_float_call_roots: PASS",
    "ordered_comparison": "[OK] dynamic ordered comparisons",
    "language_performance_features": "[OK] optimized language features",
    "language_extensions": "[OK] language extensions",
    "oop_monomorphic_dispatch": "[OK] monomorphic dispatch",
    "language_class": "[OK] classes, inheritance, overrides and runtime interfaces",
    "language_class_constructors": "[OK] class constructor parity and private fields",
    "language_class_dispatch": "[OK] polymorphic class dispatch",
    "language_class_features": "[OK] class initialization, visibility, abstract and final",
}


def command_for(compiler):
    """Invoke either a Python frontend or a native compiler executable."""
    compiler = str(compiler.resolve())
    return [sys.executable, compiler] if compiler.endswith(".py") else [compiler]


def invoke(command, timeout):
    """Return captured output and fail with the complete compiler/runtime error."""
    result = subprocess.run(command, capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{command}\nexit={result.returncode}\n"
                           f"{result.stdout}\n{result.stderr}")
    return {"stdout": result.stdout, "stderr": result.stderr}


def executable_target():
    """Identify the only target this host can execute without an emulator."""
    if platform.machine().lower() not in ("x86_64", "amd64"):
        return None
    if sys.platform.startswith("linux"):
        return "linux-x64"
    if os.name == "nt":
        return "windows-x64"
    return None


def inspect_assembly(fixture, assembly):
    """Prove that the intended paths are exercised, and exclusions remain."""
    checks = []

    def body(name):
        found = re.search(r"(?ms)^fn_user_" + re.escape(name) +
                          r":.*?(?=^fn_user_|\Z)", assembly)
        if not found:
            raise AssertionError(f"Missing function listing: {fixture} {name}")
        return found[0]

    def contains(name, marker, expected):
        if (marker in body(name)) != expected:
            raise AssertionError(f"Incorrect emission: {fixture} {name}: "
                                 f"{marker} expected={expected}")
        checks.append({"function": name, "marker": marker, "present": expected})

    if fixture == "proven_check_elision":
        for name, guarded in (("literalContracts", False),
                              ("literalFloatIsNotInt", True),
                              ("normalizedLiteralIsNotFloat", True),
                              ("localContract", True)):
            contains(name, "type_guard_valid_", guarded)

    if fixture == "numeric_typeflow_boxing":
        positive = ("fusedAddInts", "fusedAddFloats", "fusedMulFloats",
                    "fusedSubFloats", "fusedDepthTwo", "builtinConverted",
                    "branchTemporary", "loopTemporary", "parameterIntToFloat",
                    "parameterFloatToInt")
        negative = ("genericAddParent", "genericMulParent", "genericSubParent",
                    "optionalParameter", "noFuseSibling", "noFuseZeroLoop",
                    "noFuseLoopBack", "noFuseCall", "noFuseMember", "noFuseIndex",
                    "noFuseGlobal", "noFuseSynchronized", "noFuseCapture",
                    "noFuseConstantChild", "noFuseIntRight", "noFusePlainIntChild",
                    "fallibleConverted", "capturedConversionError", "capturedVoid",
                    "capturedError")
        for name in positive:
            contains(name, "float_parent_nobox_fast_", True)
            contains(name, "type_guard_valid_", True)
            text = body(name)
            regions = re.findall(
                r"(?ms)^float_parent_nobox_child_(\d+):(?P<code>.*?)"
                r"^float_parent_nobox_materialize_\1:", text)
            if not regions:
                raise AssertionError(f"Missing unboxed lifetime boundary: {name}")
            for label, code in regions:
                # Listings prefix instructions with addresses and machine
                # bytes, so the mnemonic is not at the start of the line.
                if re.search(r"(?i)\bcall\b", code):
                    raise AssertionError(f"Unboxed float crosses a call: {name} {label}")
            checks.append({"function": name, "call_free_unboxed_regions": len(regions)})
        for name in negative:
            contains(name, "float_parent_nobox_fast_", False)
        # The stressed function must still allocate its final boxed double.
        contains("fusedAddFloats", "call fn_box_float", True)
        contains("reassignedCall", "type_guard_valid_", True)
        contains("reassignedCall", "numeric_float_fast_", False)

    if fixture == "numeric_typeflow_typeof":
        contains("shadowedParameter", "type_guard_valid_", True)
        contains("shadowedParameter", "numeric_float_fast_", False)
        contains("shadowedParameter", "float_parent_nobox_fast_", False)
        contains("nestedReturn", "type_guard_valid_", True)

    if fixture == "numeric_typeflow_tofloat":
        contains("converted", "numeric_float_fast_", False)
        contains("converted", "float_parent_nobox_fast_", False)
    return checks


def main():
    """Compile the requested matrix, check parity and run host-native images."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python-compiler", type=Path, required=True)
    parser.add_argument("--native-compiler", type=Path)
    parser.add_argument("--baseline-compiler", type=Path)
    parser.add_argument("--target", action="append",
                        choices=("linux-x64", "windows-x64", "minux-x64"))
    parser.add_argument("--fixture", action="append", choices=tuple(FIXTURES))
    parser.add_argument("--gc-concurrent", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    fixtures = args.fixture or list(FIXTURES)
    targets = args.target or [executable_target() or "linux-x64"]
    flags = ["--gc-concurrent"] if args.gc_concurrent else []
    hosts = [("python", command_for(args.python_compiler), "--no-object-pipeline")]
    if args.native_compiler:
        native = command_for(args.native_compiler)
        hosts.extend([("native", native, "--no-object-pipeline"),
                      ("native-mlo", native, "--object-pipeline")])
    rows, runs, emissions = [], [], []
    report = {"host": platform.platform(), "flags": flags, "images": rows,
              "runtime_checks": runs, "emission_checks": emissions, "success": False}
    args.output.parent.mkdir(parents=True, exist_ok=True)

    try:
        with tempfile.TemporaryDirectory(prefix="ml_proven_checks_") as temporary:
            work = Path(temporary)
            for target in targets:
                for fixture in fixtures:
                    source = root / "tests" / (fixture + ".ml")
                    outputs = []
                    digests = []
                    for host, command, pipeline in hosts:
                        output = work / f"{target}-{fixture}-{host}.exe"
                        listing = work / f"{target}-{fixture}.asm"
                        inspect_paths = host == "python" and fixture in (
                            "proven_check_elision", "numeric_typeflow_boxing",
                            "numeric_typeflow_typeof", "numeric_typeflow_tofloat")
                        invocation = [*command, str(source), str(output), "-I", str(root),
                                      "--target", target, pipeline, *flags]
                        if inspect_paths:
                            invocation.extend(["--asm", "--asm-out", str(listing)])
                        invoke(invocation, 180)
                        if inspect_paths:
                            assembly = listing.read_text(encoding="utf-8")
                            emissions.append({"fixture": fixture, "target": target,
                                              "checks": inspect_assembly(fixture, assembly)})
                        data = output.read_bytes()
                        digest = hashlib.sha256(data).hexdigest()
                        rows.append({"fixture": fixture, "target": target, "host": host,
                                     "pipeline": pipeline, "sha256": digest,
                                     "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                                     "bytes": len(data), "command": invocation})
                        digests.append(digest)
                        outputs.append(output)
                    if len(set(digests)) != 1:
                        raise AssertionError(f"Output parity failed: {target} {fixture}")

                    runtime = "not executed on this host"
                    if target == executable_target():
                        output = outputs[0]
                        if os.name != "nt":
                            output.chmod(output.stat().st_mode | 0o111)
                        observed = invoke([str(output)], 120)
                        if FIXTURES[fixture] not in observed["stdout"]:
                            raise AssertionError(f"Missing success marker: {fixture}\n{observed}")
                        if "[FAIL]" in observed["stdout"]:
                            raise AssertionError(f"Failure marker: {fixture}\n{observed}")
                        run = {"fixture": fixture, "target": target, **observed}
                        if args.baseline_compiler:
                            baseline = work / f"{target}-{fixture}-baseline.exe"
                            invoke([*command_for(args.baseline_compiler), str(source),
                                    str(baseline), "-I", str(root), "--target", target,
                                    "--no-object-pipeline", *flags], 180)
                            if os.name != "nt":
                                baseline.chmod(baseline.stat().st_mode | 0o111)
                            reference = invoke([str(baseline)], 120)
                            if reference != observed:
                                raise AssertionError(f"Baseline behavior differs: {fixture}\n"
                                                     f"before={reference}\nafter={observed}")
                            run["baseline_output_equal"] = True
                        runs.append(run)
                        runtime = "runtime passed"
                    print(f"[OK] {target} {fixture}: {len(outputs)} identical image(s); "
                          f"{runtime}", flush=True)
        report["success"] = True
    finally:
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"PROVEN CHECK MATRIX [OK]: {len(rows)} images, {len(runs)} runtime cases",
          flush=True)


if __name__ == "__main__":
    main()
