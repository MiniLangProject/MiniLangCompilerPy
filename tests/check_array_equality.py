#!/usr/bin/env python3
"""Check streamed equality across compiler implementations, targets and GC modes.

Native execution follows the host OS. Other target images, including MinUX,
are byte-parity cross-builds only. Temporary binaries/objects are discarded;
the report retains commands, hashes and all execution output.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def command(path):
    return [sys.executable, str(path)] if path.suffix == ".py" else [str(path)]


def invoke(argv, cwd, *, expected=0, timeout=180):
    result = subprocess.run([str(x) for x in argv], cwd=cwd, capture_output=True,
                            text=True, encoding="utf-8", errors="replace", timeout=timeout)
    if result.returncode != expected:
        raise AssertionError((argv, result.returncode, result.stdout, result.stderr))
    return result.stdout + result.stderr


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    reference, compiler = args.reference.resolve(), args.compiler.resolve()
    baseline = args.baseline.resolve() if args.baseline else None
    peers = [("python", command(reference), []),
             ("native-direct", command(compiler), ["--no-object-pipeline"]),
             ("native-mlo", command(compiler), ["--object-pipeline"])]
    common = ["linux-x64", "windows-x64"]
    cases = [
        ("array_equality.ml", common + ["minux-x64"],
         ["--heap-reserve", "8m", "--heap-commit", "8m"], "ARRAY EQUALITY [OK]", 0),
        ("array_equality_threads.ml", common + ["minux-x64"],
         ["--heap-reserve", "8m", "--heap-commit", "8m"], "ARRAY EQUALITY THREADS [OK]", 0),
        ("array_equality_semantics.ml", common, [], "comparisons=484 true=46 checksum=339253559", 0),
        ("numeric_nan_normalization.ml", common, [], "NAN NORMALIZATION", 0),
        ("array_equality.ml", ["windows-x64"], ["--gc-concurrent"], "ARRAY EQUALITY [OK]", 0),
        ("array_equality_threads.ml", ["windows-x64"], ["--gc-concurrent"], "ARRAY EQUALITY THREADS [OK]", 0),
        ("array_equality_exhaustion.ml", common,
         ["--heap-reserve", "1m", "--heap-commit", "1m", "--no-gc-periodic"],
         "ARRAY EQUALITY entering exhausted workspace\nERROR: out of memory", 1),
    ]
    report = {"purpose": "Streaming array equality correctness and byte parity",
              "host": sys.platform,
              "limitations": ["Concurrent GC is supported only on windows-x64; other targets use the stop-the-world collector.",
                              "Cross-built Windows/MinUX executables are not runtime tests on a Linux host."],
              "native_compiler_sha256": hashlib.sha256(compiler.read_bytes()).hexdigest(),
              "versions": {"python": invoke(command(reference) + ["--version"], root).strip(),
                           "native": invoke(command(compiler) + ["--version"], root).strip()},
              "images": [], "baseline_semantics": None}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    try:
        for case_id, (fixture, targets, flags, marker, expected_exit) in enumerate(cases):
            source = root / "tests" / fixture
            for target in targets:
                hashes = []
                with tempfile.TemporaryDirectory(prefix="ml-array-equality-") as temporary:
                    for name, runner, pipeline in peers:
                        output = Path(temporary) / (name + (".exe" if target == "windows-x64" else ""))
                        argv = runner + [str(source), str(output), "--target", target, "-I", str(root), *pipeline, *flags]
                        compile_log = invoke(argv, root)
                        digest = hashlib.sha256(output.read_bytes()).hexdigest()
                        hashes.append(digest)
                        row = {"case": case_id, "fixture": fixture, "flags": flags, "target": target,
                               "compiler": name, "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                               "sha256": digest, "bytes": output.stat().st_size,
                               "command": argv, "executed": False, "compile_log": compile_log}
                        executable_target = ((os.name == "nt" and target == "windows-x64") or
                                             (sys.platform.startswith("linux") and target == "linux-x64"))
                        if executable_target:
                            text = invoke([output], root, expected=expected_exit, timeout=90)
                            assert marker in text and "[FAIL]" not in text, text
                            row.update(executed=True, exit_code=expected_exit, stdout=text)
                        report["images"].append(row)
                assert len(set(hashes)) == 1, (fixture, target, flags, hashes)
                print(f"[OK] {fixture} {target} {' '.join(flags)}: 3 byte-identical images", flush=True)
        if baseline:
            host_target = "windows-x64" if os.name == "nt" else "linux-x64"
            with tempfile.TemporaryDirectory(prefix="ml-array-semantics-") as temporary:
                output = Path(temporary) / ("baseline.exe" if os.name == "nt" else "baseline")
                source = root / "tests/array_equality_semantics.ml"
                invoke(command(baseline) + [str(source), str(output), "--target", host_target, "-I", str(root)], root)
                text = invoke([output], root)
                assert "comparisons=484 true=46 checksum=339253559" in text, text
                report["baseline_semantics"] = {"compiler": str(baseline), "stdout": text,
                                                "version": invoke(command(baseline) + ["--version"], root).strip()}
        report["status"] = "passed"
    except BaseException as error:
        report["status"] = "failed"
        report["error"] = str(error)
        raise
    finally:
        report["executed_images"] = sum(row["executed"] for row in report["images"])
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"[OK] {len(report['images'])} images; {report['executed_images']} native executions", flush=True)


if __name__ == "__main__":
    main()
