"""Exercise fragment replay on existing language, optimizer, GC and thread tests."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ml-compiler", required=True, type=Path)
    ap.add_argument("--python-repo", type=Path)
    ap.add_argument("--target", default="windows-x64", choices=("windows-x64", "linux-x64"))
    ap.add_argument("--report", required=True, type=Path)
    args = ap.parse_args()
    repo = Path(__file__).resolve().parents[1]
    pyrepo = args.python_repo or (repo if (repo / "mlc_win64.py").is_file() else repo.parent / "MiniLangCompilerPy")
    backends = [("python", [sys.executable, str(pyrepo / "mlc_win64.py")], []),
                ("ml-mono", [str(args.ml_compiler.resolve())], ["--no-object-pipeline"]),
                ("ml-mlo", [str(args.ml_compiler.resolve())], ["--object-pipeline"])]
    fixtures = ["optimizer_safety", "codegen_optimizations", "language_performance_features",
                "defer_features", "language_lambda", "language_default_lambda", "language_variadic",
                "variadic_escape_lifetime", "language_optional", "language_match", "operator_overloading",
                "thread_features", "threading_stdlib", "thread_pool", "ordered_comparison"]
    if args.target == "windows-x64":
        fixtures += ["language_suite", "gc_concurrent_dead_function"]
    rows = []
    (repo / "build").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="incremental-regressions-", dir=repo / "build") as tmp:
        root = Path(tmp)
        for fixture in fixtures:
            source = pyrepo / "tests" / (fixture + ".ml")
            options = ["--gc-concurrent"] if fixture == "gc_concurrent_dead_function" else []
            all_hashes = set()
            all_outputs = set()
            for backend, command, flags in backends:
                for mode in ("clean", "cold", "warm"):
                    output = root / f"{fixture}-{backend}-{mode}.exe"
                    extra = [] if mode == "clean" else ["--incremental-cache", str(root / backend)]
                    result = subprocess.run([*command, str(source), str(output), "-I", str(pyrepo),
                        "--target", args.target, "--no-asm", *flags, *options, *extra],
                        cwd=repo, capture_output=True, text=True, timeout=300)
                    assert result.returncode == 0, (fixture, backend, mode, result.stdout, result.stderr)
                    counters = re.findall(r"reused=(\d+) compiled=(\d+) invalid=(\d+)", result.stdout)
                    hits = sum(int(row[0]) for row in counters)
                    misses = sum(int(row[1]) for row in counters)
                    if mode == "warm":
                        assert hits > 0 and misses == 0, (fixture, backend, counters, result.stdout[-500:])
                    digest = hashlib.sha256(output.read_bytes()).hexdigest()
                    all_hashes.add(digest)
                    execution = [str(output)]
                    if args.target == "linux-x64" and os.name == "nt":
                        path = subprocess.check_output(["wsl", "-d", "Ubuntu", "--", "wslpath", "-u", output.as_posix()], text=True).strip()
                        subprocess.run(["wsl", "-d", "Ubuntu", "--", "chmod", "+x", path], check=True, capture_output=True)
                        execution = ["wsl", "-d", "Ubuntu", "--", path]
                    elif args.target == "linux-x64":
                        output.chmod(0o755)
                    run = subprocess.run(execution, capture_output=True, text=True, timeout=180)
                    assert run.returncode == 0 and "Error occured" not in run.stdout, (fixture, backend, mode, run.stdout, run.stderr)
                    # Thread scheduling may permute diagnostic output, so each
                    # fixture's own assertions remain the runtime oracle.
                    rows.append(dict(fixture=fixture, backend=backend, mode=mode,
                        target=args.target, sha256=digest, reused=hits, compiled=misses, runtime="pass"))
            assert len(all_hashes) == 1, (fixture, "clean/incremental/compiler parity", all_hashes)
            print(f"PASS {fixture}: 9 identical executed images", flush=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    print(f"PASS {len(rows)} executed images")


if __name__ == "__main__":
    main()
