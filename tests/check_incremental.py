"""Changed-build correctness, invalidation, corruption and byte-parity checks.

Run from either repository with --ml-compiler PATH to cover both native
pipelines as well as Python. Fixtures/caches live in an isolated build folder;
no application source, assets, saves, or installed compiler are modified.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ml-compiler", type=Path)
    parser.add_argument("--python-repo", type=Path)
    parser.add_argument("--target", choices=("windows-x64", "linux-x64"), default="windows-x64")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    pyrepo = args.python_repo or (repo if (repo / "mlc_win64.py").is_file() else repo.parent / "MiniLangCompilerPy")
    backends = [("python", [sys.executable, str(pyrepo / "mlc_win64.py")], [])]
    if args.ml_compiler:
        native = str(args.ml_compiler.resolve())
        backends += [("ml-mono", [native], ["--no-object-pipeline"]),
                     ("ml-mlo", [native], ["--object-pipeline"])]
    build = repo / "build"
    build.mkdir(exist_ok=True)
    rows = []
    with tempfile.TemporaryDirectory(prefix="incremental-check-", dir=build) as temp:
        root = Path(temp)
        (root / "main.ml").write_text('import "alpha.ml"\nimport "omega.ml"\nfunction main(args)\n  print alpha.value()\n  print omega.value()\nend function\n', encoding="utf-8")
        alpha_original = 'package alpha\nfunction value()\n  x = 40\n  return x + 2\nend function\n'
        omega_original = 'package omega\nfunction value()\n  x = "constant"\n  return x + " pool"\nend function\n'
        alpha = root / "alpha.ml"
        omega = root / "omega.ml"
        alpha.write_text(alpha_original, encoding="utf-8")
        omega.write_text(omega_original, encoding="utf-8")

        def compile_one(name, command, flags, scenario, cached, extra=(), success=True):
            output = root / (name + ("-cached" if cached else "-clean") + ".exe")
            options = ["--target", args.target, "--no-asm", *flags, *extra]
            if cached:
                options += ["--incremental-cache", str(root / ("cache-" + name))]
            started = time.perf_counter()
            result = subprocess.run([*command, str(root / "main.ml"), str(output), *options],
                                    cwd=repo, capture_output=True, text=True, timeout=180)
            elapsed = time.perf_counter() - started
            log = result.stdout + result.stderr
            if (result.returncode == 0) != success:
                raise AssertionError(f"{name}/{scenario}: unexpected exit {result.returncode}\n{log}")
            counters = re.findall(r"\[incremental\] reused=(\d+) compiled=(\d+) invalid=(\d+)", log)
            counts = tuple(sum(int(row[i]) for row in counters) for i in range(3))
            rows.append(dict(backend=name, scenario=scenario, cached=cached, seconds=round(elapsed, 6),
                             reused=counts[0], compiled=counts[1], invalid=counts[2], exit=result.returncode))
            return output, counts, log

        previous = None
        scenarios = [
            ("cold", lambda: None),
            ("unchanged", lambda: None),
            ("integer-body", lambda: alpha.write_text(alpha_original.replace("40", "41"), encoding="utf-8")),
            ("logic-body", lambda: alpha.write_text(alpha_original.replace("x + 2", "x - 2"), encoding="utf-8")),
            ("string-pool", lambda: omega.write_text(omega_original.replace("constant", "changed constant"), encoding="utf-8")),
            ("inline-body", lambda: alpha.write_text('package alpha\nfunction inline value()\n  return 78\nend function\n', encoding="utf-8")),
            ("inline-change", lambda: alpha.write_text('package alpha\nfunction inline value()\n  return 79\nend function\n', encoding="utf-8")),
            ("global-declaration", lambda: alpha.write_text('package alpha\nconst DELTA = 13\nfunction value()\n  return DELTA\nend function\n', encoding="utf-8")),
            ("global-change", lambda: alpha.write_text(alpha.read_text().replace("13", "14"), encoding="utf-8")),
            ("source-lines", lambda: alpha.write_text("// debug location changed\n" + alpha.read_text(), encoding="utf-8")),
        ]
        for scenario, mutate in scenarios:
            mutate()
            hashes = set()
            for name, command, flags in backends:
                cached, counts, _ = compile_one(name, command, flags, scenario, True)
                cached_hash = digest(cached)
                clean, _, _ = compile_one(name, command, flags, scenario, False)
                assert cached_hash == digest(clean), f"{name}/{scenario}: stale or different code"
                hashes.add(cached_hash)
                if scenario == "unchanged":
                    assert counts[0] >= 3 and counts[1] == 0, (name, scenario, counts)
                if scenario == "integer-body":
                    assert counts[0] > 0 and counts[1] > 0, (name, scenario, counts)
                if args.target == "windows-x64":
                    run = subprocess.run([str(cached)], capture_output=True, text=True, timeout=15)
                    assert run.returncode == 0, (name, scenario, run.stdout, run.stderr)
                    if scenario == "integer-body":
                        assert run.stdout.splitlines()[0].strip() == "43", run.stdout
            assert len(hashes) == 1, f"{scenario}: compiler/pipeline byte mismatch"
            if previous and scenario == "integer-body":
                assert hashes != previous, "changed source produced old executable"
            previous = hashes
            print(f"PASS {args.target}: {scenario}", flush=True)

        for name, command, flags in backends:
            cache = root / ("cache-" + name)
            entries = list(cache.rglob("*.mfc"))
            assert entries, (name, "no persistent fragments")
            for entry in entries:
                entry.write_bytes(b"broken/truncated cache\x00")
            cached, counts, _ = compile_one(name, command, flags, "corrupt-cache", True)
            clean, _, _ = compile_one(name, command, flags, "corrupt-cache", False)
            assert digest(cached) == digest(clean) and counts[2] > 0, (name, counts)
            cached, _, _ = compile_one(name, command, flags, "profile-options", True, ["--profile-calls"])
            clean, _, _ = compile_one(name, command, flags, "profile-options", False, ["--profile-calls"])
            assert digest(cached) == digest(clean), name

        # A definition can change only a function body while all raw files and
        # signatures stay identical. Its value must still invalidate fragments.
        alpha.write_text('package alpha\n#option FEATURE: bool = false\nfunction value()\n#if FEATURE\n  return 19\n#else\n  return 27\n#endif\nend function\n', encoding="utf-8")
        for define in ("false", "true"):
            for name, command, flags in backends:
                extra = ["-D", "FEATURE=" + define]
                cached, _, _ = compile_one(name, command, flags, "define-" + define, True, extra)
                clean, _, _ = compile_one(name, command, flags, "define-" + define, False, extra)
                assert digest(cached) == digest(clean), (name, "define", define)

        # Cache bypass must perform no writes, even when a directory is supplied.
        for name, command, flags in backends:
            cache = root / ("cache-" + name)
            before = {p.name: (p.stat().st_mtime_ns, digest(p)) for p in cache.rglob("*.mfc")}
            cached, counts, _ = compile_one(name, command, flags, "no-incremental", True, ["--no-incremental"])
            clean, _, _ = compile_one(name, command, flags, "no-incremental", False)
            after = {p.name: (p.stat().st_mtime_ns, digest(p)) for p in cache.rglob("*.mfc")}
            assert before == after and counts == (0, 0, 0) and digest(cached) == digest(clean), name

        # Independent processes may publish the same cache slot concurrently.
        for name, command, flags in backends:
            cache = root / ("parallel-" + name)
            def parallel_build(index):
                destination = root / f"parallel-{name}-{index}.exe"
                result = subprocess.run([*command, str(root / "main.ml"), str(destination),
                    "--target", args.target, "--no-asm", *flags, "--incremental-cache", str(cache)],
                    cwd=repo, capture_output=True, text=True, timeout=180)
                assert result.returncode == 0, result.stdout + result.stderr
                return digest(destination)
            with ThreadPoolExecutor(max_workers=2) as pool:
                assert len(set(pool.map(parallel_build, range(2)))) == 1
            assert not list(cache.rglob("*.tmp")), name

        alpha.write_text(alpha_original.replace("return x + 2", "return missing_identifier"), encoding="utf-8")
        for name, command, flags in backends:
            compile_one(name, command, flags, "new-diagnostic", True, success=False)
        print("PASS corruption, options, and newly introduced diagnostics", flush=True)

        # Manifest builds combine the old exact artifact cache with function
        # reuse after an edit. Explicit bypass must also reach MLO subprocesses.
        for name, command, flags in backends:
            alpha.write_text(alpha_original, encoding="utf-8")
            omega.write_text(omega_original, encoding="utf-8")
            manifest = root / (name + ".toml")
            output = root / (name + "-project.exe")
            project_cache = root / (name + "-project-cache")
            manifest.write_text('[project]\nentry = "main.ml"\n' +
                f'output = "{output.name}"\ncache_dir = "{project_cache.name}"\n' +
                f'target = "{args.target}"\nobject_pipeline = {str(name == "ml-mlo").lower()}\n', encoding="utf-8")
            def project_build(extra=()):
                result = subprocess.run([*command, "--project", str(manifest), "--no-asm", *extra],
                    cwd=repo, capture_output=True, text=True, timeout=180)
                assert result.returncode == 0, (name, result.stdout, result.stderr)
                return result.stdout
            project_build()
            original_hash = digest(output)
            assert "cache hit; restored" in project_build(), name
            alpha.write_text(alpha_original.replace("40", "41"), encoding="utf-8")
            edited_log = project_build()
            assert "cache hit; restored" not in edited_log and digest(output) != original_hash, name
            reused = re.findall(r"reused=(\d+)", edited_log)
            assert sum(map(int, reused)) > 0, (name, edited_log)
            clean, _, _ = compile_one(name, command, flags, "manifest-change", False)
            assert digest(output) == digest(clean), name
            before = {str(p.relative_to(project_cache)): (p.stat().st_mtime_ns, digest(p))
                      for p in project_cache.rglob("*") if p.is_file()}
            bypass_log = project_build(["--no-incremental", "--incremental-cache", str(project_cache)])
            after = {str(p.relative_to(project_cache)): (p.stat().st_mtime_ns, digest(p))
                     for p in project_cache.rglob("*") if p.is_file()}
            assert before == after and "reused=" not in bypass_log, (name, bypass_log)
        print("PASS manifest exact hits, partial reuse, and child-process bypass", flush=True)

    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    print(f"PASS {len(rows)} compilation checks ({len(backends)} backends)")


if __name__ == "__main__":
    main()
