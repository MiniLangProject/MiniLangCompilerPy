"""Regression matrix for lexical/global resolution, unrolling and GUI helpers.

Checks output bytes across compiler hosts and pipelines, and executes one image
per target/case. Run on Windows with WSL Ubuntu for the Linux runtime checks.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def invoke(command, *, stdin=None):
    result = subprocess.run(command, input=stdin, capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=180,
                            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
    if result.returncode:
        raise RuntimeError(f"{command}\nexit={result.returncode}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("python_compiler", type=Path)
    parser.add_argument("windows_compiler", type=Path)
    parser.add_argument("--linux-compiler", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("Run on Windows with WSL Ubuntu")
    root = Path(__file__).resolve().parents[1]
    linux_paths = {}

    def linux_path(path):
        key = Path(path).resolve().as_posix()
        if key not in linux_paths:
            linux_paths[key] = invoke(["wsl", "-d", "Ubuntu", "--", "wslpath", "-a", "-u", key]).strip()
        return linux_paths[key]

    hosts = [("python", [sys.executable, str(args.python_compiler.resolve())]),
             ("windows-ml", [str(args.windows_compiler.resolve())])]
    if args.linux_compiler:
        hosts.append(("linux-ml", ["wsl", "-d", "Ubuntu", "--", linux_path(args.linux_compiler)]))
    fixtures = [("method_globals.ml", "[OK] method globals"),
                ("for_unroll_budget.ml", "10"),
                ("type_flow_context.ml", "[OK] type-flow function context"),
                ("type_flow_rebinding.ml", "[OK] callable rebinding type flow")]
    rows = []
    with tempfile.TemporaryDirectory(prefix="ml_codegen_context_") as temporary:
        for target in ("windows-x64", "linux-x64"):
            cases = [(name, marker, []) for name, marker in fixtures]
            if target == "windows-x64":
                cases += [("gui_input.ml", "", ["--subsystem", "windows"]),
                          ("gui_input.ml", "", ["--subsystem", "windows", "--gc-concurrent"])]
            for case, (fixture, marker, flags) in enumerate(cases):
                digests = []
                executed = False
                for host, command in hosts:
                    for pipeline in ("--no-object-pipeline", "--object-pipeline"):
                        output = Path(temporary) / f"{target}-{case}-{host}-{pipeline[2:]}.exe"
                        path = linux_path if host == "linux-ml" else lambda p: str(Path(p).resolve())
                        invoke([*command, path(root / "tests" / fixture), path(output), "-I", path(root),
                                "--target", target, pipeline, *flags])
                        digest = hashlib.sha256(output.read_bytes()).hexdigest()
                        digests.append(digest)
                        rows.append(dict(fixture=fixture, target=target, flags=flags, host=host,
                                         pipeline=pipeline, sha256=digest, bytes=output.stat().st_size))
                        if not executed:
                            command_run = ([str(output)] if target == "windows-x64" else
                                           ["wsl", "-d", "Ubuntu", "--", linux_path(output)])
                            text = invoke(command_run, stdin="must not be read\n" if fixture == "gui_input.ml" else None)
                            if marker and marker not in text:
                                raise AssertionError((fixture, target, text))
                            executed = True
                if len(set(digests)) != 1:
                    raise AssertionError((target, fixture, flags, rows[-len(digests):]))
                print(f"[OK] {target} {fixture} {flags}: {len(digests)} identical images", flush=True)
    args.output.write_text(json.dumps({"images": rows}, indent=2) + "\n", encoding="utf-8")
    print(f"CODEGEN CONTEXT PARITY [OK]: {len(rows)} images", flush=True)


if __name__ == "__main__":
    main()
