"""Cross-compiler compaction and optional UPX integration regression checks.

Run from either repository. --reference compares exact native bytes; --linux
also executes Linux targets (through WSL on Windows). UPX is explicit/optional.
TemporaryDirectory owns every generated file; no existing output is modified.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


def run(command, *, success=True, cwd=None):
    result = subprocess.run(list(map(str, command)), cwd=cwd, capture_output=True,
                            text=True, errors="replace", timeout=600)
    if (result.returncode == 0) != success:
        raise AssertionError(f"{command}\nexit={result.returncode}\n{result.stdout}\n{result.stderr}")
    return result.stdout.replace("\r\n", "\n")


def compiler_command(path):
    return [sys.executable, str(path)] if path.suffix == ".py" else [str(path)]


def execute(path, target):
    if target == "linux-x64" and os.name == "nt":
        linux = run(["wsl.exe", "wslpath", "-a", "-u", path.as_posix()]).strip()
        run(["wsl.exe", "chmod", "+x", linux])
        return run(["wsl.exe", "timeout", "120s", linux])
    if os.name != "nt":
        path.chmod(0o755)
    return run([path])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--reference", type=Path)
    parser.add_argument("--upx", type=Path)
    parser.add_argument("--linux", action="store_true")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    compiler = compiler_command(args.compiler.resolve())
    reference = compiler_command(args.reference.resolve()) if args.reference else None
    report = []
    targets = ["windows-x64"] if os.name == "nt" else ["linux-x64"]
    if args.linux and "linux-x64" not in targets:
        targets.append("linux-x64")
    with tempfile.TemporaryDirectory(prefix="ml compact & [safe] ") as folder:
        folder = Path(folder)
        for target in targets:
            for fixture, marker in (("optimizer_safety", "OPTIMIZER SAFETY [OK]"),
                                    ("runtime_codegen", "RUNTIME CODEGEN [OK]"),
                                    ("thread_features", "[OK]")):
                source = root / "tests" / (fixture + ".ml")
                image = folder / (target + "-" + fixture + ".exe")
                common = [source, image, "-I", root, "--target", target]
                run(compiler + common + ["--no-object-pipeline"], cwd=root)
                original = image.read_bytes()
                stdout = execute(image, target)
                assert marker in stdout, stdout
                if fixture == "optimizer_safety":
                    assert "982104" in stdout
                obj = folder / (target + "-" + fixture + "-obj.exe")
                run(compiler + [source, obj, "-I", root, "--target", target, "--object-pipeline"], cwd=root)
                assert obj.read_bytes() == original, f"MLO mismatch: {fixture} {target}"
                if reference:
                    ref = folder / (target + "-" + fixture + "-ref.exe")
                    run(reference + [source, ref, "-I", root, "--target", target], cwd=root)
                    assert ref.read_bytes() == original, f"compiler mismatch: {fixture} {target}"
                entry = dict(target=target, fixture=fixture, bytes=len(original),
                             sha256=hashlib.sha256(original).hexdigest(), runtime="pass", object_parity=True)
                if args.upx:
                    upx = ["--upx", args.upx.resolve()]
                    packed = folder / (image.stem + "-packed.exe")
                    start = time.perf_counter()
                    run(compiler + ["--pack-exe", image, packed] + upx, cwd=root)
                    entry["packing_seconds"] = time.perf_counter() - start
                    compressed = packed.read_bytes()
                    assert len(compressed) < len(original)
                    assert execute(packed, target) == stdout
                    restored = folder / (image.stem + "-restored.exe")
                    run(compiler + ["--unpack-exe", packed, restored] + upx, cwd=root)
                    assert restored.read_bytes() == original
                    assert image.read_bytes() == original
                    entry.update(packed_bytes=len(compressed), packed_sha256=hashlib.sha256(compressed).hexdigest(),
                                 exact_restore=True, packed_runtime="pass")
                    # Compile-time packing uses the same pipeline, exactly once.
                    compiled = folder / (image.stem + "-compile-packed.exe")
                    run(compiler + [source, compiled, "-I", root, "--target", target, "--object-pipeline", "--pack"] + upx, cwd=root)
                    assert compiled.read_bytes() == compressed, "compile/standalone packed mismatch"
                    if reference:
                        refpack = folder / (image.stem + "-reference-packed.exe")
                        run(reference + ["--pack-exe", image, refpack] + upx, cwd=root)
                        assert refpack.read_bytes() == compressed, "packed compiler mismatch"
                        refrestored = folder / (image.stem + "-reference-restored.exe")
                        run(reference + ["--unpack-exe", packed, refrestored] + upx, cwd=root)
                        assert refrestored.read_bytes() == original
                    run(compiler + ["--pack-exe", image, image] + upx, success=False, cwd=root)
                    run(compiler + ["--unpack-exe", packed, restored] + upx, success=False, cwd=root)
                    assert image.read_bytes() == original and restored.read_bytes() == original
                    damaged = folder / (image.stem + "-damaged.exe")
                    damaged.write_bytes(compressed[:-1] + bytes([compressed[-1] ^ 1]))
                    rejected = folder / (image.stem + "-rejected.exe")
                    run(compiler + ["--unpack-exe", damaged, rejected] + upx, success=False, cwd=root)
                    assert not rejected.exists()
                    assert not list(folder.glob("*.mlpack-*")), "private staging files leaked"
                    if fixture == "optimizer_safety":
                        # An existing but unsuitable tool must fail cleanly. The
                        # compile form retains its valid unpacked image; neither
                        # standalone failure nor publication can destroy input.
                        failed = folder / (image.stem + "-tool-failed.exe")
                        badtool = ["--upx", Path(sys.executable).resolve()]
                        run(compiler + ["--pack-exe", image, failed] + badtool, success=False, cwd=root)
                        assert not failed.exists() and image.read_bytes() == original
                        run(compiler + [source, failed, "-I", root, "--target", target, "--pack"] + badtool,
                            success=False, cwd=root)
                        assert failed.read_bytes() == original
                        run(compiler + ["--pack-exe", packed, rejected] + upx, success=False, cwd=root)
                        assert not rejected.exists()
                        assert not list(folder.glob("*.mlpack-*")), "failed packing leaked staging files"
                report.append(entry)
                print(f"PASS {target}: {fixture} ({len(original)} bytes)", flush=True)
        # Even an unused declaration must retain compiler diagnostics.
        invalid = folder / "invalid unused.ml"
        invalid.write_text("function unusedInvalid()\nreturn unknownVariable\nend function\nprint 1\n", encoding="utf-8")
        rejected = folder / "invalid.exe"
        run(compiler + [invalid, rejected, "-I", root], success=False, cwd=root)
        assert not rejected.exists()
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("COMPACTION/PACKING [OK]")


if __name__ == "__main__":
    main()
