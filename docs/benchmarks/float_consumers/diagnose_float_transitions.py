#!/usr/bin/env python3
"""Count float-loop normalization and transition events in untimed diagnostics.

The original benchmark function is retained, with a one-call checksum driver.
Counter increments are PUSHFQ; INC qword [RIP+counter]; POPFQ. They do not touch
GPRs, XMM registers or MXCSR, restore RSP before original instructions, allocate
no heap memory and make no calls. Counters are intentionally non-atomic: these
diagnostics are only for the compiler's accepted single-threaded raw loops.

This reports event/instruction frequencies, not cycle costs or CPU percentages.
Never use the instrumented binaries for performance comparisons.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys


LABEL_EVENTS = {
    "guard": "guard_attempts",
    "fast": "raw_attempts",
    "condition": "raw_conditions",
    "commit": "raw_commits",
    "exit": "raw_exits",
    "deopt": "raw_deopts",
    "slow": "ordinary_entries",
    "reentry": "ordinary_reentries",
}
STAGES = ("entry", "condition", "body", "commit", "materialize_exit", "materialize_deopt")
COUNTERS = tuple(LABEL_EVENTS.values()) + (
    "guard_successes", "ordinary_body_iterations", "materialize_exit_calls",
    "materialize_deopt_calls", "materialize_value_groups",
) + tuple(f"{stage}_normalizer_{event}" for stage in ("condition", "body", "ordinary")
          for event in ("attempts", "passes")) + tuple(
    f"{stage}_raw_{kind}" for stage in STAGES for kind in ("loads", "stores")
) + ("raw_register_copies", "condition_integer_rejoins", "body_integer_rejoins")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def compiler_sources(compiler_root: Path):
    files = [compiler_root / "mlc_win64.py", *sorted((compiler_root / "mlc").rglob("*.py"))]
    return {str(path.relative_to(compiler_root)): sha(path) for path in files}


def install_hooks(compiler_root: Path):
    sys.path.insert(0, str(compiler_root))
    from mlc.asm import Asm
    from mlc.codegen import Codegen
    from mlc.constants import TAG_INT

    active = [None]
    instances = []
    original_init = Codegen.__init__
    original_function = Codegen.emit_user_function
    original_loop = Codegen._opt_emit_float_loop
    original_raw = Codegen._opt_emit_float_loop_raw
    original_normalize = Codegen._opt_emit_float_tree_normalize
    original_stmt_list = Codegen._emit_stmt_list
    original_expr = Codegen.emit_expr
    original_force_float = Codegen.emit_force_xmm0_to_float_value
    original_mark = Asm.mark
    original_load = Asm.movsd_xmm_membase_disp
    original_store = Asm.movsd_membase_disp_xmm
    original_regcopy = Asm.movapd_xmm_xmm
    original_immstore = Asm.mov_membase_disp_imm32

    def context(asm=None):
        ctx = active[0]
        if ctx is None or not ctx["accepted"]:
            return None
        if asm is not None and ctx["cg"].asm is not asm:
            return None
        return ctx

    def increment(cg, name):
        assert name in COUNTERS, name
        a = cg.asm
        # No helper calls or live-register spills; preserve arithmetic flags.
        a.emit(b"\x9c\x48\xff\x05")
        patch = a.pos
        a.emit32(0)
        a.patches.append((patch, "phase8_diag_" + name, "rip32"))
        a.emit(b"\x9d")
        cg._phase8_diag_static[name] += 1

    def init(cg, *args, **kwargs):
        original_init(cg, *args, **kwargs)
        cg._phase8_diag_function = None
        cg._phase8_diag_static = Counter()
        cg._phase8_diag_loops = []
        cg.data.pad_align(8)
        for name in COUNTERS:
            cg.data.add_u64("phase8_diag_" + name, 0)
        instances.append(cg)

    def function(cg, fn):
        previous = cg._phase8_diag_function
        cg._phase8_diag_function = str(getattr(fn, "name", ""))
        try:
            return original_function(cg, fn)
        finally:
            cg._phase8_diag_function = previous

    def loop(cg, stmt):
        if cg._phase8_diag_function != "bench" or cg._float_loop_disabled:
            return original_loop(cg, stmt)
        plan = cg._opt_float_loop_shape(stmt)
        if plan is None:
            return original_loop(cg, stmt)
        previous = active[0]
        ctx = dict(cg=cg, stmt=stmt, plan=plan, accepted=False, stage="entry", raw_depth=0,
                   consumer_stages={})
        active[0] = ctx
        try:
            result = original_loop(cg, stmt)
            if result:
                cg._phase8_diag_loops.append(dict(
                    state_slots=len(plan["states"]), definitions=len(plan["definitions"]),
                    output_bindings=len(plan["outputs"]),
                    distinct_output_definitions=len({d for _, d, _ in plan["outputs"]}),
                    compound=plan["escape"] is not None,
                    raw_arena_bytes=plan["bytes"]))
            return result
        finally:
            active[0] = previous

    def mark(asm, label):
        original_mark(asm, label)
        ctx = active[0]
        if ctx is None or ctx["cg"].asm is not asm:
            return
        match = re.fullmatch(r"float_loop_(guard|fast|condition|commit|exit|deopt|slow|reentry)_\d+", label)
        if match:
            event = match[1]
            if event == "guard":
                ctx["accepted"] = True
            if not ctx["accepted"]:
                return
            ctx["stage"] = {"guard": "entry", "fast": "body", "condition": "condition",
                            "commit": "commit", "exit": "exit", "deopt": "deopt",
                            "slow": "ordinary", "reentry": "ordinary"}[event]
            increment(ctx["cg"], LABEL_EVENTS[event])
        elif ctx["accepted"] and re.fullmatch(r"float_loop_consumer_\d+", label):
            assert ctx["stage"] in ("condition", "body")
            ctx["consumer_stages"][label.removeprefix("float_loop_consumer_")] = ctx["stage"]
        elif ctx["accepted"] and re.fullmatch(r"float_loop_consumer_int_\d+", label):
            stage = ctx["consumer_stages"][label.removeprefix("float_loop_consumer_int_")]
            # Out-of-line integer stubs need RAX's conversion result intact.
            # RIP-relative INC preserves every GPR and restores arithmetic flags.
            increment(ctx["cg"], stage + "_integer_rejoins")
        elif ctx["accepted"] and re.fullmatch(r"float_loop_materialize_\d+", label):
            stage = "materialize_deopt" if ctx["stage"] == "deopt" else "materialize_exit"
            ctx["stage"] = stage
            increment(ctx["cg"], stage + "_calls")

    def raw(cg, expr, *args, **kwargs):
        ctx = context()
        if ctx is None or ctx["cg"] is not cg:
            return original_raw(cg, expr, *args, **kwargs)
        if ctx["raw_depth"] == 0:
            escape = ctx["plan"]["escape"]
            ctx["stage"] = ("condition" if escape is not None and
                            (expr is escape.left or expr is escape.right) else "body")
        ctx["raw_depth"] += 1
        try:
            return original_raw(cg, expr, *args, **kwargs)
        finally:
            ctx["raw_depth"] -= 1

    def normalize(cg, slow):
        ctx = context()
        if ctx is None or ctx["cg"] is not cg:
            return original_normalize(cg, slow)
        stage = ctx["stage"] if ctx["raw_depth"] else "ordinary"
        assert stage in ("condition", "body", "ordinary"), stage
        increment(cg, stage + "_normalizer_attempts")
        original_normalize(cg, slow)
        # Both an actual bailout and a successful integer canonicalization
        # branch past this increment. Integer stubs rejoin after this site.
        increment(cg, stage + "_normalizer_passes")

    def raw_access(asm, base, disp, kind):
        ctx = context(asm)
        if ctx is None or ctx["stage"] not in STAGES or base != "rsp":
            return
        cg = ctx["cg"]
        start = cg._float_loop_raw_base
        if start <= disp < start + cg._float_loop_raw_size:
            increment(cg, ctx["stage"] + "_raw_" + kind)

    def load(asm, dst, base, disp=0):
        raw_access(asm, base, disp, "loads")
        return original_load(asm, dst, base, disp)

    def store(asm, base, disp, src):
        raw_access(asm, base, disp, "stores")
        return original_store(asm, base, disp, src)

    def regcopy(asm, dst, src):
        ctx = context(asm)
        if ctx is not None and ctx["stage"] in ("condition", "body") and dst != src:
            increment(ctx["cg"], "raw_register_copies")
        return original_regcopy(asm, dst, src)

    def immstore(asm, base, disp, imm, *args, **kwargs):
        ctx = context(asm)
        if ctx is not None and ctx["stage"] == "entry" and base == "rsp" and imm == 0:
            plan, cg = ctx["plan"], ctx["cg"]
            flag = cg._float_loop_raw_base + (len(plan["states"]) + len(plan["definitions"])) * 8
            if disp == flag:
                increment(cg, "guard_successes")
        return original_immstore(asm, base, disp, imm, *args, **kwargs)

    def stmt_list(cg, stmts):
        ctx = context()
        if (ctx is not None and ctx["cg"] is cg and cg._float_loop_disabled
                and stmts is ctx["stmt"].body):
            increment(cg, "ordinary_body_iterations")
        return original_stmt_list(cg, stmts)

    def force_float(cg):
        ctx = context()
        if ctx is not None and ctx["cg"] is cg and ctx["stage"].startswith("materialize_"):
            increment(cg, "materialize_value_groups")
        return original_force_float(cg)

    def expr(cg, node, **kwargs):
        ml = cg.ml
        if (type(node) is ml.Call and type(node.callee) is ml.Var
                and node.callee.name == "phase8DiagnosticRead"):
            assert len(node.args) == 1 and type(node.args[0]) is ml.Num
            index = node.args[0].value
            assert type(index) is int and 0 <= index < len(COUNTERS)
            cg.asm.mov_rax_rip_qword("phase8_diag_" + COUNTERS[index])
            cg.asm.shl_rax_imm8(3)
            cg.asm.or_rax_imm8(TAG_INT)
            return
        return original_expr(cg, node, **kwargs)

    Codegen.__init__ = init
    Codegen.emit_user_function = function
    Codegen._opt_emit_float_loop = loop
    Codegen._opt_emit_float_loop_raw = raw
    Codegen._opt_emit_float_tree_normalize = normalize
    Codegen._emit_stmt_list = stmt_list
    Codegen.emit_force_xmm0_to_float_value = force_float
    Codegen.emit_expr = expr
    Asm.mark = mark
    Asm.movsd_xmm_membase_disp = load
    Asm.movsd_membase_disp_xmm = store
    Asm.movapd_xmm_xmm = regcopy
    Asm.mov_membase_disp_imm32 = immstore
    return instances


def compile_action(args):
    instances = install_hooks(args.compiler_root.resolve())
    from mlc.compiler import main
    code = main([str(args.compiler_root / "mlc_win64.py"), *args.compiler_args])
    save(args.metadata, dict(instrumentation="PUSHFQ; INC qword [RIP+counter]; POPFQ",
                            counter_order=COUNTERS,
                            instances=[dict(static_sites=dict(cg._phase8_diag_static),
                                            loops=cg._phase8_diag_loops) for cg in instances]))
    return code


def invoke(command, *, cpu=None):
    if cpu is not None:
        command = ["taskset", "-c", str(cpu), *map(str, command)]
    result = subprocess.run(command, text=True, capture_output=True, timeout=240)
    if result.returncode:
        raise RuntimeError(f"{command}\n{result.returncode}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def run_action(args):
    args.work.mkdir(parents=True, exist_ok=True)
    inputs = args.work / "inputs"
    inputs.mkdir(exist_ok=True)
    output = args.work / args.variant
    output.mkdir(exist_ok=True)
    spec = importlib.util.spec_from_file_location("diagnostic_oracle", args.suite / "verification/other_reference.py")
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    calibration = json.loads((args.suite / "results/calibration.json").read_text())
    rows = []
    for case in ("float_recurrence", "mandelbrot"):
        original_source = args.suite / "inputs" / (case + ".ml")
        original_text = original_source.read_text()
        prefix, marker, _ = original_text.partition("// Appended to each independent MiniLang kernel.")
        if not marker:
            raise AssertionError("Original benchmark driver boundary missing")
        source = inputs / (case + ".ml")
        driver = ("\nfunction phase8DiagnosticRead(index as int) returns int\n"
                  "  return 0\nend function\n\nfunction main(args) returns int\n"
                  "  if len(args) != 2 then return 90 end if\n"
                  "  n = toNumber(args[0])\n  seed = toNumber(args[1])\n"
                  "  if n < 1 or seed < 0 or seed > 2147483647 then return 90 end if\n"
                  "  result = bench(n, seed)\n  print \"CHECKSUM \" + result\n")
        driver += "".join(f'  print "COUNTER {name} " + phase8DiagnosticRead({index})\n'
                          for index, name in enumerate(COUNTERS))
        driver += "  return 0\nend function\n"
        text = prefix + driver
        if source.exists() and source.read_text() != text:
            raise AssertionError("Existing shared diagnostic source differs")
        source.write_text(text)
        binary, metadata = output / case, output / (case + ".sites.json")
        command = [sys.executable, str(Path(__file__).resolve()), "compiler", "--compiler-root",
                   str(args.compiler_root), "--metadata", str(metadata), "--", str(source), str(binary),
                   "--target", "linux-x64", "--no-object-pipeline", "--no-incremental", "-I", str(args.stdlib)]
        invoke(command)
        binary.chmod(binary.stat().st_mode | 0o111)
        normal_binary = output / (case + "_uninstrumented")
        invoke([sys.executable, str(args.compiler_root / "mlc_win64.py"), str(source), str(normal_binary),
                "--target", "linux-x64", "--no-object-pipeline", "--no-incremental", "-I", str(args.stdlib)])
        normal_binary.chmod(normal_binary.stat().st_mode | 0o111)
        sizes = (1, 17, 67, calibration[case]["n"])
        for n in dict.fromkeys(sizes):
            for seed in args.seeds:
                stdout = invoke([str(binary), str(n), str(seed)], cpu=args.cpu)
                ordinary = invoke([str(normal_binary), str(n), str(seed)], cpu=args.cpu)
                found = re.search(r"^CHECKSUM (-?\d+)$", stdout, re.M)
                ordinary_found = re.search(r"^CHECKSUM (-?\d+)$", ordinary, re.M)
                expected = oracle.expected_checksum(case, n, seed)
                if not found or not ordinary_found or int(found[1]) != expected or int(ordinary_found[1]) != expected:
                    raise AssertionError((case, n, seed, expected, stdout, ordinary))
                counts = {name: int(value) for name, value in re.findall(r"^COUNTER (\w+) (\d+)$", stdout, re.M)}
                if set(counts) != set(COUNTERS):
                    raise AssertionError("Missing diagnostic counters")
                branches = {stage: counts[stage + "_normalizer_attempts"] - counts[stage + "_normalizer_passes"]
                            for stage in ("condition", "body", "ordinary")}
                rejoins = {stage: counts.get(stage + "_integer_rejoins", 0)
                           for stage in ("condition", "body", "ordinary")}
                deopts = {stage: branches[stage] - rejoins[stage] for stage in branches}
                if any(value < 0 for value in deopts.values()):
                    raise AssertionError(("Integer normalization accounting", counts, branches, rejoins))
                if deopts["condition"] + deopts["body"] != counts["raw_deopts"]:
                    raise AssertionError(("Raw normalization bailout accounting", counts, branches, rejoins, deopts))
                if counts["guard_successes"] != counts["raw_exits"] + counts["raw_deopts"]:
                    raise AssertionError(("Each admitted raw interval must exit or deoptimize", counts))
                total_iterations = counts["raw_commits"] + counts["ordinary_body_iterations"]
                if total_iterations != (n if case == "float_recurrence" else expected):
                    raise AssertionError(("Kernel iteration accounting", case, n, counts))
                rows.append(dict(case=case, variant=args.variant, n=n, seed=seed, checksum=expected,
                                 counts=counts, normalization_branches=branches,
                                 integer_rejoins=rejoins, normalization_deopts=deopts,
                                 total_body_iterations=total_iterations,
                                 source_sha256=sha(source), original_source_sha256=sha(original_source),
                                 binary_sha256=sha(binary), uninstrumented_binary_sha256=sha(normal_binary),
                                 uninstrumented_checksum_equal=True))
        print("DIAGNOSED", args.variant, case, flush=True)
    save(output / "counts.json", rows)
    save(output / "method.json", dict(
        method=__doc__, compiler_root=str(args.compiler_root), stdlib=str(args.stdlib),
        compiler_revision=invoke(["git", "-C", str(args.compiler_root), "rev-parse", "HEAD"]).strip(),
        compiler_source_sha256=compiler_sources(args.compiler_root),
        helper_sha256=sha(Path(__file__).resolve()), seeds=args.seeds,
        counters=COUNTERS, one_benchmark_call_per_process=True, no_warmup=True,
        timings_reported=False, checksum_against_oracle_and_uninstrumented=True,
        raw_access_scope="MOVSD to/from the private raw frame area in bench's accepted loop only",
        event_scope="bench function only; ordinary_entries includes false-condition visits",
        normalization_branches="attempts minus float-path passes; includes successful integer rejoin branches",
        normalization_deopts="normalization branches minus successful integer rejoins; condition+body equals raw_deopts",
        integer_rejoins="per-stage out-of-line canonicalizations counted without clobbering RAX",
        total_body_iterations="raw_commits plus ordinary_body_iterations; matches independent kernel oracle"))
    return 0


def compare_action(args):
    before = json.loads((args.work / args.before / "counts.json").read_text())
    after = json.loads((args.work / args.after / "counts.json").read_text())
    key = lambda row: (row["case"], row["n"], row["seed"])
    by_key = {key(row): row for row in after}
    if len(before) != len(after) or set(map(key, before)) != set(by_key):
        raise AssertionError("Mismatched diagnostic probe sets")
    rows = []
    for old in before:
        new = by_key[key(old)]
        for field in ("checksum", "source_sha256", "original_source_sha256"):
            if old[field] != new[field]:
                raise AssertionError((key(old), field))
        if old["total_body_iterations"] != new["total_body_iterations"]:
            raise AssertionError((key(old), "total_body_iterations"))
        old_loads = sum(v for name, v in old["counts"].items() if name.endswith("_raw_loads"))
        new_loads = sum(v for name, v in new["counts"].items() if name.endswith("_raw_loads"))
        old_stores = sum(v for name, v in old["counts"].items() if name.endswith("_raw_stores"))
        new_stores = sum(v for name, v in new["counts"].items() if name.endswith("_raw_stores"))
        rows.append(dict(case=old["case"], n=old["n"], seed=old["seed"], checksum=old["checksum"],
                         event_counts_unchanged=old["counts"] == new["counts"],
                         total_body_iterations=old["total_body_iterations"],
                         raw_commits={"before": old["counts"]["raw_commits"], "after": new["counts"]["raw_commits"]},
                         ordinary_body_iterations={"before": old["counts"]["ordinary_body_iterations"], "after": new["counts"]["ordinary_body_iterations"]},
                         raw_deopts={"before": old["counts"]["raw_deopts"], "after": new["counts"]["raw_deopts"]},
                         integer_rejoins={"before": old["integer_rejoins"], "after": new["integer_rejoins"]},
                         raw_loads=dict(before=old_loads, after=new_loads),
                         raw_stores=dict(before=old_stores, after=new_stores),
                         counter_delta={name: new["counts"][name] - value
                                        for name, value in old["counts"].items()
                                        if new["counts"][name] != value},
                         removed_raw_memory_instructions=old_loads + old_stores - new_loads - new_stores))
    result = dict(all_probes_preserve_results_and_total_iterations=True, compared_probes=len(rows),
                  invariants=("checksum", "source_sha256", "original_source_sha256", "total_body_iterations"), rows=rows,
                  limitation="Instruction/event frequencies do not establish CPU-time shares.")
    save(args.work / "comparison.json", result)
    print("COMPARED", len(rows), "diagnostic probe pairs; results and total iterations unchanged", flush=True)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    compile_parser = sub.add_parser("compiler")
    compile_parser.add_argument("--compiler-root", type=Path, required=True)
    compile_parser.add_argument("--metadata", type=Path, required=True)
    compile_parser.add_argument("compiler_args", nargs=argparse.REMAINDER)
    run = sub.add_parser("run")
    run.add_argument("--compiler-root", type=Path, required=True)
    run.add_argument("--suite", type=Path, required=True)
    run.add_argument("--stdlib", type=Path, required=True)
    run.add_argument("--work", type=Path, required=True)
    run.add_argument("--variant", required=True)
    run.add_argument("--cpu", type=int, default=min(os.sched_getaffinity(0)))
    run.add_argument("--seeds", type=int, nargs="+", default=[12345])
    compare = sub.add_parser("compare")
    compare.add_argument("--work", type=Path, required=True)
    compare.add_argument("--before", default="before")
    compare.add_argument("--after", default="after")
    args = parser.parse_args()
    for field in ("compiler_root", "suite", "stdlib", "work", "metadata"):
        if hasattr(args, field):
            setattr(args, field, getattr(args, field).resolve())
    if args.action == "compiler":
        if args.compiler_args[:1] == ["--"]:
            args.compiler_args.pop(0)
        return compile_action(args)
    if args.action == "compare":
        return compare_action(args)
    return run_action(args)


if __name__ == "__main__":
    raise SystemExit(main())
