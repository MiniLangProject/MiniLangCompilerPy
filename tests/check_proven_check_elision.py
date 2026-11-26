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
    "typed_numeric_temporary_inline": "TYPED NUMERIC TEMPORARY INLINE [OK]",
    "typed_local_custom_typeof": "TYPED LOCAL CUSTOM TYPEOF [OK]",
    "typed_float_temporary_inline": "TYPED FLOAT TEMPORARY INLINE [OK]",
    "typed_float_temporary_typeof": "TYPED FLOAT TEMPORARY TYPEOF [OK]",
    "numeric_typeflow_boxing": "NUMERIC TYPEFLOW BOXING [OK]",
    "numeric_typeflow_typeof": "NUMERIC TYPEFLOW TYPEOF [OK]",
    "numeric_typeflow_tofloat": "NUMERIC TYPEFLOW TOFLOAT [OK]",
    "numeric_nullable_boxing": "NUMERIC NULLABLE BOXING [OK]",
    "numeric_nullable_typeof": "NUMERIC NULLABLE TYPEOF [OK]",
    "numeric_nullable_tofloat": "NUMERIC NULLABLE TOFLOAT [OK]",
    "numeric_float_tree": "NUMERIC FLOAT TREE [OK]",
    "numeric_float_tree_typeof": "NUMERIC FLOAT TREE TYPEOF [OK]",
    "numeric_float_tree_tofloat": "NUMERIC FLOAT TREE TOFLOAT [OK]",
    "numeric_float_loop": "NUMERIC FLOAT LOOP [OK]",
    "numeric_float_loop_typeof": "NUMERIC FLOAT LOOP TYPEOF [OK]",
    "numeric_float_loop_threads": "NUMERIC FLOAT LOOP THREADS [OK]",
    "numeric_float_nested": "NUMERIC FLOAT NESTED [OK]",
    "numeric_float_nested_typeof": "NUMERIC FLOAT NESTED TYPEOF [OK]",
    "numeric_float_nested_threads": "NUMERIC FLOAT NESTED THREADS [OK]",
    "numeric_float_cache": "NUMERIC FLOAT CACHE [OK]",
    "numeric_float_consumer": "NUMERIC FLOAT CONSUMER [OK]",
    "numeric_nan_normalization": "NUMERIC NAN NORMALIZATION [OK]",
    "gc_allocation_totals": "GC TOTALS checks=15 failures=0",
    "gc_allocation_totals_threads": "GC TOTALS THREADS [OK]",
    "gc_stats_default_reference": "GC DEFAULT REFERENCE [OK]",
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
    "language_typed_bindings": "TYPED BINDINGS [OK]",
    "language_typed_fields": "TYPED FIELDS [OK]",
    "language_typed_arrays": "TYPED ARRAYS [OK]",
    "language_packed_array": "PACKED ARRAY [OK]",
    "language_strict_types": "STRICT TYPES RUNTIME FALLBACK [OK]",
    "language_typed_binding_typeof": "TYPED BINDING TYPEOF [OK]",
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


def inspect_assembly(fixture, assembly, *, gc_concurrent=False):
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

    def loop_normalizers(name, text, label, speculative, normalizers):
        """Keep strict roots while validating complete bounded continuations.

        Every node retains its conversion/comparison and f32 probe. A permitted
        child may branch to an out-of-line canonicalization continuation; a
        stored definition must still branch to the committed-state bailout.
        """
        branch = re.compile(r"(?s)cvttsd2si.*?cvtsi2sd.*?ucomisd.*?\bje\s+(\w+)")
        deopt = f"float_loop_deopt_{label}"
        consumers = []
        for normalizer in normalizers:
            found = branch.search(normalizer)
            if not found:
                raise AssertionError(f"Missing integer/NaN normalization branch: {name} {label}")
            target = found[1]
            consumer = re.fullmatch(r"float_loop_consumer_int_(\d+)", target)
            if target != deopt and consumer is None:
                raise AssertionError(f"Unvalidated normalization target: {name} {target}")
            probe_end = len(normalizer)
            if consumer is not None:
                number = consumer[1]
                start = f"float_loop_consumer_{number}"
                resume = f"float_loop_consumer_resume_{number}"
                if not re.search(r"(?m)^" + re.escape(start) + r":[^\n]*\n"
                                 r"float_tree_normalize_\d+:", speculative):
                    raise AssertionError(f"Consumer does not begin at a normalizer: {name} {number}")
                resumed = re.search(r"(?m)^" + re.escape(resume) + r":", normalizer)
                if not resumed:
                    raise AssertionError(f"Missing local consumer continuation: {name} {number}")
                probe_end = resumed.start()
                stub = re.search(r"(?ms)^" + re.escape(target) + r":(.*?)"
                                 r"(?=^[A-Za-z_]\w*:|\Z)", text)
                if not stub:
                    raise AssertionError(f"Missing canonicalization code: {name} {number}")
                sequence = (
                    r"(?s)\bshl(?:_r64_imm8)?[\s(]+rax\s*,\s*3\b.*?"
                    r"\bor(?:_r64_imm)?[\s(]+rax\s*,\s*1\b.*?"
                    r"\bsar(?:_r64_imm8)?[\s(]+rax\s*,\s*3\b.*?"
                    r"\bcvtsi2sd(?:_xmm_r64)?[\s(]+xmm0\s*,\s*rax\b.*?"
                    r"\bjmp\s+" + re.escape(resume) + r"\b")
                if (not re.search(sequence, stub[1])
                        or len(re.findall(r"(?m)^[0-9A-Fa-f]{8,16}\s", stub[1])) != 5
                        or re.search(r"\bxmm(?:[1-9]|1[0-5])\b", stub[1])):
                    raise AssertionError(f"Canonicalization changes scratch/state: {name} {number}")
                if not (text.index(f"float_loop_exit_{label}:") < stub.start()
                        < text.index(deopt + ":")):
                    raise AssertionError(f"Canonicalization lacks out-of-line placement: {name} {number}")
                consumers.append(number)
            if not re.search(r"(?s)cvtsd2ss.*?cvtss2sd",
                             normalizer[found.end():probe_end]):
                raise AssertionError(f"Missing original f32 normalization probe: {name} {label}")
        if len(set(consumers)) != len(consumers):
            raise AssertionError(f"Duplicate normalization continuation: {name} {label}")
        normalizer_starts = [m.start() for m in re.finditer(
            r"(?m)^float_tree_normalize_\d+:", speculative)]
        writes = re.finditer(
            r"(?m)^float_loop_cache_" + re.escape(label) + r"_\d+_xmm\d+:"
            r"|\bmovsd_membase_disp_xmm\(rsp,\s*\d+,\s*xmm0\)", speculative)
        for write in writes:
            prior = [start for start in normalizer_starts if start < write.start()]
            found = branch.search(speculative[prior[-1]:write.start()]) if prior else None
            if not found or found[1] != deopt:
                raise AssertionError(f"Stored definition root bypasses rollback: {name} {label}")
        return consumers

    if fixture == "proven_check_elision":
        for name, guarded in (("literalContracts", False),
                              ("literalFloatIsNotInt", True),
                              ("normalizedLiteralIsNotFloat", True),
                              ("localContract", True)):
            contains(name, "type_guard_valid_", guarded)

    if fixture == "language_packed_array":
        contains("main", "packed_i32_index_", True)
        contains("main", "packed_i32_value_", True)
        dynamic = body("writeTo").split("\nfn_ret_writeTo:", 1)[0]
        if ("packed_i32_index_" in dynamic
                or "call fn_user_std.ds.packed_array.Int32Array.set" not in dynamic):
            raise AssertionError("Packed array writes through an unknown receiver must dispatch")
        checks.append({"function": "writeTo", "dispatch": "runtime"})

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

    if fixture == "numeric_nullable_boxing":
        positive = ("variableFloatRight", "variableFloatMulRight",
                    "variableFloatSubRight", "variableNumberRight", "nullableAdd",
                    "nullableMultiply", "nullableSubtract", "nullableFloatDivisor",
                    "nullableRight", "caughtNullableRight", "caughtNullableAdd",
                    "nullableAliasJoin", "nullableLoopJoin", "nullableChain",
                    "smallMandelbrot", "nullableGc")
        negative = ("referenceAdd", "referenceMul", "referenceSub", "referenceCaught",
                    "referenceDivision", "referenceMandelbrot", "readBeforeNumericInit",
                    "zeroTripRight", "noFuseRightCall", "noFuseBothCalls",
                    "noFuseErrorOrder", "noFuseRightMember", "noFuseRightIndex",
                    "noFuseRightGlobal", "noFuseRightSynchronized", "noFuseRightCapture",
                    "noFuseMixedRight", "optionalRight", "noFuseOpaqueRight",
                    "noFuseErrorRight")
        for name in positive:
            contains(name, "float_parent_nobox_rhs_fast_", True)
            text = body(name)
            regions = re.findall(
                r"(?ms)^float_parent_nobox_child_(\d+):(?P<code>.*?)"
                r"^float_parent_nobox_materialize_\1:", text)
            if not regions:
                raise AssertionError(f"Missing nullable unboxed lifetime boundary: {name}")
            for label, code in regions:
                if re.search(r"(?i)\bcall\b", code):
                    raise AssertionError(f"Nullable float crosses a call: {name} {label}")
            guards = re.findall(
                r"(?ms)^float_parent_nobox_rhs_guard_(\d+):(?P<code>.*?)"
                r"^float_parent_nobox_rhs_fast_\1:", text)
            if not guards:
                raise AssertionError(f"Missing actual-float RHS guard: {name}")
            for label, code in guards:
                rhs_ok = code.find(f"float_parent_nobox_rhs_ok_{label}:")
                leaf = code.find(f"float_parent_nobox_leaf_{label}_")
                if rhs_ok < 0 or leaf < rhs_ok or re.search(r"(?i)\bcall\b", code):
                    raise AssertionError(f"RHS guard does not precede child work: {name} {label}")
                if f"float_parent_nobox_slow_{label}" not in code:
                    raise AssertionError(f"Missing original-expression fallback: {name} {label}")
            checks.append({"function": name, "call_free_unboxed_regions": len(regions),
                           "rhs_float_guard_before_child": len(guards)})
        for name in negative:
            contains(name, "float_parent_nobox_fast_", False)
        contains("nullableGc", "call fn_box_float", True)
        # Nullable candidates cannot authorize the unconditional conversion
        # fastpath. These leaves still need ordinary void/error behavior.
        for name in ("caughtNullableChild", "nullableConversionTag"):
            contains(name, "float_parent_nobox_fast_", False)

    if fixture == "numeric_nullable_typeof":
        for name in ("shadowedDivisor", "shadowedRight"):
            contains(name, "type_guard_valid_", True)
            contains(name, "float_parent_nobox_fast_", False)
            contains(name, "numeric_float_fast_", False)

    if fixture == "numeric_nullable_tofloat":
        for name in ("shadowedDivision", "shadowedRight", "reference"):
            contains(name, "float_parent_nobox_fast_", False)

    if fixture == "numeric_float_tree":
        # Listings use both ordinary mnemonics and helper spellings such as
        # movapd_xmm_xmm(xmm5, xmm0). Check the actual instruction comments.
        call_pattern = r"(?i)\bcall(?:_\w+)?(?:\s|\()"
        stack_store_pattern = (
            r"(?i)\b(?:mov\w*\s+(?:qword\s+)?\[rsp"
            r"|mov\w*_membase_disp_\w+\(\s*rsp\b"
            r"|mov_rsp_disp32_\w+\()")
        guarded_work_pattern = r"(?i)\b(?:call|addsd|subsd|mulsd)(?:_\w+)?(?:\s|\()"
        positive = ("treeBalanced", "treeDeep", "treeEight", "treeRightNested",
                    "treeNumberCancellation", "treeTwoCancellation", "treeWrap",
                    "treeNaN", "treeProbe", "treeSubnormal", "treeOrder",
                    "treeComparisons", "treeCompareRight", "treeCompareLeft",
                    "treeCompareLiteral", "treeNullable", "treeCaughtNullable",
                    "treeNullableComparison", "treeBuiltinConverted")
        negative = ("referenceBalanced", "referenceDeep", "referenceEight",
                    "referenceRightNested", "referenceCancellation",
                    "referenceTwoCancellation", "referenceWrap", "referenceNaN",
                    "referenceProbe", "referenceSubnormal", "referenceOrder",
                    "referenceComparisons", "referenceCompareRight",
                    "referenceCompareLeft", "referenceNullable",
                    "referenceNullableComparison", "noTreeCall", "noTreeErrorOrder",
                    "noTreeMember", "noTreeIndex", "noTreeGlobal",
                    "noTreeSynchronized", "noTreeCapture", "noTreeOptional",
                    "noTreeIntegerLeaf", "noTreeIntegerLiteral",
                    "noTreeConstantSubtree", "noTreeDivision")
        for name in positive:
            contains(name, "float_tree_fast_", True)
            text = body(name)
            regions = re.findall(
                r"(?ms)^float_tree_fast_(\d+):(?P<code>.*?)"
                r"^float_tree_(materialize|compare)_\1:", text)
            if not regions:
                raise AssertionError(f"Missing float tree lifetime boundary: {name}")
            for label, code, consumer in regions:
                if re.search(call_pattern, code):
                    raise AssertionError(f"Unmaterialized tree crosses a call: {name} {label}")
                if re.search(stack_store_pattern, code):
                    raise AssertionError(f"Raw tree stores into a stack/root slot: {name} {label}")
                normalizers = re.findall(r"(?m)^float_tree_normalize_\d+:", code)
                maximum = 6 if consumer == "materialize" else 7
                if not 1 <= len(normalizers) <= maximum:
                    raise AssertionError(f"Incorrect bounded tree normalization: {name} {label}")
                if f"float_tree_slow_{label}" not in code:
                    raise AssertionError(f"Missing non-float intermediate fallback: {name} {label}")
            guards = re.findall(
                r"(?ms)^float_tree_guard_(\d+):(?P<code>.*?)"
                r"^float_tree_fast_\1:", text)
            for label, code in guards:
                if re.search(guarded_work_pattern, code):
                    raise AssertionError(f"Leaf guards run after tree work: {name} {label}")
                if f"float_tree_leaf_{label}_" not in code:
                    raise AssertionError(f"Missing actual-float leaf guard: {name} {label}")
            if not guards:
                raise AssertionError(f"Missing tree leaf guards: {name}")
            if name == "treeEight" and not any(
                    re.search(r"(?i)\bmovapd(?:_xmm_xmm)?[\s(]+xmm5\s*,", code)
                    for label, code, consumer in regions):
                raise AssertionError("Seven-node tree does not exercise its second saved operand")
            checks.append({"function": name, "call_free_float_tree_regions": len(regions),
                           "actual_float_leaf_guard_regions": len(guards)})
        for name in negative:
            contains(name, "float_tree_fast_", False)
        contains("treeEight", "call fn_box_float", True)
        # The overdeep root may optimize a three-level descendant, but never
        # the four-level expression with three inner normalization boundaries.
        for label, code in re.findall(
                r"(?ms)^float_tree_fast_(\d+):(?P<code>.*?)"
                r"^float_tree_materialize_\1:", body("outsideDepthBudget")):
            if len(re.findall(r"(?m)^float_tree_normalize_\d+:", code)) > 2:
                raise AssertionError(f"Float tree exceeded depth budget: {label}")

    if fixture == "numeric_float_tree_typeof":
        for name in ("shadowedTree", "shadowedComparison"):
            contains(name, "type_guard_valid_", True)
            contains(name, "float_tree_fast_", False)

    if fixture == "numeric_float_tree_tofloat":
        for name in ("shadowedTree", "shadowedComparison", "reference",
                     "referenceComparison"):
            contains(name, "float_tree_fast_", False)

    if fixture == "numeric_float_loop":
        # Every arithmetic result is checked before the iteration commits.
        # Private unscanned spills are permitted here; a call is not.
        call_pattern = r"(?i)\bcall(?:_\w+)?(?:\s|\()"
        positive = {
            "loopRecurrence": (12, 3),
            "loopAlias": (2, 1),
            "loopWriteOnly": (2, 1),
            "loopLate": (3, 3),
            "loopNumericEntry": (2, 2),
            "loopCounter": (2, 1),
            "loopSpecial": (3, 1),
        }
        negative = ("referenceRecurrence", "referenceAlias", "referenceWriteOnly",
                    "referenceLate", "referenceNumericEntry", "referenceSpecial",
                    "referenceOldAlias",
                    "noLoopCall", "noLoopError", "noLoopGlobal",
                    "noLoopSynchronized", "noLoopCapture", "noLoopContract",
                    "noLoopControl", "noLoopReturn", "noLoopChangingBound",
                    "noLoopStep", "noLoopOldAlias", "noLoopBodyTypeof")
        contains("loopLong", "float_loop_fast_", not gc_concurrent)
        contains("referenceLong", "float_loop_fast_", False)
        for name, (operations, materializations) in positive.items():
            contains(name, "float_loop_fast_", not gc_concurrent)
            if gc_concurrent:
                contains(name, "gc_poll_done_", True)
                continue
            text = body(name)
            regions = re.findall(
                r"(?ms)^float_loop_fast_(\d+):(?P<code>.*?)"
                r"^float_loop_exit_\1:", text)
            if len(regions) != 1:
                raise AssertionError(f"Missing counted float loop boundary: {name}")
            for label, code in regions:
                if re.search(call_pattern, code):
                    raise AssertionError(f"Unmaterialized loop crosses a call: {name} {label}")
                commit = f"float_loop_commit_{label}:"
                if code.count(commit) != 1:
                    raise AssertionError(f"Missing unique iteration commit: {name} {label}")
                speculative, committed = code.split(commit)
                normalizers = re.findall(
                    r"(?ms)^float_tree_normalize_\d+:(.*?)"
                    r"(?=^float_tree_normalize_\d+:|\Z)", speculative)
                if len(normalizers) != operations or "float_tree_normalize_" in committed:
                    raise AssertionError(f"Arithmetic normalization after/missing commit: {name} {label}")
                loop_normalizers(name, text, label, speculative, normalizers)
                # Peephole lowering may combine jge exit; jmp fast into jl fast.
                if not re.search(r"\b(?:jmp|jl)\s+" + re.escape(f"float_loop_fast_{label}")
                                 + r"\b", committed):
                    raise AssertionError(f"Missing committed-loop backedge: {name} {label}")
                exit_path = re.search(
                    r"(?ms)^float_loop_exit_" + re.escape(label) + r":(.*?)"
                    r"^float_loop_deopt_" + re.escape(label) + r":", text)
                if (not exit_path or "float_loop_materialize_" not in exit_path[1]
                        or len(re.findall(r"\bcall\s+fn_box_float\b", exit_path[1]))
                        != materializations):
                    raise AssertionError(f"Incorrect exit materialization/alias groups: {name} {label}")
                guard = re.search(
                    r"(?ms)^float_loop_guard_" + re.escape(label) + r":(.*?)"
                    r"^float_loop_fast_" + re.escape(label) + r":", text)
                if not guard or re.search(call_pattern, guard[1]):
                    raise AssertionError(f"Invalid float loop entry guard: {name} {label}")
                zero_trip = re.search(r"\bjge\s+" + re.escape(f"float_loop_done_{label}")
                                      + r"\b", guard[1])
                first_leaf = guard[1].find(f"float_loop_leaf_{label}_")
                if not zero_trip or first_leaf < zero_trip.end():
                    raise AssertionError(f"Float inputs inspected before zero-trip test: {name} {label}")
            checks.append({"function": name, "call_free_float_loops": len(regions),
                           "normalizers_before_commit": operations,
                           "exit_materialization_groups": materializations})
        for name in negative:
            contains(name, "float_loop_fast_", False)

    if fixture == "numeric_float_loop_typeof":
        contains("shadowedLoop", "type_guard_valid_", True)
        contains("shadowedLoop", "float_loop_fast_", False)

    if fixture == "numeric_float_loop_threads":
        contains("threadedLoop", "float_loop_fast_", False)
        contains("threadedLoop", "gc_poll_done_", True)
        contains("threadedLoop", "thread_cancel_done_", True)

    if fixture == "numeric_float_nested":
        # Counts include arithmetic in the escape predicate. The two sibling
        # sites have separate labels and sequential ownership of one arena.
        positive = {
            "nestedCounted": [(2, 1, False)],
            "nestedBranches": [(2, 1, False), (2, 1, False)],
            "nestedSiblings": [(5, 2, True), (5, 2, True)],
            "nestedMandel": [(8, 4, True)],
            "compoundReentry": [(4, 3, True)],
            "compoundEscape": [(4, 2, True)],
            "compoundCounter": [(2, 1, True)],
            "compoundIntegerEntry": [(5, 2, True)],
            "compoundNormalizeCondition": [(5, 2, True)],
            "compoundShortCircuit": [(3, 1, True)],
            "compoundAliases": [(2, 1, True)],
            "compoundWriteOnly": [(2, 1, True)],
            "compoundBothTrees": [(8, 1, True)],
            "compareEqual": [(2, 1, True)],
            "compareUnequal": [(2, 1, True)],
            "compareLess": [(2, 1, True)],
            "compareLessEqual": [(2, 1, True)],
            "compareGreater": [(2, 1, True)],
            "compareGreaterEqual": [(2, 1, True)],
        }
        negative = ("referenceCounted", "referenceSiblings", "referenceReentry",
                    "referenceEscape", "referenceIntegerEntry",
                    "referenceNormalizeCondition", "referenceAliases",
                    "referenceBothTrees", "referenceCompare", "referenceMandel",
                    "noNestedCall", "noNestedGlobal", "noNestedCapture",
                    "noNestedOldAlias", "noNestedChangingBound", "noNestedOr",
                    "noNestedDuplicate", "noNestedInline")
        call_pattern = r"(?i)\bcall(?:_\w+)?(?:\s|\()"
        for name, expected_regions in positive.items():
            contains(name, "float_loop_fast_", not gc_concurrent)
            if gc_concurrent:
                contains(name, "gc_poll_done_", True)
                continue
            text = body(name)
            regions = re.findall(r"(?ms)^float_loop_fast_(\d+):(.*?)"
                                 r"^float_loop_exit_\1:", text)
            if len(regions) != len(expected_regions):
                raise AssertionError(f"Incorrect nested loop sites: {name}")
            for (label, code), (operations, groups, compound) in zip(regions, expected_regions):
                if re.search(call_pattern, code):
                    raise AssertionError(f"Raw nested state crosses a call: {name} {label}")
                commit = f"float_loop_commit_{label}:"
                if code.count(commit) != 1:
                    raise AssertionError(f"Missing unique nested commit: {name} {label}")
                speculative, committed = code.split(commit)
                normalizers = re.findall(r"(?ms)^float_tree_normalize_\d+:(.*?)"
                                         r"(?=^float_tree_normalize_\d+:|\Z)", speculative)
                if len(normalizers) != operations or "float_tree_normalize_" in committed:
                    raise AssertionError(f"Incorrect nested normalization boundaries: {name} {label}")
                loop_normalizers(name, text, label, speculative, normalizers)
                if not re.search(r"\b(?:jmp|jl)\s+" + re.escape(f"float_loop_fast_{label}")
                                 + r"\b", committed):
                    raise AssertionError(f"Missing nested committed backedge: {name} {label}")
                guard = re.search(r"(?ms)^float_loop_guard_" + re.escape(label) + r":(.*?)"
                                  r"^float_loop_fast_" + re.escape(label) + r":", text)
                if not guard or re.search(call_pattern, guard[1]):
                    raise AssertionError(f"Invalid nested entry guard: {name} {label}")
                zero_trip = re.search(r"\bjge\s+" + re.escape(f"float_loop_done_{label}")
                                      + r"\b", guard[1])
                if not zero_trip or guard[1].find(f"float_loop_leaf_{label}_") < zero_trip.end():
                    raise AssertionError(f"Nested condition precedes zero-trip check: {name} {label}")
                exit_path = re.search(r"(?ms)^float_loop_exit_" + re.escape(label) + r":(.*?)"
                                      r"^float_loop_deopt_" + re.escape(label) + r":", text)
                if (not exit_path or "float_loop_materialize_" not in exit_path[1]
                        or len(re.findall(r"\bcall\s+fn_box_float\b", exit_path[1])) != groups):
                    raise AssertionError(f"Incorrect nested output alias groups: {name} {label}")
                condition_marker = f"float_loop_condition_{label}:"
                if (condition_marker in speculative) != compound:
                    raise AssertionError(f"Incorrect compound condition path: {name} {label}")
                reentry = re.search(r"(?ms)^float_loop_reentry_" + re.escape(label)
                                    + r":(.*?)^float_loop_done_" + re.escape(label) + r":", text)
                if bool(reentry) != compound:
                    raise AssertionError(f"Incorrect ordinary-iteration reentry: {name} {label}")
                if compound:
                    if not re.search(r"\bjmp\s+" + re.escape(f"float_loop_guard_{label}")
                                     + r"\b", reentry[1]):
                        raise AssertionError(f"Missing reentry guard backedge: {name} {label}")
                    before_materialize = exit_path[1].split("float_loop_materialize_", 1)[0]
                    if not re.search(r"\bje\s+" + re.escape(f"float_loop_done_{label}")
                                     + r"\b", before_materialize):
                        raise AssertionError(f"First false condition materializes outputs: {name} {label}")
                    slow = text.find(f"float_loop_slow_{label}:")
                    if slow < 0 or slow >= reentry.start():
                        raise AssertionError(f"Reentry precedes ordinary retry: {name} {label}")
                checks.append({"function": name, "loop_label": label,
                               "compound_condition": compound,
                               "call_free_raw_region": True,
                               "normalizers_before_commit": operations,
                               "exit_materialization_groups": groups,
                               "ordinary_iteration_reentry": compound})
        for name in negative:
            contains(name, "float_loop_fast_", False)

    if fixture == "numeric_float_nested_typeof":
        for name in ("shadowedNested", "shadowedCompound"):
            contains(name, "type_guard_valid_", True)
            contains(name, "float_loop_fast_", False)

    if fixture == "numeric_float_nested_threads":
        contains("threadedNested", "float_loop_fast_", False)
        contains("threadedNested", "gc_poll_done_", True)
        contains("threadedNested", "thread_cancel_done_", True)

    if fixture == "numeric_float_cache":
        # The fixture exercises whole-region saved-left pressure, including
        # conditions, while preserving the established rollback/GC boundary.
        # Counts describe source arithmetic and observable output alias groups.
        positive = {
            "cacheRepeated": (8, 2, 4, {"xmm4", "xmm5"}),
            "cacheFanout": (4, 2, 2, {"xmm4", "xmm5"}),
            "cacheLate": (10, 4, 5, {"xmm4", "xmm5"}),
            "cachePressureOne": (6, 2, 2, {"xmm5"}),
            "cacheConditionOne": (5, 2, 2, {"xmm5"}),
            "cachePressureTwo": (7, 1, 1, set()),
            "cacheConditionTwo": (10, 2, 2, set()),
            "cacheTies": (8, 4, 4, {"xmm4", "xmm5"}),
            "cachePromoted": (4, 1, 2, {"xmm4", "xmm5"}),
        }
        call_pattern = r"(?i)\bcall(?:_\w+)?(?:\s|\()"
        for name, (operations, groups, definitions, expected_registers) in positive.items():
            contains(name, "float_loop_fast_", not gc_concurrent)
            if gc_concurrent:
                contains(name, "float_loop_cache_", False)
                contains(name, "gc_poll_done_", True)
                continue
            text = body(name)
            regions = re.findall(r"(?ms)^float_loop_fast_(\d+):(.*?)"
                                 r"^float_loop_exit_\1:", text)
            if len(regions) != 1:
                raise AssertionError(f"Missing cache fixture raw loop: {name}")
            label, code = regions[0]
            if re.search(call_pattern, code):
                raise AssertionError(f"Cached raw values cross a call: {name}")
            commit = f"float_loop_commit_{label}:"
            if code.count(commit) != 1:
                raise AssertionError(f"Missing unique cache fixture commit: {name}")
            speculative, committed = code.split(commit)
            normalizers = re.findall(r"(?ms)^float_tree_normalize_\d+:(.*?)"
                                     r"(?=^float_tree_normalize_\d+:|\Z)", speculative)
            if len(normalizers) != operations or "float_tree_normalize_" in committed:
                raise AssertionError(f"Cache changed normalization boundaries: {name}")
            loop_normalizers(name, text, label, speculative, normalizers)
            cached = list(re.finditer(r"(?m)^float_loop_cache_" + re.escape(label)
                                      + r"_(\d+)_(xmm\d+):[^\n]*\n", speculative))
            cache_registers = [match[2] for match in cached]
            if (set(cache_registers) != expected_registers
                    or len(cache_registers) != len(expected_registers)
                    or len({match[1] for match in cached}) != len(cached)):
                raise AssertionError(f"Cache overlaps saved-left registers or definitions: {name}")
            for match in cached:
                after_marker = speculative[match.end():].lstrip().splitlines()[0]
                if not re.search(r"\bmovapd(?:_xmm_xmm)?[\s(]+" + re.escape(match[2])
                                 + r"\s*,\s*xmm0\b", after_marker):
                    raise AssertionError(f"Cache marker lacks its fresh value: {name}")
            # Every uncached arithmetic definition still has one staged store;
            # a cached definition must not also be written to a staging slot.
            staged_stores = len(re.findall(
                r"\bmovsd_membase_disp_xmm\(rsp,\s*\d+,\s*xmm0\)", speculative))
            if staged_stores != definitions - len(cached):
                raise AssertionError(f"Cached definitions retain redundant staged stores: {name}")
            exit_path = re.search(r"(?ms)^float_loop_exit_" + re.escape(label) + r":(.*?)"
                                  r"^float_loop_deopt_" + re.escape(label) + r":", text)
            if (not exit_path or "float_loop_materialize_" not in exit_path[1]
                    or len(re.findall(r"\bcall\s+fn_box_float\b", exit_path[1])) != groups):
                raise AssertionError(f"Cache changed output alias materialization: {name}")
            checks.append({"function": name, "call_free_raw_region": True,
                           "normalizers_before_commit": operations,
                           "cache_registers": sorted(cache_registers),
                           "cached_definitions": [int(match[1]) for match in cached],
                           "uncached_staged_stores": staged_stores,
                           "exit_materialization_groups": groups})
        for name in ("referenceRepeated", "referenceFanout", "referenceLate",
                     "referencePressureOne", "referenceConditionOne",
                     "referencePressureTwo", "referenceConditionTwo",
                     "referenceTies", "referencePromoted"):
            contains(name, "float_loop_fast_", False)
        if not gc_concurrent:
            promoted = set(re.findall(r"\bmovq_xmm_r64\((xmm(?:[6-9]|1[01])),",
                                      body("cachePromoted")))
            if promoted != {f"xmm{index}" for index in range(6, 12)}:
                raise AssertionError("Cache fixture does not exercise all promoted integer homes")
            checks.append({"function": "cachePromoted",
                           "preserved_integer_registers": sorted(promoted)})
    if fixture == "numeric_float_consumer":
        # (arithmetic nodes, permitted numeric continuations, output groups).
        # The both-tree cases enforce the boundary that preserves int/int work.
        positive = {
            "consumerLeft": (2, 1, 1),
            "consumerRight": (2, 1, 1),
            "consumerChain": (3, 2, 1),
            "consumerFresh": (4, 2, 2),
            "consumerBoth": (3, 0, 1),
            "consumerBothCondition": (4, 1, 1),
            "consumerLate": (7, 4, 3),
            "consumerEqual": (3, 2, 1),
            "consumerUnequal": (3, 2, 1),
            "consumerLess": (3, 2, 1),
            "consumerLessEqual": (3, 2, 1),
            "consumerGreater": (3, 2, 1),
            "consumerGreaterEqual": (3, 2, 1),
            "consumerConditionRight": (3, 2, 1),
            "consumerLiterals": (4, 2, 1),
        }
        call_pattern = r"(?i)\bcall(?:_\w+)?(?:\s|\()"
        for name, (operations, expected_consumers, groups) in positive.items():
            contains(name, "float_loop_fast_", not gc_concurrent)
            if gc_concurrent:
                contains(name, "float_loop_consumer_", False)
                contains(name, "float_loop_literal_", False)
                contains(name, "gc_poll_done_", True)
                continue
            text = body(name)
            regions = re.findall(r"(?ms)^float_loop_fast_(\d+):(.*?)"
                                 r"^float_loop_exit_\1:", text)
            if len(regions) != 1:
                raise AssertionError(f"Missing consumer fixture raw loop: {name}")
            label, code = regions[0]
            if re.search(call_pattern, code):
                raise AssertionError(f"Consumer raw state crosses a call: {name}")
            commit = f"float_loop_commit_{label}:"
            if code.count(commit) != 1:
                raise AssertionError(f"Missing unique consumer iteration commit: {name}")
            speculative, committed = code.split(commit)
            normalizers = re.findall(r"(?ms)^float_tree_normalize_\d+:(.*?)"
                                     r"(?=^float_tree_normalize_\d+:|\Z)", speculative)
            if len(normalizers) != operations or "float_tree_normalize_" in committed:
                raise AssertionError(f"Consumer changed normalization boundaries: {name}")
            consumers = loop_normalizers(name, text, label, speculative, normalizers)
            if len(consumers) != expected_consumers:
                raise AssertionError(f"Consumer crossed float-sibling proof boundary: {name}")
            if len(re.findall(r"(?m)^float_loop_consumer_\d+:", speculative)) != len(consumers):
                raise AssertionError(f"Unmatched numeric consumer marker: {name}")
            exit_path = re.search(r"(?ms)^float_loop_exit_" + re.escape(label) + r":(.*?)"
                                  r"^float_loop_deopt_" + re.escape(label) + r":", text)
            if (not exit_path or "float_loop_materialize_" not in exit_path[1]
                    or len(re.findall(r"\bcall\s+fn_box_float\b", exit_path[1])) != groups):
                raise AssertionError(f"Consumer changed output alias materialization: {name}")
            if name == "consumerFresh":
                caches = re.findall(r"(?m)^float_loop_cache_" + re.escape(label)
                                    + r"_(\d+)_(xmm\d+):", speculative)
                if caches != [("0", "xmm5")]:
                    raise AssertionError("Fresh float consumer lacks cached/saved-left coexistence")
            if name == "consumerLiterals":
                kinds = re.findall(r"(?m)^float_loop_literal_(immf|boxed)_\d+:", speculative)
                if kinds.count("immf") != 2 or kinds.count("boxed") != 1:
                    raise AssertionError("Literal fixture lacks both known representations")
                for kind, literal_code in re.findall(
                        r"(?ms)^float_loop_literal_(immf|boxed)_\d+:(.*?)"
                        r"(?=^[A-Za-z_]\w*:|\Z)", speculative):
                    if kind == "immf":
                        if not re.search(r"(?s)shr.*?movq.*?cvtss2sd", literal_code):
                            raise AssertionError("Immediate literal loses original f32 conversion")
                    elif not re.search(r"\bmovsd_membase_disp_xmm|\bmovsd_xmm_membase_disp",
                                       literal_code):
                        raise AssertionError("Boxed literal lacks its direct double load")
            checks.append({"function": name, "call_free_raw_region": True,
                           "normalizers_before_commit": operations,
                           "numeric_consumer_continuations": len(consumers),
                           "strict_integer_nan_bailouts": operations - len(consumers),
                           "exit_materialization_groups": groups})
        for name in ("referenceLeft", "referenceRight", "referenceChain",
                     "referenceFresh", "referenceBoth", "referenceBothCondition",
                     "referenceLate", "referenceCompare", "referenceConditionRight",
                     "referenceLiterals"):
            contains(name, "float_loop_fast_", False)
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
                            "numeric_typeflow_typeof", "numeric_typeflow_tofloat",
                            "numeric_nullable_boxing", "numeric_nullable_typeof",
                            "numeric_nullable_tofloat", "numeric_float_tree",
                            "numeric_float_tree_typeof", "numeric_float_tree_tofloat",
                            "numeric_float_loop", "numeric_float_loop_typeof",
                            "numeric_float_loop_threads", "numeric_float_nested",
                            "numeric_float_nested_typeof", "numeric_float_nested_threads",
                            "numeric_float_cache", "numeric_float_consumer", "language_packed_array")
                        invocation = [*command, str(source), str(output), "-I", str(root),
                                      "--target", target, pipeline, *flags]
                        if inspect_paths:
                            invocation.extend(["--asm", "--asm-out", str(listing)])
                        invoke(invocation, 180)
                        if inspect_paths:
                            assembly = listing.read_text(encoding="utf-8")
                            emissions.append({"fixture": fixture, "target": target,
                                              "checks": inspect_assembly(
                                                  fixture, assembly,
                                                  gc_concurrent=args.gc_concurrent)})
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
