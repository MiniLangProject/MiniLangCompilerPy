# HollowKeep string-concatenation compile-time fix

Date: 2026-09-28. Both compiler source trees; local validation on Windows x64,
with Linux runtime checks under WSL Ubuntu. This is a compiler-time fix, not
a change to string semantics or a claimed runtime-speed improvement.

## Root cause and correction

`_opt_expr_known_type` analyzed each Unary/Bin operand twice whenever any
operator declaration was present in the program, including imported modules:

1. `_resolve_operator_overload` recursively inferred operand types.
2. If no overload matched, builtin inference recursively inferred them again.

A left-associated chain therefore repeatedly doubled the work. HollowKeep's
MiniPixels imports enable operator resolution even for ordinary mixed
concatenation. The emitter attempts overload resolution before its existing
literal-first string-chain fast path, so prefixing `""` did not eliminate
the expensive analysis.

Both implementations now infer each operand once and pass the full facts to
`_resolve_operator_overload_facts`. Qualified struct facts remain intact for
exact overload matching; only builtin inference reduces them to base types.
The unary case is fixed as well. There is no cross-statement cache, no
invalidation assumption, no expression reassociation, and no string-lowering
change. The individual Unary/Bin type walk is linear for these expression
trees; this does not claim that every other compiler pass is linear.

Python baseline: `6b0a84cc93499590b49190cb3483396521fcf1c0`.
ML source baseline: `8d9c6725f28b32ddf5394748998285158f577bcd`.
The previous local Windows compiler image was retained as
`MiniLangCompilerML/build/mlc_win64.concat-before.exe`, SHA-256
`493965554B865B9666927551165D321D9338359CD4BFCF03AF01A344CA6B3F20`.

## HollowKeep measurements

The original expression in `src/ui/menu.ml` was left unchanged.
These are individual profiled samples, not hardware-independent guarantees.

| Workload | Before | After |
| --- | ---: | ---: |
| Isolated menu package: code generation | 57.062 s | 0.187 s |
| Isolated menu build: final total | 73.969 s | 14.313 s |
| Full application source build: final total | Previously aborted in the reported investigation | 96.438 s |
| Menu package inside the full application: code generation | No completed baseline | 0.281 s |

The isolated package is approximately 305 times faster; the entire isolated
build is approximately 5.2 times faster. Its eight functions still generate
161,039 text bytes. Both isolated executables have SHA-256:

`0CCAE19EB45A4DBB05528047D9CAA3AFE349D231DB83672C99D59A41EF3DB977`

Reproduce from the HollowKeep directory (`DungeonCrawler`):

```powershell
& '..\MiniLangCompilerOptimization\MiniLangCompilerML\build\mlc_win64.exe' `
  src/ui/menu.ml build/menu-concat-after.exe `
  -I '..\MiniLangCompilerOptimization\MiniPixels\src' `
  -I '..\MiniLangCompilerOptimization\MiniLangCompilerML' `
  -I build/generated --target windows-x64 `
  --object-pipeline --profile-compiler-batches
```

For the complete source build, replace the entry with `src/main.ml`, use
`build/hollowkeep-concat-fixed.exe` as output, and add `--subsystem windows`.
It completed with 407 object files and produced a 51,663,360-byte PE, SHA-256:

`74E5FCC245C956AF9DBC5B0DD9E2FCD1957EF58D5B0CDF4BAF86520840DB2137`

The current source fingerprint was recomputed with the game's existing
`tools.write_build_info.source_hash()` and matched the generated build-info
module. Its short form `ca7f85398432` was verified inside the executable.
The full source SHA-256 was
`ca7f8539843209eab9a2ac4504cbe010a4a78ed1b3dbaa077410b2e7961f3965`.

This reused the existing generated assets/native libraries and did not run
the asset-authoring pipeline or modify the dirty game working tree. The full
source-build timing overlapped other validation work and is a completion
measurement, not a controlled game-build benchmark. A production-image
`--self-test` invocation was rejected as designed because
`HOLLOWKEEP_DEVELOPER=false`; no full gameplay-test success is claimed.

## Bounded A/B benchmark

Three serial runs per compiler/pipeline, including process startup, after the
full compiler suites had completed. The 20-addition fixture below is bounded
so the previous compiler can finish; the permanent regression deliberately
has a longer chain. All 24 benchmark executables ran successfully and were
byte-identical across before/after, Python/ML and pipeline selection.

| Compiler / pipeline option | Before median | After median |
| --- | ---: | ---: |
| Python / monolithic | 4.820825 s | 0.156793 s |
| Python / object compatibility option | 4.702705 s | 0.152380 s |
| ML / monolithic | 4.202796 s | 0.055240 s |
| ML / object pipeline | 4.203805 s | 0.079087 s |

Python accepts the object-pipeline compatibility flag but does not implement
a separate MLO backend. Its baseline was the original
`_opt_expr_known_type` method loaded from Git into the existing class in a
fresh process; no working-tree rollback was used.

Benchmark source (compiled with `--no-object-pipeline` or
`--object-pipeline`, otherwise default Windows settings):

```minilang
struct Token
  value as int
  operator +(left as Token, right as int) returns int
    return left.value + right
  end operator
end struct

function chain(value)
  return value + ":" + 0 + ":" + 1 + ":" + 2 + ":" + 3 + ":" + 4 + ":" + 5 + ":" + 6 + ":" + 7 + ":" + 8 + ":" + 9
end function

function main(args)
  if chain(7) != "7:0:1:2:3:4:5:6:7:8:9" then return 1 end if
  print "[OK] concat benchmark"
  return 0
end function
```

Common benchmark executable SHA-256:
`997AB3282D267436E1BFCB704DC8E5144A881C382C07AB3F130B5472AB4E079D`.
Local raw samples: `MiniLangCompilerPy/build/concat-benchmark-results.csv`
(decimal-comma values inside quoted CSV fields).

## Regression and parity validation

- Python unified suite: **153 passed, 0 failed, 0 skipped**.
- ML core harness: **136 passed, 0 failed**; all **152 outer checks** passed,
  including Windows/Linux execution and existing object/monolithic parity.
- Identical `tests/mixed_concat_overloads.ml` files in both repositories:
  untyped member-first 40-addition chain, literal-first chain, mixed number/
  bool/string conversion, exact side-effect order, early error propagation,
  parenthesized grouping, real unary/binary overloads and deep unary nesting.
- That fixture is registered for Windows and Linux in both runners and for
  ML object/monolithic parity. The newly added Linux registration was also
  covered by an explicit cross-compiler/pipeline execution matrix.
- Python `tests/check_operator_type_scaling.py` bounds actual inference
  visits at depths 16, 32 and 64, with and without overload checking. It tests
  mixed binary, numeric binary and unary trees without a timing assertion.
  Loading the old method makes this guard fail; the fixed method passes.
- Fixed an independently encountered Python test-runner import collision:
  unittest discovery now selects the local Linux-loader test file instead
  of resolving a possibly installed third-party package named `tests`.

The explicit matrix used one identical source path and default heap options.
Every output was executed; each target's four outputs (Python/ML times
monolithic/object option) matched:

| Target | SHA-256 |
| --- | --- |
| Windows x64 | `930B8A4E79ABFCCEA53F2ACD57B131BABFE7BF7112EE09ACA9313F267792338D` |
| Linux x64 | `EDF8D8D8FCFAF9ECAAE7C6669CFAE7EA86C3DA36345EB8A3C8E4062851C9372E` |

## Self-hosting and local artifact

The modified Python compiler built the Windows ML compiler; that compiler
then rebuilt itself. Both 65,327,616-byte images are byte-identical:

`E92F52FC142970D4F1FDF82742D7D8C75E9FB50517872361076841A49FBC0581`

The verified self-hosted result replaces local
`MiniLangCompilerML/build/mlc_win64.exe`; the previous image remains in the
backup noted above. No release/version bump is included: this remains a
local fixed 1.2.11 development build. The Linux-host compiler artifact and
published GitHub releases were not rebuilt or replaced in this task.

