# Struct namespace identity and default-call audit — 2026-11-26

## Reported failure

The MiniQuake3 audit supplied a two-file compiler reproducer. The entry file
imports a module whose `Record` has two fields, then declares an unrelated
three-field `Record` of its own:

```ml
// model.ml
package namespace_repro.model
struct Record left right end struct
function make() return Record(11, 22) end function
```

```ml
// main.ml
import namespace_repro.model as model
struct Record left right extra end struct
function main(args)
  value = model.make()
  print value.right
  return 0
end function
```

The correct output is `22`. Both baseline compilers instead rejected the
module's constructor with `Missing field argument 'extra' for struct Record`.
A same-arity entry declaration, `struct Record right left end struct`, made the
problem silent: both compilers produced a program that exited successfully
but printed `11`.

The shared fixtures under `tests/struct_namespace_identity/` retain the small
reproducer and independently cover annotated returns, inlining, nested and
ordinary methods, stored/returned constructors, named arguments, local
callables, captured callables, explicit aliases and default expressions.

## Provenance and baseline observations

The initial, unchanged checkouts were:

| Compiler | Revision | Reported version |
|---|---|---|
| Python | `0150d5a57b288847386282d1216763e5f1686549` | 1.3.12 |
| Native ML | `2b06138140b22c3a37cd314d00abcbfb90d36b3e` | 1.3.12 |

The native baseline was built locally from that revision. The constructor
arity failure occurred in both `--no-object-pipeline` and `--object-pipeline`
modes. The silent field-order probe was compiled and executed on Linux with
both baseline compilers. Additional baseline probes established:

- Annotated imported results could select the entry module's field layout.
- The native first-class constructor path could preserve the wrong root
  binding even after direct constructor resolution was corrected.
- Imported parameter/field default expressions were resolved using the
  caller's namespace and could select its unrelated `Record`.
- Python nested constant loops could generate duplicate `while_top_*` or
  `dowhile_top_*` assembler labels when consecutive headers emitted no bytes.
- The native baseline compiled `language_default_stack_args.ml`, but executing
  the result on Linux terminated with signal 11. Expanded arguments require
  the complete call frame, including calls hidden inside defaults.

While this work was in progress, current `main` advanced to 1.3.13 and gained
formatter changes and the Python default-stack fix. Those changes were
integrated before the final compiler build and validation. The final change
is based on Python `4699eb578d8fe485ec2285ff4489099e30bfc359` and native ML
`1245c4303d1e5bb5d3d7ba60e428da1cb0888656`; it does not change version numbers.

## Cause and changes

Struct declarations already had qualified identities. The failure was in
selecting the declaration: a hoisted root constructor counted as a global
binding and was found before the imported function's own namespace. Some
optimizer paths repeated that raw-name-first decision independently.

Both compilers now resolve ordinary unqualified symbols consistently:

1. A true local, parameter or captured callable keeps its lexical binding.
2. The function's defining namespace and source package are searched before
   unrelated root declarations.
3. The existing root and unique-package fallbacks remain available.

A method's owner is handled separately from its containing namespace. This
keeps a method named `len` from capturing an ordinary builtin `len(text)` call
in a sibling method, while retaining the existing bare static-sibling fallback.
Explicit qualified names and import aliases preserve their declared target.
The native variable emitter also uses the same resolver for stored and
returned constructor values.

The resolved name also remains authoritative through builtin/intrinsic call
lowering. The full self-build comparison exposed two native `slice` fallback
paths that still consulted the original source spelling after resolution.
They selected the builtin instead of `mlc.cache_codec.slice`, changing
`cache_codec.finish` and `cache_codec.read` by 688 bytes each. A standalone
namespace-function probe reproduced the incorrect runtime behavior. The native
call dispatcher now uses the canonical name consistently, and the shared
`namespace_builtins.ml` regression covers module and namespace declarations
named `slice`, `len`, `decode` and `typeof`, plus genuine builtin controls.

Signature type facts are resolved in the declaration's context, including
annotated results and inline parameters. A lexical callable that happens to
share a constructor name is not assigned that constructor's static layout.
Direct and indirect call lowering use the same distinction.

Nonliteral omitted arguments and struct-field defaults carry an internal
declaration-context wrapper. They are emitted in the caller's frame with the
declaration's namespace and global name visibility, then the caller's name
and optimizer state is restored. Caller locals, parameters and alias-shaped
local names cannot capture the inserted expression. Explicit arguments keep
the caller's context. Literal defaults retain their existing representation.
The language reference now states this rule.

The outgoing-frame scan follows full function/method signatures, implicit
receivers, constructors and nested calls in defaults, using the declaration's
context and a visited-default guard. The native compiler mirrors the Python
implementation. The pre-existing default-stack regression keeps its original
10-argument memory-corruption check; the provider/caller helper arities were
swapped so it exercises the corrected declaration-context rule.

The separate Python loop-label fix allocates a unique label identifier for
each `while` or `do-while` statement. Both repositories carry the shared
nested-loop regression; the native compiler already used distinct labels.

## Original MiniQuake3 integration

The integration source is pinned to MiniQuake3 commit
`f241b3408f4e63d9eee970d58e0dd57bb132a40e`. A separate source snapshot restores
the names `Triangle` and `ShadowTriangle` in
`tests/qvm_scene_materials_contracts.ml`, reversing only the audit's local
`MaterialTestTriangle` / `MaterialTestShadowTriangle` workaround. The original
MiniQuake3 checkout is not modified.

The baseline Python compiler rejected that source with
`Missing field argument 'surfaceName' for struct ShadowTriangle` at the
production constructor in `src/mq3/renderer/qvm_scene_geometry.ml`. Validation
of the corrected compiler uses this same contract with the workaround removed.
This is a Windows cross-compilation check: the contract imports
`miniquake3_abi.dll`, and this Linux environment has no Windows runtime or Wine.
It is not a claim that the game or this contract was executed on Windows.

## Final validation

All checks below use the final reviewed source hashes recorded in the
[portable machine-readable evidence](STRUCT_NAMESPACE_IDENTITY_2026-11-26.json).
Both compiler CLI pipeline modes are checked. For every fixture/target group,
the Python and native compilers' four emitted images are byte-identical.

| Suite | Fixtures | Emitted images | Actual Linux executions |
|---|---:|---:|---:|
| Namespace/default regressions and controls | 11 | 132 | 44 |
| Existing namespace/type/operator compatibility | 8 | 96 | 32 |
| Original MiniQuake3 contract, workaround removed | 1 | 4 | 0 |
| **Total** | **20** | **232** | **76** |

The first two suites cover Linux x64, Windows x64 and MinUX x64. All executed
Linux programs exited with status 0 and their exact expected output. Windows
and MinUX results are compile/byte-comparison evidence only. The four
MiniQuake3 images target Windows and are all **9,651,712 bytes**, SHA-256
`11364c459c10a71ad453237446484bc0bb7dbb215f0a358ad43a71dc1f0c1075`.

The Python unit suite ran **65 tests: 62 passed, 3 skipped, 0 failed**. The skips
are environment-dependent Windows-native/optional-assembler cases and are
listed in the JSON. Focused existing default-argument and StringBuilder checks
also passed before the final matrices.

### Full compiler bootstrap and fixed point

The final native Linux compiler was built with the corrected Python compiler
using `build.sh`, including its direct/object/project smoke checks. It then
rebuilt itself from exactly the same source and options, passing the same
checks. The two complete compiler images are **byte-identical**:

- Image size: **69,031,328 bytes**.
- SHA-256: `19779cf9753c8fb0a6149879ee7b1d16a252742cb276fafd36a65d3da6f6cae1`.
- Python bootstrap, including smoke checks: **95 seconds**.
- Native self-build, including smoke checks: **102 seconds**.

The fixed-point comparison is significant here: it exposed the remaining
native builtin-name override before publication, after the original small
regressions had already passed.

### Reproducing the core regressions

From either compiler checkout, supply the Python entry point and a freshly
built native compiler to the shared runner:

```sh
python3 tests/check_native_semantics.py \
  --python-compiler ../MiniLangCompilerPy/mlc_win64.py \
  --native-compiler ./build/mlc_linux_x64 \
  --target linux-x64 \
  --fixture tests/struct_namespace_identity/arity_collision.ml \
  --fixture tests/struct_namespace_identity/field_order.ml \
  --fixture tests/struct_namespace_identity/typed_returns.ml \
  --fixture tests/struct_namespace_identity/lexical_bindings.ml \
  --fixture tests/struct_namespace_identity/global_fallback.ml \
  --fixture tests/struct_namespace_identity/default_context.ml \
  --fixture tests/struct_namespace_identity/builtin_methods.ml \
  --fixture tests/namespace_builtins.ml \
  --fixture tests/nested_constant_loops.ml \
  --fixture tests/language_default_stack_args.ml \
  --fixture tests/native_semantics_regression.ml
```

Repeat with `--target windows-x64 --compile-only` and
`--target minux-x64 --compile-only` for the cross-target byte comparisons.
The ten new or adjusted scenarios are also registered in the normal and Linux
test lists of both repositories. The shared fixtures and runner are identical
between the Python and native repositories. No GitHub Actions were used.
