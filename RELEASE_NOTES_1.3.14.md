# MiniLang 1.3.14 — namespace identity, defaults and formatter fixes

Released on 2026-11-26.

This release fixes name-resolution errors that could reject valid imported
struct constructors or silently select the wrong field layout. It also fixes
expanded default-argument frames, preserves module functions through native
builtin lowering, and includes the current `mlfmt` corrections. Both compiler
CLIs and the `MINILANG_VERSION` conditional-compilation constant report
**1.3.14**. Recompile existing applications to pick up generated-code fixes.

## Struct and function namespace identity

An imported module's `Record(left, right)` is distinct from a root-level
`Record` in the entry program. Previously, the root declaration could win even
inside the imported function. A three-field root `Record` caused a false
`Missing field argument 'extra'` error. With two reversed fields, compilation
succeeded but a program that should print `22` instead printed `11`.

Both compilers now resolve unqualified constructors and functions in the
defining namespace/package before falling back to unrelated root declarations.
Local variables, parameters and captured callable values retain their lexical
meaning. Explicit qualified names and import aliases retain their target.
The same rule covers stored and returned constructor values.

Signature type facts use their declaration's context, including annotated
returns and inline parameters. Optimized field access therefore uses the same
struct identity as the actual constructor. A callable local whose name matches
a struct is not assigned that struct's layout merely because of its spelling.

Methods use their owner's containing namespace for ordinary names. An instance
method named `len` does not capture a sibling method's builtin `len(text)` call.
Conversely, a module function named `slice`, `len`, `decode` or `typeof` remains
the selected function through native builtin/intrinsic lowering. The complete
self-build comparison exposed and verified this latter correction.

## Default expressions and call frames

Omitted function arguments and struct-field defaults resolve names in the
context of their declaration. Caller locals, parameters and alias-shaped local
names cannot capture those expressions. Explicitly supplied arguments retain
the caller's context. Defaults still evaluate at each call.

Both code generators plan the outgoing argument area from full signatures,
implicit receivers and calls hidden inside defaults before laying out caller
locals. This prevents expanded stack arguments from overwriting saved values.
The native baseline crashed on the targeted default-stack regression; the
corrected compiler executes it successfully in both pipelines.

The Python compiler also allocates distinct assembler labels for nested
constant `while` and `do-while` loops, including headers that emit no machine
instructions. The native compiler already used distinct loop identifiers.

## Formatter corrections

`mlfmt` now preserves multiline literal contents, whitespace and literal line
endings while formatting the surrounding program. Block indentation handles
comments in headers and an `else` branch that closes its `if` on the same line.
Spacing is normalized around grouped expressions, array literals and word
operators; unary signs remain attached to their operands. Compact calls,
indexing and operator declaration names are preserved.

Shared golden-output regressions cover formatting, idempotence and executable
behavior. These are formatting changes; source literals retain their values.

## Included source updates since the previous binary release

The previous published compiler packages were 1.3.11. This release also includes
these intervening source updates:

- [1.3.12](RELEASE_NOTES_1.3.12.md): preserve NaN through scalar and optimized
  numeric normalization; add complete allocation and full-stop GC diagnostics;
  retain native-thread safety paths when `Thread` appears only in defaults,
  field initializers, lock expressions or expression wrappers.
- [1.3.13](RELEASE_NOTES_1.3.13.md): remove the fixed pending-pair limit from
  array equality, terminate cyclic comparisons and memoize shared subgraphs.
  Flat arrays retain constant comparison workspace without comparison
  allocation. Deep graphs use traced growing storage, with the memory and
  performance costs documented in that update.

The historical reports retain their original source revisions, versions and
measurement scopes; their results are not relabeled as 1.3.14 package tests.

## Validation

The [namespace implementation audit](docs/reports/STRUCT_NAMESPACE_IDENTITY_2026-11-26.md)
records the completed pre-version-bump checks on the corrected 1.3.13 source:

- 228 fixture images agree byte-for-byte across both compilers, both CLI
  pipeline options and the Linux, Windows and MinUX targets.
- All 76 Linux executions in those matrices produce the exact expected output.
- The original MiniQuake3 contract compiles without its local struct-renaming
  workaround; all four Windows images are byte-identical.
- The Python unit suite runs 65 tests: 62 pass, 3 environment-dependent checks
  are skipped and none fail.
- The complete native Linux compiler rebuilds itself byte-identically to the
  Python bootstrap, including direct/object/project smoke checks.

Fresh checks on **1.3.14** verify both CLI version flags in both compilers and
produce 12 version/target-predefine images with four-way byte parity for each
target. All four Linux images execute successfully. The new native Linux
compiler also reaches a byte-identical full self-hosting fixed point and
passes the build script's smoke checks. The Windows and packed MinUX compiler
images match independent Python/native cross-builds byte-for-byte. MinUX
unpack/repack verification reproduces the packed image exactly; its
15,427,999-byte size is below the 16,777,216-byte loader limit.

The [1.3.14 release verification matrix](docs/reports/release-1.3.14-version-matrix.json)
records the new version's compiler builds, predefines and release checks.
Final archive verification, run after the source commit, is provided as
`release-1.3.14-package-verification.json` on both release pages.
Windows and MinUX checks are cross-compilation and byte-comparison evidence
unless explicitly stated otherwise; execution on those operating systems is
not claimed by the Linux-hosted verification.

## Downloads and installation

- [Python reference compiler](https://github.com/MiniLangProject/MiniLangCompilerPy/releases/tag/v1.3.14):
  a source ZIP containing the tagged compiler, standard library, documentation
  and regression tests, with a SHA-256 sidecar. Python 3.11 or newer is required.
- [Native compiler](https://github.com/MiniLangProject/MiniLangCompilerML/releases/tag/v1.3.14):
  Windows x64 ZIP, Linux x64 tar.gz and packed MinUX x64 tar.gz packages, with
  matching libraries, licenses, `BUILD_INFO.json` and SHA-256 sidecars. These
  compilers have no Python runtime dependency.

Extract the whole package. See the
[native binary installation guide](https://github.com/MiniLangProject/MiniLangCompilerML/blob/v1.3.14/README-BINARY.md)
for executable hashes, runtime deployment and host prerequisites, and the
[MinUX guide](docs/MINUX.md) for kernel/runtime requirements.

- [Changelog](CHANGELOG.md)
- [Language reference](docs/LANGUAGE_REFERENCE.md)
