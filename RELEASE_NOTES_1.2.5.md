# MiniLang Compiler 1.2.5

MiniLang 1.2.5 reduces actual generated x64 machine code in the matching Python
reference and self-hosted compilers, and fixes an existing object-pipeline
variadic-array lifetime bug. No executable packer or runtime unpacking is used.

Highlights:

- Shorter accumulator-immediate instructions and implicit-one shifts.
- Flag-equivalent 32-bit AND masks where the 64-bit result is unchanged.
- Conservative fallthrough branch-pair folding with label/relocation barriers.
- An updated canonical Linux syscall/pthread runtime blob, with a reproducible
  byte/label/relocation check against the Python implementation.
- Retained variadic escape-analysis facts after MLO function-body release,
  preventing globally retained argument arrays from referring to caller stacks.
- New opcode, CPU flag/result, boundary, GC lifetime and object-parity tests,
  plus paired size/runtime measurements and refreshed compiler API docs.

Same-source measurements before the release version stamp reduced executable
file sizes by 1.47–1.78%, including approximately 1.09 MB for the self-hosted
compiler. Overall measured runtime was comparable, not universally faster;
individual microbenchmarks and desktop scheduling noise still matter. See the
[measurement report](docs/reports/CODE_SIZE_2026-09-05.md) for raw samples,
limitations and exact before/after image identities.

Both version switches (`-version` and `--version`) report
`MiniLang Compiler 1.2.5`; the predefined `MINILANG_VERSION` is `"1.2.5"`.
Windows x64 PE and Linux x64 ELF remain supported. Current Python and
self-hosted outputs retain the canonical byte-identity contract; see
[release verification](COMPILER_PARITY.md) for the fixed point and test results.
The shared standard-library sources are unchanged from 1.2.4.

This remains a source-only release. Generated executables are excluded from
Git and GitHub release assets; native build verification is performed locally.
Bootstrap from the matching Python repository and rebuild the self-hosted
compiler with `build.ps1`. Existing 1.2.4 tags and releases remain available.
