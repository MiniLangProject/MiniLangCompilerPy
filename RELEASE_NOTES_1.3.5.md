# MiniLang 1.3.5

This release integrates direct `typeof` literal comparisons in both compilers
and fixes qualified type lookup, shadowed member access and inline error
propagation. The 1.3.4 loop-parity repair remains included.

`--version`, `-version` and `MINILANG_VERSION` report **1.3.5**.

Validation: 227 Python integration checks, 45 unit tests (one optional NASM
skip), 143 native harness tests, 257 outer steps, 288 focused/OOP parity images
and 192 incremental checks. Seven full compiler builds reach a byte-identical
fixed point within each target. Both std copies and their generated docs match.

Read the [correctness and performance evaluation](docs/reports/TYPEOF_FOLDING_2026-11-13.md)
for before/after time, memory, image-size results and measurement limitations.
The [release matrix](docs/reports/release-1.3.5-version-matrix.json) records hashes,
source fingerprints, build options and cross-host/target checks.

The native release provides complete Windows x64 ZIP and Linux x64 tar.gz
packages with std, native-media runtime, manifests and SHA-256 sidecars.
Extract the complete archive. The Python release is source and requires
Python 3.11 or newer. Windows remains the default output target; use
`--target linux-x64` for ELF output.
