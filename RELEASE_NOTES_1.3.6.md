# MiniLang 1.3.6

Both compilers now use checked direct calls for dynamic method names with one
or two complete-program implementations. Required parameters of classes without
descendants also support direct method dispatch. Polymorphic bases and larger
method sets retain dynamic dispatch. The Python compiler now preserves caller
stack arguments for dynamic calls with more than eight total arguments.

`--version`, `-version` and `MINILANG_VERSION` report **1.3.6**.

The [OOP evaluation](docs/reports/OOP_DISPATCH_2026-11-14.md) records tests,
byte parity, compiler time, executable size and Windows/Linux runtime samples.
The [release matrix](docs/reports/release-1.3.6-version-matrix.json) records
the final compiler-image hashes and source fingerprints.

Validation: 228 Python integration tests, 45 Python unit tests (one optional
skip), 144 native harness tests and 382 additional native steps passed. The
Windows/Linux OOP parity matrix contains 144 byte-identical images. The
Windows and Linux compiler builds reach a byte-identical self-hosted fixed
point. MiniDoc regenerated the compiler reference with zero warnings.

The Python compiler is distributed as source and requires Python 3.11 or newer.
The matching self-hosted release provides Windows x64 and Linux x64 binaries.
