# MiniLang Compiler 1.2.9

This release improves standard-library throughput and adds portable, bounded
compression without changing MiniLang source syntax or the executable format.

- `std.compress` adds a dependency-free LZ4 raw-block codec, a byte-run codec,
  and a checksummed `MLC1` container. Decoding requires an explicit output
  limit; raw LZ4 blocks interoperate with liblz4.
- Windows SHA-256/384 and HMAC one-shot operations reuse CNG algorithm
  pseudo-handles, avoiding provider open/close overhead for each digest.
- Stable array sorting now uses merge sort; the fast integer sort has a fixed
  pivot and a bounded work stack.
- Threading timeouts use monotonic elapsed time, hash-map tombstones are
  compacted, and TLS, StringBuilder, file copying, and short Windows text
  writes received focused efficiency or correctness improvements.

Both compiler repositories contain the same standard-library modules. The
Python and self-hosted compilers produced byte-identical focused Windows and
Linux executables for the compression and crypto regressions. The detailed
[crypto/compression report](https://github.com/MiniLangProject/MiniLangCompilerPy/blob/v1.2.9/docs/reports/CRYPTO_COMPRESSION_2026-09-20.md)
includes reproducible measurements and test coverage.

The Python suite passes 151/151 tests; the full self-hosted verification passes.
Python bootstrap and native self-hosting produce byte-identical compiler images
for each platform. Their Windows and Linux SHA-256 digests are respectively
`C1D0FD2895B5C853BA461C6BE3A67C6C2A21647D22C23DBBB22897B80A6D685E`
and `84B474193973EC0FED41CB5711F1BDA05FEFA5C8849E3B5DC599F54E81C9C75B`.

Both CLI version switches and `MINILANG_VERSION` report 1.2.9. This Python
compiler release provides GitHub source archives. Ready-to-run Windows x64 and
Linux x64 compiler packages, including `std/` and SHA-256 sidecars, are in the
[matching self-hosted release](https://github.com/MiniLangProject/MiniLangCompilerML/releases/tag/v1.2.9).
