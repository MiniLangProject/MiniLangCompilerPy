# MiniLang Compiler 1.2.17

This patch release adds automatic secure seeding to `std.random` in both
standard-library copies. The existing deterministic API is unchanged.
Both CLI version flags and compile-time `MINILANG_VERSION` report **1.2.17**.

## Automatic random seeding

```ml
import std.random as random

function main(args)
  rng = try(random.autoSeeded())
  if typeof(rng) == "error" then
    print rng.message
    return 1
  end if
  print rng.rangeInt(1, 7) // 1 through 6
  return 0
end function
```

- `autoSeeded()` creates an independent RNG from four bytes supplied by
  `std.crypto.secureRandom`: Windows CNG or Linux OpenSSL 3.
- Zero state is rejected and sampled again because xorshift32 cannot leave it.
  Entropy-provider errors propagate unchanged; no timestamp or fixed-seed
  fallback is used. Use `try(...)` to handle failures.
- Secure seeding does **not** turn xorshift32 into a cryptographic generator.
  Use `std.crypto.secureRandom(length)` directly for secrets.
- Seeds and sequences can collide; they are not unique identifiers.
- Create a generator once and reuse it, normally one instance per thread.
  Sharing its mutable state requires synchronization.
- `seeded(seed)`, its deterministic sequences and its explicit zero-seed
  behavior remain unchanged. On Linux, automatic seeding needs
  `libcrypto.so.3`; deterministic-only fixtures do not load it.

No language syntax, code-generation algorithm, managed-memory policy or native
media ABI was changed. This is a standard-library feature release, not a new
performance optimization. No new application-performance claim is made.

## Validation

- Python full regression suite: **159 passed, 0 failed, 0 skipped**.
- Self-hosted suite: **136 core cases passed, 0 failed**, plus outer checks.
- New tests cover known deterministic vectors, high-bit/little-endian seed
  decoding, zero-state retries, immediate and post-retry provider failures,
  independent state, collection survival and concurrent per-thread creation.
  Tests do not assume random samples are distinct.
- **24 random-fixture images** execute successfully and match byte-for-byte
  per target/fixture across Python, Windows ML and Linux ML hosts with both
  pipeline options. Linux deterministic-only fixtures also pass a loader check.
- Version/runtime fixtures execute with six-way per-target byte parity.
  Both `--version` and `-version`, and compile-time `MINILANG_VERSION`, report 1.2.17.
- Windows Python bootstrap and native selfbuild are byte-identical.
  Python and Windows ML also produce byte-identical Linux compiler images.
  A full Linux-native compiler selfbuild was not repeated for this release;
  the release-stamped Linux compiler was checked through the fixture matrix.
- Structural codegen and canonical Linux runtime-blob checks pass.
- All **53 standard-library modules** and the generated standard-library
  references are byte-identical between repositories.
- MiniDoc standard-library reference: **53 files, 1,930 symbols, 0 warnings**.
  Compiler reference: **37 files, 3,287 symbols, 0 warnings**.
- Extracted Windows/Linux packages pass version, hello/std-import, automatic
  seeding and deterministic-only smoke tests. Manifest and archive hashes match.

The [random parity manifest](https://github.com/MiniLangProject/MiniLangCompilerML/blob/v1.2.17/docs/reports/release-1.2.17-random-parity.json)
and [version matrix](https://github.com/MiniLangProject/MiniLangCompilerML/blob/v1.2.17/docs/reports/release-1.2.17-version-matrix.json)
preserve the release-stamped fixture hashes.
Python accepts the object-pipeline option but emits its monolithic equivalent.
The existing native `cstr` return-lowering exception to general byte parity
remains unchanged; see [compatibility scope](https://github.com/MiniLangProject/MiniLangCompilerML/blob/v1.2.17/COMPILER_PARITY.md).

## Release-stamped compiler checksums

| Executable | Bytes | SHA-256 |
| --- | ---: | --- |
| Windows `mlc.exe` | 55,015,936 | `0895874C84BBFFFDB060B784B99030903C663281D81F06D69EA5059941C78EAB` |
| Linux `mlc` | 55,017,456 | `69131667618014713A6D7107A92298F8196FE72169FAD2BB17BD600817CA84C8` |

Archive checksums are provided as separate `.sha256` downloads.

## Downloads

This Python release provides GitHub source archives. Ready-to-run Windows and
Linux packages are available in the [matching self-hosted release](https://github.com/MiniLangProject/MiniLangCompilerML/releases/tag/v1.2.17).
