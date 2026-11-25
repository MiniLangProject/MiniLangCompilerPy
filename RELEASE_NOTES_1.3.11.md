# MiniLang 1.3.11

Released on 2026-11-25.

This correctness release makes overlapping byte and array copies reliable and
aligns constant string lengths with native runtime strings. Both compiler CLIs
and the `MINILANG_VERSION` conditional-compilation constant report **1.3.11**.

## Overlap-safe copies

`copyBytes` and `copyArray` now preserve the original source values when the
source and destination ranges overlap. Direct calls and calls through stored
function values have the same behavior. For example:

```minilang
values = [1, 2, 3, 4, 5]
copyArray(values, 1, values, 0, 4)
print values == [1, 1, 2, 3, 4]  // true
```

Overlapping ranges use a directional copy without allocating a temporary
buffer. Disjoint ranges retain the optimized copy path. Array copies preserve
the existing garbage-collector write barrier and use whole aligned cells.
Existing clipping and invalid-argument behavior is retained.

## Consistent UTF-8 string lengths

Native `len(string)` counts **UTF-8 bytes**. The Python compiler now applies
this rule when folding a constant string, matching variables, function
arguments, array elements, and the self-hosted compiler:

```minilang
text = "Grüße 🌍"
print len("Grüße 🌍")  // 12
print len(text)        // 12
```

String metadata, byte-based indexing and standard-library buffer sizing keep
their existing semantics. Embedded NULs are included in the length. The
separate WebAssembly compiler retains its own documented length policy.

## Compiler fixes and regression coverage

The companion self-hosted release corrects native-helper dispatch boundaries
and preserves the source pointer in its generic direct byte-copy path.
Shared regressions cover copy direction, aliases, clipped and empty ranges,
Unicode lengths, copied references surviving collection, initializer scope,
and Boolean/integer equality. The existing initializer and comparison rules
are preserved.

The [implementation validation report](docs/reports/NATIVE_COPY_AND_LENGTH_2026-11-25.md)
records the checks completed before the version bump: 1,446 copy cases in the
shared fixture, 8,820 independent native-helper comparisons including guard
pages, and byte parity across the Python, native monolithic, and native MLO
paths. Executable checks in that report ran on Linux; Windows and MinUX images
were cross-compiled and compared. See the
[1.3.11 release verification matrix](docs/reports/release-1.3.11-version-matrix.json)
for version-specific build and regression results. Final archive checks run
after the source commit and are reported separately in
`release-1.3.11-package-verification.json` on both 1.3.11 release pages.

## Distribution

This repository supplies the Python reference compiler as source. Ready-to-run
native compiler packages are published in the
[MiniLangCompilerML 1.3.11 release](https://github.com/MiniLangProject/MiniLangCompilerML/releases/tag/v1.3.11).
Use the matching standard library from the release checkout or package.

- [Changelog](CHANGELOG.md)
- [Language reference](docs/LANGUAGE_REFERENCE.md)
- [Native copy and runtime primitives](docs/NATIVE_PRIMITIVES.md)
- [MinUX setup and platform prerequisites](docs/MINUX.md)
