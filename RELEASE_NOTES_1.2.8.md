# MiniLang Compiler 1.2.8

This release strengthens MiniLang's collection safety and numeric intent while
preserving cross-compiler target-output compatibility.

- `div` provides explicit integer floor division, including defined behavior
  for negative operands.
- `std.math` adds exact, floor, ceiling, truncating and rounding conversions to
  integers.
- Normal arrays can store `void`; byte buffers remain strict. New `std.array`
  helpers provide Option, fallback, conditional-write and detailed-error access.
- The compiler rejects provably invalid index types, constant out-of-bounds
  accesses and missing members on statically known structs.
- Struct fields can declare defaults used by positional and named constructors.
- Long statically string-starting concatenation chains compile iteratively,
  avoiding expression-temp exhaustion and repeated dynamic dispatch.

Both compiler implementations include matching language, formatter, standard
library, documentation and regression updates. Windows and Linux focused
fixtures are byte-identical between the Python and self-hosted compilers. Three
consecutive Windows compiler stages converge to one 65,274,880-byte image with
SHA-256
`60DB15723F1D33AFCCBAF81657E91569811C38CF54A320117857C29027700E0B`.

The Python suite passes 149/149 tests, with the new long-chain regression also
verified independently. The complete self-hosted verification passes its
136/136 embedded tests and all outer Windows, Linux, FFI, GC, threading and MLO
gates.

Both CLI version switches and `MINILANG_VERSION` report 1.2.8.

Following existing Python compiler releases, GitHub publishes source archives
for this repository. Ready-to-run native Windows and Linux packages are
published by the matching MiniLangCompilerML release.
