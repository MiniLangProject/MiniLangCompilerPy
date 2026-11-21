# MiniLang 1.3.10

MiniLang adds fixed variable types through `var name as Type = expression`.
Fixed bindings check each write, including assignments from closures and
through module globals. Optional types accept `void`. A dynamic mismatch
returns error `1308` before the store. The compiler rejects incompatible
primitive literals and conflicting annotations.

```minilang
function add(bonus as int) returns int
  var score as int = 10
  score += bonus
  return score
end function
```

Existing single-write annotations and function contracts keep their behavior.
Both compilers can remove checks for proven copies and supported integer
expressions. Small typed integer and float helpers can be inlined, and the
generated code can keep short float expressions in registers across operations.
This release also includes guarded float loop and array construction
optimizations.

Both compiler CLIs and `MINILANG_VERSION` report **1.3.10**.
The Python release contains the reference compiler source. The self-hosted
release provides native Windows x64, Linux x64 and packed MinUX x64 packages.
The packages include the matching standard library, manifests and SHA-256
sidecars. See the [MinUX guide](docs/MINUX.md) for platform prerequisites.

- [Fixed variable types](docs/LANGUAGE_REFERENCE.md#fixed-variable-types)
- [Typed binding and helper benchmarks](docs/reports/TYPED_BINDINGS_2026-11-21.md)
- [Release verification matrix](docs/reports/release-1.3.10-version-matrix.json)
