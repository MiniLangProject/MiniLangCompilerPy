# MiniLang Compiler 1.3.1

Both compiler implementations report **1.3.1** through `--version` and the
compile-time `MINILANG_VERSION` constant.

## Object-oriented language support

The [classes and interfaces guide](docs/OOP.md) documents the complete syntax
and constructor and access rules.

- `class` adds single inheritance with `extends`, virtual instance methods,
  mandatory `override`, and `super.method(...)`. Overrides must preserve the
  inherited parameter and return types and visibility. `final` methods and
  classes cannot be overridden or extended. Abstract classes may declare
  abstract methods, which concrete descendants must implement.
- Fields and methods support `public`, `protected`, and `private`. Access checks
  cover `this`, stable aliases, typed parameters, and qualified static calls.
- An `init(...)` method defines constructor parameters and may use defaults.
  Constructors initialize fields before calling the most-derived initializer.
  Without `init`, only public fields are constructor parameters. Calls through
  class values use the same accepted positional arities as direct calls.
- Interfaces may extend one or more interfaces. Implementations must satisfy
  inherited methods, and runtime `is` recognizes inherited interface identities.
- Dynamic method calls use a precomputed candidate index and a balanced
  fallback search after their two-entry inline cache misses. No whole-program
  speedup is claimed from this dispatch change.

## Validation and distribution

The new positive and rejection fixtures cover constructors, visibility,
overrides, abstract/final rules, dynamic dispatch, and interface inheritance.
The self-hosted compiler reaches a byte-identical fixed point on both targets.
Python and self-hosted compilation produce behaviorally matching OOP fixtures,
but their generated image bytes differ for those fixtures. The Python compiler
release is source-only; Windows x64 and Linux x64 binary
packages are published in the
[self-hosted compiler release](https://github.com/MiniLangProject/MiniLangCompilerML/releases/tag/v1.3.1).
