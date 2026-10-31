# MiniLang Python reference compiler

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

MiniLang compiles `.ml` programs directly to native **Windows x64 (PE32+)** or
**Linux x64 (ELF64)** executables. This repository contains the Python bootstrap
and reference compiler. The [self-hosted compiler](https://github.com/MiniLangProject/MiniLangCompilerML)
is written in MiniLang and provides ready-to-run compiler packages.

The reference compiler is distributed as source. See the [latest release](https://github.com/MiniLangProject/MiniLangCompilerPy/releases/latest),
[release notes](RELEASE_NOTES_1.3.2.md) and [changelog](CHANGELOG.md).

## Quick start

Save this as `hello.ml`:

```ml
function main(args)
  print "Hello from MiniLang!"
  return 0
end function
```

From the repository root, on Windows:

```powershell
python mlc_win64.py hello.ml hello.exe -I .
.\hello.exe
```

On Linux (Python 3.11 or newer):

```sh
python3 mlc_win64.py hello.ml hello --target linux-x64 -I .
./hello
```

The default target is Windows x64, even when the compiler runs on Linux. Set
`--target linux-x64` to produce a Linux executable. The output runs on its
selected target OS. Top-level statements also work without `main`; if present,
`main(args)` runs after module initialization and its integer return value
becomes the process exit code.

## Language and runtime

- Dynamic values with optional checked type annotations, functions, closures,
  arrays, bytes, structs, enums, packages and imports.
- Classes with single inheritance, virtual methods, `override`, `super`,
  abstract and final members, constructors, visibility rules and inherited
  interfaces. See the [OOP guide](docs/OOP.md).
- Native threads, synchronization, managed tasks and a shared garbage-collected
  heap on both targets.
- Standard-library modules under `std/`, native FFI, conditional compilation,
  typed inline x64 assembly, and `error`/`try` propagation.

For example, virtual dispatch calls the derived method:

```ml
class Animal
  function speak() returns string
    return "animal"
  end function
end class

class Dog extends Animal
  override function speak() returns string
    return super.speak() + " / dog"
  end function
end class

function main(args)
  pet as Animal = Dog()
  print pet.speak()
  return 0
end function
```

See the [language reference](docs/LANGUAGE_REFERENCE.md) for syntax and the
[standard-library API reference](docs/api/std/markdown/README.md) for generated
API documentation.

## Compile a project

```powershell
python mlc_win64.py src/main.ml build/app.exe -I . -I src
python mlc_win64.py --project minilang.toml
python mlc_win64.py --version
python mlc_win64.py --help
```

A shared project manifest can be used with either compiler:

```toml
[project]
entry = "src/main.ml"
output = "build/app.exe"
include = ["src", "vendor"]
target = "windows-x64"
incremental = true
cache_dir = ".minilang-cache"
```

Paths in the manifest are relative to the manifest file. `--project` requires
Python 3.11 or newer. A direct build can opt into native-function reuse with
`--incremental-cache DIR`; `--no-incremental` bypasses the cache. See the
[incremental-build guide](docs/INCREMENTAL_BUILDS.md).

| Option | Use |
| --- | --- |
| `--target windows-x64\|linux-x64` | Select the output platform. |
| `-I DIR` | Add an import root; repeat as needed. |
| `-DNAME[=VALUE]` | Set a typed conditional-compilation option. |
| `--subsystem windows` | Build a Windows GUI application. |
| `--asm`, `--asm-data` | Emit an assembly listing and optional data sections. |
| `--heap-reserve SIZE`, `--gc-limit SIZE` | Configure the native runtime. |
| `--profile-calls`, `--pgo-profile FILE` | Collect call counts and guide inlining. |

`--object-pipeline` is accepted for shared build commands but the Python
compiler emits the equivalent monolithic image. The self-hosted compiler can
also emit and link `.mlo` objects. Both compiler implementations are expected
to produce identical target bytes for the same supported inputs, options and
target. Version 1.3.2 restored this parity for the OOP regression programs;
see the [parity guide](COMPILER_PARITY.md) and
[1.3.2 verification matrix](https://github.com/MiniLangProject/MiniLangCompilerML/blob/v1.3.2/docs/reports/release-1.3.2-version-matrix.json).

## Documentation and development

| Topic | Document |
| --- | --- |
| Classes and interfaces | [OOP guide](docs/OOP.md) |
| Language syntax, standard library and FFI | [Language reference](docs/LANGUAGE_REFERENCE.md) |
| Incremental builds | [Guide](docs/INCREMENTAL_BUILDS.md) |
| Typed inline assembly | [Guide](docs/INLINE_ASM.md) |
| Native crypto, checksums and CPU features | [Native primitives](docs/NATIVE_PRIMITIVES.md) |
| Compression and platform services | [Platform services](docs/PLATFORM_SERVICES.md) |
| Executable packing | [Packing guide](docs/EXECUTABLE_PACKING.md) |
| Generated `std` API | [MiniDoc output](docs/api/std/markdown/README.md) |
| Changes and releases | [Changelog](CHANGELOG.md) · [Releases](https://github.com/MiniLangProject/MiniLangCompilerPy/releases) |

Run the Python regression suite from the repository root on a supported host:

```powershell
python tests/run_tests.py
```

Both compiler implementations and their documentation were developed with the
assistance of generative AI. Licensed under [Apache 2.0](LICENSE); see
[third-party notices](THIRD_PARTY_NOTICES.md) for bundled or generated-code
components that require attribution.
