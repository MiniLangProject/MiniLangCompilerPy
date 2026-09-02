# MiniLang Compiler 1.2.3

MiniLang 1.2.3 is a source-only maintainability and documentation release of
the matching Python reference and self-hosted compilers. Generated executables
remain excluded from Git and from GitHub release assets; native compilers are
rebuilt and verified from the tagged sources.

Highlights:

- complete, meaningful English API documentation for the Python reference
  compiler and the shared cross-platform standard library;
- a source-policy regression that prevents new undocumented public Python APIs;
- focused helpers replacing the largest self-hosted statement and generic-call
  code-generation routines while preserving target-code emission order;
- deterministic, timestamp-free checked-in MiniDoc references; and
- refreshed compiler and standard-library HTML and Markdown documentation.

Python and self-hosted compilers retain compatible Windows x64 PE32+ and Linux
x64 ELF64 target output. Build the compiler from source by following the
repository README and see `CHANGELOG.md` for the detailed change list.
