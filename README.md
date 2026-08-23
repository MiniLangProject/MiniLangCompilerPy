# MiniLang - Python Reference Compiler

Current stable release: **1.0.0**.

Release 1.0.0 and later are source-only: generated `.exe` files are not
tracked in Git and are not attached to GitHub releases.

MiniLang (`.ml`) is a small, dynamically typed language that compiles to a
native Windows x64 executable (PE32+) with `mlc_win64.py`. Console applications
are the default; `--subsystem windows` emits a GUI-subsystem executable.

This Python implementation is the bootstrap/reference compiler. Its normal
monolithic build path is kept byte-for-byte output-compatible with the
self-hosted MiniLang compiler in `MiniLangCompilerML`; see
[Compiler parity and self-hosting](COMPILER_PARITY.md).

Both compiler implementations and their documentation were developed with the
assistance of generative AI.

---

## Contents

- [1. Quickstart](#1-quickstart)
- [2. Files & Running](#2-files--running)
- [3. Comments](#3-comments)
  - [3.1 Newlines & statement separators](#31-newlines--statement-separators)
- [4. Types & Literals](#4-types--literals)
- [5. Variables & Assignments](#5-variables--assignments)
- [6. Operators & Expressions](#6-operators--expressions)
- [7. Arrays](#7-arrays)
- [8. Control Flow](#8-control-flow)
  - [8.1 if / else if / else](#81-if--else-if--else)
  - [8.2 while](#82-while)
  - [8.3 loop ... while ... end loop (do-while)](#83-loop--while--end-loop-do-while)
  - [8.4 for ... to](#84-for--to)
  - [8.5 for each ... in](#85-for-each--in)
  - [8.6 break / continue](#86-break--continue)
  - [8.7 switch / case](#87-switch--case)
- [9. Functions](#9-functions)
  - [Deferred cleanup (`defer`)](#deferred-cleanup-defer)
  - [Inline functions (`inline`)](#inline-functions-inline)
  - [9.1 Native threads & synchronization](#91-native-threads--synchronization)
  - [9.2 Thread-safe standard-library types](#92-thread-safe-standard-library-types)
  - [9.3 Managed thread pools](#93-managed-thread-pools)
- [10. struct](#10-struct)
- [11. enum](#11-enum)
- [12. Modules, namespace & import](#12-modules-namespace--import)
- [13. Standard Library & Builtins](#13-standard-library--builtins)
  - [13.1 Stdlib modules (std.*)](#131-stdlib-modules-std)
  - [13.2 Builtins: basics](#132-builtins-basics)
  - [13.3 Bytes / Encoding / File I/O](#133-bytes--encoding--file-io)
  - [13.4 Heap / GC debug](#134-heap--gc-debug)
  - [13.5 Call profiling (optional)](#135-call-profiling-optional)
- [14. extern](#14-extern)
- [15. Error handling: `error` & `try`](#15-error-handling-error--try)
- [16. Syntax Reference (short)](#16-syntax-reference-short)
- [17. Examples](#17-examples)
- [Native compiler status](#native-compiler-status)
- [Compiler parity and self-hosting](#compiler-parity-and-self-hosting)

---

## 1. Quickstart

**Hello World**

```ml
print "Hello MiniLang!"
```

**Variables and math**

```ml
x = 10
y = 5
print x + y
```

**If/then**

```ml
age = 18
if age >= 18 then
  print "ok"
else
  print "nope"
end if
```

Inline form also works:

```ml
if age >= 18 then print "ok" else print "nope" end if
```

Program entry via `main(args)`:
```ml
function main(args)
  print "argc=" + len(args)
  if len(args) > 0 then
    print "first=" + args[0]
  end if
  return 0
end function
```

---

## 2. Files & Running

- Source files use the extension: `.ml`

### Compile to native Windows x64

```bash
python mlc_win64.py input.ml output.exe [options]
python mlc_win64.py -version
```

Notes:
- Flags can appear before or after the positional arguments.
- On non-Windows hosts you can still compile, but running the resulting `.exe` requires Wine.

Common options:

**Import / modules**
- `-I <dir>` / `--import-path <dir>` add an import search path (repeatable). The directory of `input.ml` is always an implicit import root.

**Listings / diagnostics**
- `--asm` write a combined `.asm` listing (default: off)
- `--asm-out <path>` override listing path (default: output basename + `.asm`)
- `--asm-cols addr,opcodes,code` choose columns (default: all)
  - or `--asm-no-addr`, `--asm-no-opcodes`, `--asm-no-code`
- `--asm-data` include `.rdata/.data/.idata` dumps (**constants and imports**)
- `--asm-pe` include a PE32+ header + section table dump in the listing
- `--dump-labels <path>` write a raw section/helper/label dump for parity
  debugging

**Diagnostics**
- `--keep-going` continue after the first error and report multiple diagnostics
- `--max-errors <n>` cap the number of diagnostics when using `--keep-going` (default: 20)

**Heap / GC tuning (native runtime)**
- `--heap-reserve <size>` reserve heap address space (e.g. `256m`)
- `--heap-commit <size>` initial committed heap bytes (e.g. `16m`)
- `--heap-grow <size>` minimum commit growth step when the heap needs to grow (e.g. `1m`)
- `--heap-shrink` enable decommit after GC (trim-from-top). Default: off
- `--heap-shrink-min <size>` minimum committed heap when shrinking (default: initial commit)
- `--gc-limit <size>` bytes allocated between periodic GC runs (default: backend constant)
- `--no-gc-periodic` disable periodic GC trigger (collect only on OOM)

**Profiling / tracing**
- `--profile-calls` instrument user functions with call counters; enables `callStats()`
- `--trace-calls` print each entered function name to stderr (runtime trace)

**Output**
- `--subsystem console` / `cui` selects the default console subsystem
- `--subsystem windows` / `window` / `gui` selects the Windows GUI subsystem

**Cross-compiler build compatibility**
- `--object-pipeline` is accepted so project commands can be shared with the
  self-hosted compiler; the Python compiler still emits its monolithic image

`python mlc_win64.py -version` and `--version` both print
`MiniLang Compiler 1.0.0`. `python mlc_win64.py --help` prints the full option
list.

Notes (current implementation):
- Targets Windows x64 console (PE32+).
- Heap parameters can be configured via `--heap-*` flags (reserve/commit/grow/shrink).
- If a top-level `function main(args)` exists, the native entrypoint will call it after module initialization has completed. Imported module initializers and the entry file's top-level initialization run automatically before `main`. `args` is `argv[1..]` as an array of strings. The returned int becomes the process exit code (void -> 0).
- The native runtime uses a VirtualAlloc heap with **separate reserve/commit**: it reserves a large address range and commits pages on demand.
- Listing order is stable: optional PE dump -> `.text` listing -> optional section dumps.
- The compiler uses the shared MiniLang frontend for parsing (tokenizer/parser).


### Project manifests and incremental builds

Larger programs can keep their entry point, output path and compiler options in
a TOML manifest and build it with one command:

```bash
python mlc_win64.py --project minilang.toml
```

```toml
[project]
entry = "src/main.ml"
output = "build/app.exe"
include = ["src", "vendor"]
subsystem = "console"
object_pipeline = true
incremental = true
cache_dir = ".minilang-cache"
compiler_args = ["--heap-reserve", "1g"]
```

All paths are relative to the manifest. The supported project fields are:

| Field | Meaning |
| --- | --- |
| `entry` / `input` | required entry `.ml` file |
| `output` | required output `.exe` path |
| `include` / `import_paths` | array of import roots |
| `subsystem` | `console` or `windows` (aliases accepted by the CLI) |
| `object_pipeline` | request the self-hosted `.mlo` pipeline |
| `incremental` | enable the exact-hit artifact cache (default `true`) |
| `cache_dir` | cache directory (default `.minilang-cache`) |
| `compiler_args` | array of additional compiler arguments |

Unknown project fields and wrong field types are errors. Command-line
arguments after the manifest are appended; use `--no-incremental` to bypass
the cache for one build. Python 3.11 or newer is required for `--project`.

For manifests that must work with both compilers, use the conservative TOML
subset shown above: a `[project]` table, quoted strings, booleans, and
single-line arrays of quoted strings. Keep comments on their own lines. The
Python implementation uses `tomllib`; the self-hosted implementation has a
small purpose-built parser for this shared subset.

The incremental cache is deliberately conservative. Its fingerprint covers the
manifest, effective compiler arguments, compiler identity and every `.ml`
source below the entry/include roots. An exact hit restores the already linked
executable. Any relevant change performs a full build; this is artifact caching,
not per-module incremental compilation. Listing and label-dump builds bypass
the cache. The Python compiler accepts `object_pipeline` for manifest
compatibility and emits the equivalent monolithic image; the self-hosted
compiler uses its retained `.mlo` pipeline when the field is true.

### Formatting (mlfmt)

There is a small auto-formatter written in MiniLang: `tools/mlfmt.ml`.

Compile it once:

```bash
python mlc_win64.py tools/mlfmt.ml mlfmt.exe -I .
```

Format a single file:

```bash
mlfmt.exe src.ml --inplace
mlfmt.exe src.ml out.ml --indent 2 --max-blank 2
```

Format a whole tree (recursive, **in-place**):

```bash
mlfmt.exe .
```

Insert an Apache 2.0 header (only if missing):

```bash
mlfmt.exe . --apache "Authorname"
# or:
mlfmt.exe . --author "Authorname"
```

Notes:
- `--max-blank -1` allows unlimited blank lines.
- Directory formatting uses Win32 directory enumeration (so it is meant to run on Windows / Wine).
- When `<path>` is a directory, `mlfmt` formats all `*.ml` files recursively **in-place** (the optional `output.ml` argument is only valid for single-file formatting).
- `--apache/--author` uses the local year (via `std.time.win32.GetLocalTime()` in the compiled binary).
- The formatter is intentionally conservative (it does not change program semantics).


### Run

```bash
./output.exe [args...]
```

Running tests:

```bash
python tests/run_tests.py
python tests/run_tests.py --verbose
python tests/run_tests.py --only import
python tests/run_tests.py --allow-skip
```

Notes:
- The test runner compiles a set of `.ml` programs to Windows `.exe` files and executes them.
- On Windows, `.exe` runs natively; on non-Windows you need `wine` to execute the produced binaries.
- `--only PAT` filters by substring, `--verbose` prints full stdout/stderr, and `--allow-skip` exits with code 0 even if some tests were skipped (e.g. no Wine).
- Latest complete run for this revision: **95 passed, 0 failed, 0 skipped**.

### Compiler parity and self-hosting

For identical source files, include roots and compiler options, this compiler
and the self-hosted compiler's normal monolithic path emit byte-identical PE
files. The current 25-program parity matrix covers the language/standard-library
suites, GC stress, compiler-GC liveness, extern/native interop, global rebinding,
native threads and managed thread pools; every pair matches by SHA-256.

The compiler executables themselves are not expected to match: the production
self-build uses the MiniLang-only `.mlo` object pipeline, which has no Python
counterpart and produces a differently laid-out compiler PE. Both compiler
variants nevertheless emit the same tested target executables. Exact hashes,
test counts, boundaries and reproduction commands are recorded in
[COMPILER_PARITY.md](COMPILER_PARITY.md).

The sibling self-hosted compiler also supports `--profile-compiler` for
wall-clock phase timings. Its `.mlo` pipeline uses capacity-backed internal
vectors, a prebuilt per-module function index and sparse read-only support-label
indexes so object clones do not copy the complete support `.data`/`.rdata`.
These are self-host implementation details and do not change the language or
the normal cross-compiler target-byte contract.

The last recorded 112-module / 656-object MiniQuake benchmark predates the
`defer`/managed-FFI/project-manifest revision: the Python monolithic compiler
took 69.089 seconds and the self-hosted object pipeline took 420.095 seconds.
Treat these as historical measurements, not promises for later revisions.

The 1.0.0 self-host source reaches a binary fixed point: the latest two
301-object `.mlo` stages took 181.644 and 470.513 seconds and produced identical
54,650,368-byte compiler images. See the parity report for the exact hash.


---

## 3. Comments

### Line comment

```ml
// this is a comment
print "hi" // comment at end of line
```

### Block comment

```ml
/*
  Multi-line comment
  is ignored
*/
print "ok"
```

### 3.1 Newlines & statement separators

MiniLang is newline-oriented, but supports a few "robust syntax" rules to make formatting easier:

#### Statement separators
- Newlines separate statements.
- `;` can also separate statements (useful for single-line / inline code).

```ml
a = 1; b = 2; print a + b
```

#### Where newlines are optional / ignored
Newlines are allowed (and ignored) in common "continuation" positions:

- **After operators** (and after unary operators):
  ```ml
  x = 1 +
      2 +
      3

  y = -
      5

  z = not
      false
  ```

- **Inside bracketed lists and calls** (after `[` / `(`, after commas, and before the closing `]` / `)`):
  ```ml
  a = [
    1, 2, 3,
    4, 5, 6,
  ]

  print add(
    1,
    2,
    3,
  )
  ```

- **Inside indexing** (after `[` and before `]`):
  ```ml
  v = a[
    0
  ]
  ```

#### Trailing commas
Trailing commas are allowed in array literals and call argument lists:

```ml
a = [1, 2, 3,]
print add(1, 2, 3,)
```

---

## 4. Types & Literals

MiniLang values:

### Numbers
- Int: `1`, `-42`
- Hex int: `0xabc`, `-0x10`
- Binary int: `0b10101`, `-0b10`
- Float: `3.14`, `-0.5`

```ml
a = 10
b = -3.5
h = 0xFF
m = 0b1010
```

Note: the tokenizer currently treats a leading `-` as part of a numeric literal. In expressions like `a-1`, write spaces (`a - 1`) to ensure `-` is parsed as an operator.

### Strings
- Strings use double quotes: `"Text"`
- Common escapes are supported, e.g. `\n`, `\t`, `\"`, `\\`

```ml
s = "Hello\nWorld"
print s
```

### Booleans
- `true`
- `false`

```ml
flag = true
```

### Arrays
- Literals: `[1, 2, 3]`, `["a", "b"]`
- Trailing commas are allowed: `[1, 2, 3,]`
- Multiline literals are allowed (see section 7).

```ml
arr = [1, 2, 3]
```

### Bytes

`bytes` is a mutable raw byte buffer (values `0..255`). You create it with `bytes(...)` (or legacy `byteBuffer(...)`).

- Indexing returns an `int` byte value.
- Assignment `buf[i] = n` expects `n` in `0..255`.

See [13.3](#133-bytes--encoding--file-io) for details and file / encoding examples.

### void
`void` is the “no value” literal.

You get `void` when a function ends without `return`, or explicitly via `return void`. It is a real runtime value, so it can be assigned:

```ml
function maybeGetName()
  if input() == "" then
    return void
  end if
  return "Nina"
end function

x = maybeGetName()
if x is void then
  print "no name"
else
  print x
end if
```

**Strict void handling (runtime):** using `void` in most operations produces a runtime `error(...)`:

- calling it: `void()` or `x()` when `x` is `void`
- member access: `void.field`
- indexing: `void[i]` or `a[void]`
- arithmetic / bitwise ops: `+ - * / % & | ^ ~ << >>`
- ordered comparisons: `< <= > >=`
- boolean ops: `and` / `or` / `not` (if an operand is `void`)
- as a condition in `if` / `while` / `loop ... while`
- `len(void)`

For type checks, prefer:

- `x is void` / `x is not void`
- `x is int`, `x is string`, etc. (primitive type checks; sugar for `typeof(x) == "..."`)
- `x is Thread` / `x is thread` (the native thread category; both spellings
  are equivalent)
- `x is Thing`, `x is Color`, etc. (concrete struct/enum type checks; compares the internal type id)

Equality/inequality (`==`, `!=`) still works with `void` (e.g. `void == void`).

> Note: `print void` (and printing unsupported heap objects) raises a runtime `error(...)`.

#### Legacy note
Older MiniLang versions treated `void` as an internal-only value that was not directly writable (e.g. assignment and printing were rejected). With strict void handling, `void` is writable, but *using it as a real value in operations* now fails loudly as described above.

---

## 5. Variables & Assignments

### Assignment

```ml
name = "Max"
score = 100
```

Variables do not need to be declared.

### Synchronized variables

Use `synchronized` for a shared global binding:

```ml
synchronized counter = 0
```

Synchronized variables may only be declared at top level or in a namespace.
Every read and write uses the runtime's process-wide recursive monitor. For an
assignment such as `counter = counter + 1`, the lock covers the complete
read/modify/write operation.

The binding may contain any MiniLang value, including strings, arrays, bytes,
structs, functions and thread objects. The monitor protects access to the
binding; it does not automatically protect later mutations of an object stored
in it. Wrap compound object operations in a synchronized function or use a
thread-safe collection.

### const (write-once bindings)

Supported at top level, in namespaces, and inside functions.

```ml
const PI = 3.14159
const NAME = "MiniLang"
```

Rules:
- A `const` binding can only be assigned **once**.
- At **top-level / in namespaces**, the initializer must be `constexpr` (compile-time evaluable).
  Typical `constexpr` expressions include literals, arithmetic/bitwise operations on constexpr values, references to other `const`s, and enum values.
- Inside **functions**, the initializer may be any expression, but the name is still write-once.

Note: `const` makes the **binding** immutable (you can’t reassign the name). It does not deep-freeze objects like arrays/bytes.

### What counts as a statement?
Allowed standalone statements are:

- assignments (e.g. `x = 1`)
- function calls (e.g. `foo(1,2)`)
- `print <expr>`

Not allowed, for example:

```ml
1 + 2    // invalid: expressions alone are not statements
```

Statements can be separated by **newlines** or by **`;`**.

---

## 6. Operators & Expressions

### Arithmetic

| Operator | Meaning |
|---------:|---------|
| `+` | add / string concat / array concat / bytes concat |
| `-` | subtraction |
| `*` | multiplication |
| `/` | division |
| `%` | modulo |

Important:
- `-`, `*`, `/`, `%` work only with numbers (not `bool`).
- `+` is special:
  - number + number -> number
  - array + array -> array concatenation
  - bytes + bytes -> bytes concatenation
  - otherwise -> string concatenation (both sides are converted to strings automatically)

Use `str(value)` when an explicit string conversion is clearer.

### Comparisons

| Operator |
|---------:|
| `==` |
| `!=` |
| `>` |
| `<` |
| `>=` |
| `<=` |
| `is <type>` | type check (runtime categories such as `int`/`thread` via `typeof`, struct/enum via internal id) |
| `is not <type>` | negated type check |

### Logic
- `and`, `or` (short-circuit)
- `not` (unary)

```ml
if not (x == 10) and true then
  print "ok"
end if
```

### Bitwise (integers)
- shifts: `<<`, `>>`
- bitwise AND: `&`
- bitwise OR: `|`
- bitwise XOR: `^`
- bitwise NOT: `~x`

### Operator precedence (low -> high)
1. `or`
2. `and`
3. `|`
4. `^`
5. `&`
6. `==`, `!=`, `is`
7. `>`, `<`, `>=`, `<=`
8. `<<`, `>>`
9. `+`, `-`
10. `*`, `/`, `%`
11. unary: `not`, `-x`, `~x`

Parentheses override precedence.

Newlines may appear after operators (see [3.1](#31-newlines--statement-separators)).

---

## 7. Arrays

### Create arrays

```ml
a = [1, 2, 3]
b = ["x", "y"]
c = array(4)         // [void, void, void, void]
d = array(3, "hi")   // ["hi", "hi", "hi"]
```

`array(size[, fill])` initializes a new array with `size` elements.  
If `fill` is omitted, elements are initialized with `void`.
Invalid `size` (non-int, negative, or too large) returns a runtime `error`
(catchable via `try(...)`).

### Multiline literals + trailing commas

```ml
a = [
  1, 2, 3,
  4, 5, 6,
]
```

### Indexing

```ml
arr = [10, 20, 30]
print arr[0] // 10
```

Multiline indexing is allowed:

```ml
print arr[
  2
] // 30
```

Index must be an int (not bool).

Out of bounds indexing (or indexing a non-indexable value) raises a runtime `error`
that you can catch with `try(...)`.

### Assigning to an index

```ml
arr = [1, 2, 3]
arr[1] = 99
print arr // [1, 99, 3]
```

Invalid index assignment (wrong target type, non-int index, out of bounds, invalid byte value)
raises a runtime `error` (catchable via `try(...)`).

### Concatenation

```ml
x = [1,2]
y = [3,4]
z = x + y
print z // [1,2,3,4]
```

---

## 8. Control Flow

### 8.1 if / else if / else

Block form:

```ml
if <cond> then
  ...
else if <cond> then
  ...
else
  ...
end if
```

Inline form (single-line / compact):

```ml
if <cond> then <stmt> end if
if <cond> then <stmt> else <stmt> end if
```

Use `;` to put multiple statements on one line:

```ml
if x > 0 then a = 1; b = 2; print a + b end if
```

### 8.2 while

```ml
while <cond>
  ...
end while
```

### 8.3 loop ... while ... end loop (do-while)
Body executes at least once.

```ml
loop
  ...
while <cond>
end loop
```

### 8.4 for ... to

```ml
for <var> = <start> to <end>
  ...
end for
```

- `start` and `end` must be int
- runs automatically up or down (step +1 or -1)

### 8.5 for each ... in
Iterates over arrays, strings, or bytes.

```ml
for each <var> in <iterable>
  ...
end for
```

### 8.6 break / continue

#### continue
Jumps to the next loop iteration.

```ml
i = 0
while i < 5
  i = i + 1
  if i == 3 then
    continue
  end if
  print i
end while
```

#### break
Exits the current loop or a `switch`.

```ml
while true
  print "once"
  break
end while
```

#### break with a counter: `break n`
`break 2` breaks two nested levels (e.g. inner + outer loop).

```ml
while true
  while true
    print "stop"
    break 2
  end while
  print "never reached"
end while
```

Note: `break`/`continue` should only be used inside matching constructs (loops, and `switch` for `break`).

### 8.7 switch / case

```ml
switch <expr>
  case <value>
    ...
  end case

  case <value1>, <value2>, <value3>
    ...
  end case

  case <start> to <end>
    ...
  end case

  case default
    ...
  end case
end switch
```

- `case X, Y, Z` = multiple values
- `case A to B` = range (mainly useful for ints)
- `case default` = fallback
- When a case matches, its body runs and the switch is exited afterwards.
- `break` inside a case also exits the switch.

Robust syntax for value lists:
- Trailing commas are allowed before the case body: `case 1, 2, 3,`
- Value lists can span multiple lines:

```ml
switch x
  case 1, 2, 3,
       4, 5, 6
    print "hit"
  end case
end switch
```

---

## 9. Functions

### Definition

```ml
function <name>(a, b, c)
  ...
  return <expr>
end function
```

- parameters are names (identifiers)
- `return` is optional
- without `return`, the function returns `void`
- `return;` is allowed and is equivalent to `return`
- Robust syntax: a bare `return` can appear directly before a block terminator in inline forms, e.g. `if cond then return end if`

Example:

```ml
function add(a, b)
  return a + b
end function

print add(2, 3)
```

Multiline parameters are allowed (trailing comma optional):

```ml
function add3(
  a,
  b,
  c,
)
  return a + b + c
end function
```


### Deferred cleanup (`defer`)

Inside a function, `defer` registers a function or method call for execution
when that function leaves:

```ml
function saveFile(path, data)
  handle = openFile(path)
  defer closeFile(handle)
  writeFile(handle, data)
  return true
end function
```

- Deferred calls execute in reverse registration order (LIFO) on `return`,
  normal fall-through and automatic `error` propagation.
- The callee/receiver and all arguments are captured when `defer` is reached;
  later variable assignments do not change the queued call.
- A `defer` in a branch is registered only if that branch executes.
- If a deferred call returns an `error`, it becomes the pending function result;
  older deferred calls still run.
- The current implementation accepts call expressions only and rejects `defer`
  directly inside loops. Put one iteration in a helper function when per-item
  cleanup is needed.

### Inline functions (`inline`)

You can mark **top-level functions** and **struct methods** as `inline`:

```ml
function inline clamp01(x)
  if x < 0 then return 0 end if
  if x > 1 then return 1 end if
  return x
end function
```

For an eligible **direct** call such as `clamp01(v)`, the compiler expands the
callee body at the call site (no call/ret overhead). `inline` is a bounded
optimization request, not a guarantee.

Current behavior / limits:
- Only supported for **top-level functions** and **struct methods** (`function inline ...`).
- `inline` and `synchronized` are mutually exclusive on the same function.
- Only **direct calls** are inlined. Calls through a variable (e.g. `f = clamp01; f(v)`) are not inlined.
- Inline bodies must not capture variables (no closures / env hops / boxed captures).
- Bodies containing loops, `switch`, nested functions, or `defer` are not
  eligible and use the normal callable body instead.
- Inline recursion / mutual recursion is rejected.
- `return <expr>` returns from the *inline call* (the call yields the return value).
- The inline expansion uses an isolated scope so it won't clobber caller locals.
- Eligibility is deliberately cost-bounded, and each callee has a 4096-byte
  native expansion budget. Later call sites fall back to its normal callable
  body instead of allowing unbounded code growth.
- Caller stack sizing includes the widest call inside every eligible inline
  body. Such a call is hidden from the caller's own AST, but still needs the
  same outgoing-argument and GC-rooted call-temp space after expansion.
- Every inline function retains a normal callable body. This deliberately
  trades a small amount of executable size for relocation safety across
  imported aliases, first-class callable values and late budget fallbacks.


### Function calls

```ml
print add(2, 3)
```

Multiline call arguments are allowed (trailing comma optional):

```ml
print add3(
  1,
  2,
  3,
)
```

### 9.1 Native threads & synchronization

`Thread(function[, logicalId])` creates a real Win32 thread object without
starting it. Its entry point must be a top-level, capture-free function with
zero or one parameter. A one-parameter worker receives the exact managed value
passed to `Start(value)`:

```ml
synchronized jobsDone = 0

function worker(data)
  global jobsDone
  // allocations enter the process-wide managed heap
  scratch = array(1024, data)
  jobsDone = jobsDone + 1
  return scratch
end function

t = Thread(worker, "request-worker-1")
print t.Status()  // Created
print t.Start(42) // true
print t.Join()    // true; waits indefinitely
print t.Status()  // Completed
print t.Result()  // the returned array
print t.Close()   // closes the native thread handle
```

Threads are a first-class runtime category. Both constructor-style and
lowercase checks are accepted, including their negated forms:

```ml
print t is Thread      // true
print t is thread      // true
print t is not Thread  // false
```

Thread methods:

- `Start()` or `Start(value)` starts a newly created thread once and returns
  `bool`. Its argument count must match the entry function's zero/one arity.
- `Stop()` atomically requests cooperative cancellation and returns whether a
  running thread changed to `StopRequested`.
- `Join()` waits indefinitely; `Join(timeoutMs)` waits at most the given number
  of milliseconds. Both return `true` only when the thread terminated.
- `Status()` returns `Created`, `Running`, `StopRequested`, `Completed`,
  `Stopped`, or `Failed`.
- `IsAlive()` is true for `Running` and `StopRequested`.
- `Id()` returns the native thread id (`0` before a successful start).
- `LogicalId()` returns the user-defined logical id. `SetLogicalId(value)` can
  replace it while the thread is still in `Created`; the constructor's optional
  second argument sets the initial value. Logical ids do not change the native
  Win32 id.
- `Result()` returns the worker's result (`void` until it publishes one). Use
  `try(t.Result())` when a failed worker returned an `error` value.
- `Close()` closes the native handle after termination. Status metadata remains
  valid; its small control page is retained until process exit.

Worker helpers:

- `threadStopRequested()` reports whether the current worker was asked to stop
  (and returns `false` on the main thread).
- `threadLogicalId()` returns the logical id of the current worker (`void` on
  the main thread).
- `threadSleep(milliseconds)` calls the native sleep primitive.

`Stop()` is safe and cooperative: the compiler inserts cancellation checks at
statement boundaries. It never uses asynchronous thread termination. Long
native calls may finish before cancellation is observed, but a thread in a
blocking native call does not prevent another thread from collecting garbage.

All threads allocate into one process-wide, non-moving managed heap. Allocation,
heap growth, free-list access and collection are serialized internally. Each OS
thread owns only its native stack plus a private GC root chain and temporary
root slots. Collection is cooperative stop-the-world: generated function and
loop safepoints park managed threads, while threads inside known native calls
publish a stable root chain. The collector traces global roots and every
registered thread context before sweeping.

Each thread context also retains its four most recent allocation results as
handoff roots. This closes the short lifetime gap while nested object graphs
are being assembled, before a precise stack or global root owns them. These
slots are GC metadata; they are not a private managed heap.

Consequently, an object created by a worker remains valid after that worker
terminates whenever it is still reachable from a global, another live object,
a thread result or another registered root. `heap_bytes_used()`,
`heap_bytes_committed()` and `heap_bytes_reserved()` report the same global heap
from every thread. `Thread.Close()` releases the native handle and clears roots
owned by the thread object; it does not invalidate objects published elsewhere.

Use a synchronized function when a whole critical section must be serialized:

```ml
function synchronized updateSharedState()
  global jobsDone
  jobsDone = jobsDone + 1
end function
```

All synchronized variables and synchronized functions currently share one
recursive process-wide monitor. Managed object identity is shared across
threads; no copy is made when a reference is published. Concurrent writes to
the same object, array slot or unsynchronized global are data races. Use a
synchronized function, a synchronized binding or the primitives/collections in
the next section to define the required critical section. Console and other
process-wide I/O should also be serialized when multiple workers can use it.

For closed programs that never reference `Thread`, the compiler selects a
single-thread fast path. Generated hot code then omits cancellation and GC
safepoint polls, thread-local root/debug handoffs, managed/native transition
wrappers and allocator/world-lock traffic. Programs that can construct a
`Thread` retain the fully synchronized shared-heap runtime above; after all
workers have exited, uncontended allocation also bypasses the heap lock again.
This selection is automatic and does not change source semantics.

### 9.2 Thread-safe standard-library types

`std.threading` exposes native process-wide synchronization objects:

- `Lock.new()` creates a recursive Win32 mutex. Methods are `acquire()`,
  `tryAcquire()`, `acquireFor(timeoutMs)`, `release()`, `isClosed()` and
  `close()`. `Acquire`, `TryAcquire`, `AcquireFor` and `Release` aliases are
  also available.
- `Semaphore.new(initialCount, maximumCount)` provides `acquire()`,
  `tryAcquire()`, `acquireFor(timeoutMs)`, `release()`,
  `releaseMany(count)`, `isClosed()` and `close()`.
- `Event.new(manualReset, initialState)` provides `wait()`, `tryWait()`,
  `waitFor(timeoutMs)`, `set()`, `reset()`, `isClosed()` and `close()`.

All waits return `bool`; a timeout is reported as `false`. A lock acquired after
`WAIT_ABANDONED` is treated as successfully acquired and must be released.

The collection modules serialize access to managed backing arrays in the global
heap:

- `std.ds.concurrent_list.ThreadSafeList`: `new`, `withCapacity`, `fromArray`,
  `add`/`push`, `addAll`, `get`, `set`, `insert`, `removeAt`, `pop`, `popOr`,
  `first`, `last`, `len`/`count`, `reserve`, `clear`, `toArray`, `close`.
- `std.ds.concurrent_hashmap.ThreadSafeHashMap`: `new`, `withCapacity`, `set`,
  `get`, `getOr`, `has`, `remove`/`delete`, `count`/`len`, `clear`,
  `keysArray`, `valuesArray`, `entriesArray`, `increment`, `close`.
  `increment(key, delta)` is an atomic integer read/modify/write and initializes
  a missing key with `delta`.

Collection values may be arbitrary MiniLang values, including nested arrays and
structs, and retain object identity instead of being deep-copied. Map keys may
be `int`, `string` or `bytes`; unsupported key types return `false` from
mutating methods. Snapshot methods return ordinary managed arrays. As with any
container, a lock protects the collection operation, not an unsynchronized
mutation later performed through an object reference returned by `get()`.

```ml
import std.threading as threading
import std.ds.concurrent_list as concurrentList
import std.ds.concurrent_hashmap as concurrentMap

gate = threading.Semaphore.new(0, 1)
jobs = concurrentList.ThreadSafeList.new()
counts = concurrentMap.ThreadSafeHashMap.new()

function worker()
  gate.acquire()
  jobs.add("done")             // same managed value is visible to all threads
  counts.increment("done", 1) // atomic
end function

t = Thread(worker)
t.Start()
gate.release()
t.Join()
print jobs.get(0)
print counts.get("done")
t.Close()

// Only after all operations and waiters are finished:
jobs.close()
counts.close()
gate.close()
```

Create shared objects before starting their users and keep their global
references alive. `close()` is a lifecycle operation, not a concurrent method:
call it only after all worker operations, lock holders and waiters have ended.
Because cancellation is cooperative, a worker blocked in a native wait can
observe `Stop()` only after that wait returns.

### 9.3 Managed thread pools

`std.concurrent.thread_pool` provides reusable GC-registered workers for
request-oriented workloads such as web servers. Jobs accept one managed data
value, retain its identity in the shared heap, and expose completion, failure
and cancellation without terminating the reusable worker:

```ml
import std.concurrent.thread_pool as threadPool

function handleRequest(request)
  return "handled " + request
end function

pool = threadPool.ThreadPool.withQueueCapacity(8, 1024)
job = pool.Submit(handleRequest, "/status")

if typeof(job) == "void" then
  // bounded queue is full or shutdown has begun: apply backpressure
  return 503
end if

job.Wait()
print job.GetStatus() // Completed, Failed, or Cancelled
print job.GetResult()
job.Dispose()

pool.Shutdown()             // graceful: drain accepted jobs
pool.AwaitTermination()
pool.Dispose()
```

- `ThreadPool.new(workerCount)` uses an unbounded queue.
- `ThreadPool.withQueueCapacity(workerCount, capacity)` bounds waiting jobs;
  capacity `0` is unbounded. Worker counts must be between 1 and 256.
- `Submit(function, data)` returns a `ThreadPoolJob`, or `void` after shutdown
  or when a bounded queue is full.
- `PendingCount()`, `WorkerCount()` and `IsShutdown()` expose pool state.
- `Shutdown()` stops accepting work and drains the queue.
- `ShutdownNow()` cancels queued jobs; currently running callbacks finish
  cooperatively.
- `AwaitTermination()` / `AwaitTerminationFor(timeoutMs)` join all workers.
- `Dispose()` performs graceful shutdown if needed and closes native handles.
- Jobs provide `Cancel`, `Wait`, `WaitFor`, `GetStatus`, `GetResult`, `IsDone`,
  `IsCancelled` and `Dispose`.

Pool workers receive stable logical ids such as `thread-pool-0`. Callbacks may
allocate, trigger GC and return arbitrary managed values. A `Failed` job stores
the callback's `error`; retrieve it with `try(job.GetResult())`. Pool disposal
and job disposal are lifecycle operations and must not race their active users.

### Function values (function pointers)

Functions are **first-class values**. A function name evaluates to a pointer to that function and can be:

- assigned to a variable
- stored in arrays / structs
- passed to other functions
- called indirectly via `fn(...)`

```ml
function add(a, b)
  return a + b
end function

fn = add
print fn(2, 3) // 5
```

Passing a function:

```ml
function apply(fn, a, b)
  return fn(a, b)
end function

print apply(add, 2, 3) // 5
```

Storing in an array (dispatch table):

```ml
function sub(a, b)
  return a - b
end function

ops = [add, sub]
print ops[0](10, 4) // 14
print ops[1](10, 4) // 6
```

Notes:
- `typeof(add)` is `"function"`.
- Inline expansion applies only to **direct** calls (e.g. `add(1,2)`), not to indirect calls like `fn(1,2)`.

Direct **and** indirect calls are supported.


### Program entry: main(args)

If a top-level function named `main` exists with exactly one parameter, it is treated as the program entrypoint:

```ml
function main(args)
  // args is an array of strings (argv[1..], without the program path)
  if len(args) > 0 then
    print args[0]
  end if
  return 0
end function
```

Rules:
- `main` must be declared at top-level (not inside a `namespace`).
- Signature must be `main(args)` (exactly 1 parameter).
- `args` contains `argv[1..]` (arguments after the executable name), parsed with Windows quoting rules.
- If `main` returns an `int`, it becomes the process exit code. If it returns `void` (no return), the exit code is `0`.
- The entrypoint call happens **after** module initialization has executed. Imported modules are initialized automatically before the entry file continues, and all module-init blocks run at most once.


### Recursion

```ml
function fact(n)
  if n <= 1 then
    return 1
  else
    return n * fact(n - 1)
  end if
end function

print fact(5)
```

### Scoping

- Lexical block scopes inside functions (variables are introduced on first assignment in the current block; shadowing is allowed).
- Functions are first-class values (you can store them in variables, pass them around, and call indirectly).
- Nested functions + closures are supported (captured vars are boxed and stored in an environment frame).
  - Current limitation: shadowing of a **captured** name is rejected by the compiler.
- Reading a name that has never been assigned in any visible scope is a compile error (“undefined variable”).
- Writing to a global from inside a function requires an explicit `global` declaration.
  - Unqualified names resolve to the active `package` / `namespace` context of the file.
  - If the global does not exist yet (no prior top-level initialization), the compiler creates it automatically and initializes it to `void`.
  - Globals are keyed by fully-qualified name, so `package Bar` + `Fu` is different from `package Bar2` + `Fu`.

`global` inside functions:

```ml
package demo

function inc()
  global counter
  if typeof(counter) == "void" then counter = 0 end if
  counter = counter + 1
end function

inc()
inc()
print counter // 2
```

You can also declare a qualified global explicitly:

```ml
function setOther()
  global other.pkg.counter
  other.pkg.counter = 123
end function
```

Robust syntax: trailing commas are allowed in `global` declarations:

```ml
function f()
  global counter, total,
  counter = 1
end function
```

---

## 10. struct

```ml
struct Person
  name
  age
end struct

p = Person("Alice", 30)
print p.name
p.age = p.age + 1
print p.age
```

### Methods (OOP-style)
**Inline methods:** You can also write `function inline name(...)` inside a
`struct` to request the same bounded direct-call expansion described in
[9. Functions](#9-functions).


You can define **instance methods** and **static methods** inside a struct.

- Instance methods get an implicit first parameter `this` (the instance).
- Access fields via `this.field`.
- Call instance methods via `obj.method(...)`.
- Call static methods via `StructName.method(...)`.

```ml
struct Box
  value

  function show()
    print this.value
  end function

  static function make(v)
    return Box(v)
  end function
end struct

b = Box.make(123)
b.show()
```

Notes:

- Struct constructors are calls: `Person(arg0, arg1, ...)` (argument count must match the field count).
- Field reads/writes are supported: `p.name`, `p.age = ...`.
- Statically known constructor, method, and field mistakes are diagnosed during
  compilation; dynamic invalid operations follow the runtime's normal
  `error`/`void` behavior.

---

## 11. enum

Ordinal enums currently support up to **65536 variants per enum** and up to **65535 ordinal-enum types** in one program.

Basic form:

```ml
enum Color
  Red
  Green
  Blue
end enum

c = Color.Red
print c
```

### Explicit values

Enum variants can optionally have `= <constexpr>` values (ints, strings, etc.). If a variant has **no** explicit value, the native compiler will:
- auto-increment by `+1` if the previous value is an `int`, otherwise
- require an explicit value (compile error).

```ml
enum Http
  Ok = 200
  Created      // 201
  Accepted     // 202
  NotFound = 404
end enum
```


---

## 12. Modules, namespace & import

### Overview
The native compiler supports **compile-time** composition:
- `namespace` groups declarations under a qualified name.
- `import` merges other `.ml` files into the program before code generation.


### namespace

```ml
namespace geom
  function add(a, b)
    return a + b
  end function

  struct Point
    x
    y
  end struct
end namespace
```

How to use it:
- Calls / constructors can be qualified: `geom.add(1,2)`, `geom.Point(1,2)`.
- In the native compiler, namespaces are **not runtime objects**; they are only used to qualify symbol names.

### import (top-level only)

```ml
import "path/to/other.ml"
```

Module-style form (syntactic sugar):

```ml
import foo.bar   // resolves to "foo/bar.ml"
```

Example with an include root:

```bash
python mlc_win64.py main.ml out.exe -I src
```

You can add multiple search roots by repeating the flag. The compiler also always treats the **directory of the entry file** as an implicit import root.

```bash
# repeat -I / --import-path (recommended)
python mlc_win64.py main.ml out.exe -I src -I std -I vendor
```

Notes:
- `-I` is repeatable. The current CLI does **not** split platform path lists like `src;std;vendor` automatically.

Rules:
- Paths are resolved relative to the importing file’s directory (absolute paths are also allowed).
- If the file is not found there, the compiler also searches the include roots in order: **entry file directory (implicit)** first, then the `-I/--import-path` directories (in the order provided).
- If an import matches multiple files across the search paths, compilation fails with an **ambiguous import** error listing the matches.
- Diagnostics prefer short, stable paths (relative to the entry file directory) when possible.
- Imported modules remain **declaration-oriented**. At top-level (and inside `namespace` blocks) the supported forms are:
  - `package`, `import`, `namespace`
  - `function`, `struct`, `enum`
  - `extern function` / `extern struct`
  - global `const` (initializer must be `constexpr`)
  - global assignments (runtime initializers are allowed)
  - enum variants with explicit `= <value>` must also be `constexpr`
- Imported top-level global assignments are compiled as internal **module initialization** code. They run automatically before `main(args)` and each module-init block runs at most once.
- Side-effectful top-level statements other than global assignments are still rejected in imported modules (for example `print`, top-level `if/while/for`, or arbitrary expression statements).
- Harmless import cycles are supported, and self-imports are ignored. Cycles that create unsafe cross-module initialization reads are diagnosed at runtime during module initialization.
- `import ... as <alias>` is supported: it creates a compile-time alias for the imported module’s `package` name, so you can write e.g. `g.add()` instead of `geom.vec.add()`. The imported file must declare `package ...`.
- Alias names must be valid identifiers and must not be reserved (`try`, `error`).
- If an imported file declares `package foo.bar`, its location must match that package when resolved via a stable root (importing directory or `-I` root): the file should be found as `foo/bar.ml` under that root. Absolute-path imports and aliased explicit file imports (`import "path/file.ml" as X`) skip this location check, which is useful for code-behind files.


### package (top-level only)

A file can declare its *package name* once at the very top:

```ml
package foo.bar
```

This is used by the native compiler’s import system (for `import ... as <alias>` and for verifying that a module’s file path matches its declared package when resolved via an import root).

Notes:
- `package` must be the **first** statement in the file (before `import`, `namespace`, `function`, etc.).
- It is compile-time only (no runtime effect).

### Module initialization

Imported modules may contain top-level global assignments such as:

```ml
package demo

players = [void, void, void, void]
count = len(players)
```

These assignments are compiled into internal module-init code. The compiler/runtime ensures that:

- imported modules initialize automatically before `main(args)`
- each module is initialized at most once
- self-imports are ignored
- simple cyclic imports are allowed
- unsafe cross-module reads during initialization are reported instead of silently using half-initialized state

Top-level `const` still stays compile-time only:

```ml
const Answer = 42
```

---

## 13. Standard Library & Builtins

### 13.1 Stdlib modules (std.*)

MiniLang ships with a source-based standard library in `std/`. You import it the same way you import your own modules:

```ml
import std.string as s
import std.time as t
import std.fs as fs
```

The stdlib is compiled together with your program (there is no separate link step). Most “systems” features are **Windows-oriented** because the native backend targets Windows x64.

The current library contains 26 source modules, byte-for-byte identical in both
compiler repositories:

- **Core:** `std.core`, `std.assert`, `std.array`, `std.sort`, `std.math`,
  `std.random`, `std.fmt`
- **Text and bytes:** `std.string`, `std.string_builder`, `std.bytes`,
  `std.encoding.hex`, `std.encoding.base64`
- **System APIs:** `std.time`, `std.fs`, `std.net`
- **Collections:** `std.ds.list`, `std.ds.stack`, `std.ds.queue`,
  `std.ds.hashmap`, `std.ds.set`
- **Concurrency:** `std.threading`, `std.concurrent.thread_pool`,
  `std.ds.concurrent_list`, `std.ds.concurrent_hashmap`
- **Compatibility helpers:** `std.result` provides `Option` and `Result`;
  `std.concurrent.shared_value` provides a legacy unmanaged snapshot codec.

New code should normally use native `error(...)` propagation with `try(...)`
instead of `std.result.Result`. Managed objects already share one process-wide
heap, so `std.concurrent.shared_value` is not needed for ordinary communication
between MiniLang threads.

Stdlib APIs that can fail (I/O, networking, parsing, …) use MiniLang's native `error(...)` system. In practice this means a function either returns its normal value or an `error` value that automatically propagates unless you intercept it with `try(...)`.

```ml
import std.fs as fs

w = try(fs.writeAllText("demo.txt", "hello\n"))
if typeof(w) == "error" then
  print "write failed: " + w.message
end if
```

### 13.2 Builtins: basics

#### len(x)
Length of arrays, strings, or bytes.

```ml
print len([1,2,3]) // 3
print len("abc")   // 3
print len(bytes(4)) // 4
```

Current runtime behavior: unsupported types return `0`.

#### array(size[, fill])
Creates an array with a fixed size and optional fill value.

```ml
a = array(5)       // 5x void
b = array(5, 42)   // 5x 42
```

Invalid `size` (non-int, negative, or > `2147483647`) returns a runtime `error`
(catchable via `try(...)`).

#### input() / input(prompt)
Reads one line from stdin.

```ml
name = input("Name: ")
print "Hello " + name
```

#### toNumber(x)
Converts string -> int/float (or returns numbers unchanged).

```ml
a = toNumber("123")     // 123 (int)
b = toNumber("3.14")    // 3.14 (float)
c = toNumber(10)        // 10
```

Current runtime behavior: invalid inputs return `void`.

Not allowed:
- `toNumber(true/false)`
- `toNumber(void)`
- non-parsable strings

#### toFloat(x)

Converts an int, float, or numeric string to a float. Invalid inputs return
`void`. Unlike `toNumber`, an integral input still produces a `float`.

```ml
print typeof(toFloat(2))     // "float"
print toFloat("3.5")         // 3.5
```

#### str(x)

Converts a printable MiniLang value to a string. String concatenation uses the
same conversion implicitly.

```ml
print str(123)   // "123"
print str(true)  // "true"
```

#### typeof(x)
Returns a string describing the type of `x`.

Type strings: `int`, `float`, `bool`, `string`, `array`, `bytes`, `void`,
`function`, `enum`, `struct`, `error`, `thread`, `unknown`.

```ml
print typeof(123)      // "int"
print typeof("hi")     // "string"
print typeof([1,2,3])  // "array"

// error values
err = error(2, "bad input")
print typeof(err) // "error"
```

#### typeName(x)
Returns a concrete type name for structs/enums.

- For struct instances (and struct constructor values), returns the struct name.
- For enum values, returns the enum name.
- For all other values, behaves like `typeof(x)`.

Note: `typeof(x)` intentionally stays coarse (`"struct"` / `"enum"`) for backward compatibility.

```ml
struct Animal
  name
end struct

enum Color
  Red
end enum

a = Animal("Fay")
print typeof(a)      // "struct"
print typeName(a)    // "Animal"

print typeof(Color.Red)   // "enum"
print typeName(Color.Red) // "Color"
```

#### error(code, message) -> error value

Constructs an `error` value (fields: `.code` and `.message`).  
See **Chapter 15** for full semantics (automatic propagation and `try(...)`).

#### try(expr) -> value

Stops automatic error propagation for the given expression and returns either the normal value or the `error` value.  
See **Chapter 15** for full details.

### 13.3 Bytes / Encoding / File I/O

File I/O is provided via the stdlib module `std.fs` (see “File I/O” below).

#### bytes(...) / byteBuffer(...)
Creates a mutable `bytes` buffer.

- `bytes(size[, fill])` and `byteBuffer(size[, fill])` allocate `size` bytes, filled with `fill` (default 0).

- `bytes(...)` supports additional forms: `bytes()` (empty), `bytes(string)`
  (UTF-8), `bytes(array<int>)`, and `bytes(bytes)` (copy).
- `byteBuffer(size)` is a legacy alias (1 argument only). Use `bytes(size[, fill])` if you need a fill value.

```ml
buf = bytes(8)
print typeof(buf) // "bytes"
print len(buf)    // 8
buf[0] = 255
print buf[0]      // 255
```

#### decode(bytes[, encoding]) -> string
Decodes a byte buffer to a string.

- Expects a `bytes` object and decodes its complete payload as UTF-8.
- If `encoding` is provided it must be a string, but its content is currently
  ignored. Encodings other than UTF-8 are not implemented.

```ml
b = bytes(3)
b[0] = 65
b[1] = 66
b[2] = 67
print decode(b)           // "ABC"
print decode(b, "utf-8")  // "ABC"
```


#### decodeZ(bytes) -> string
Decodes a `bytes` object as UTF-8, but stops at the first NUL byte (`0x00`).  
Returns `void` on type errors.

#### decode16Z(bytes) -> string
Interprets a `bytes` object as UTF-16LE and stops at the first UTF-16 NUL (`0x0000`).  
Returns `void` on type errors.

Typical use: converting `wstr` data coming from `extern` calls into a MiniLang string.


#### hex(bytes) -> string
Encodes a `bytes` object as a lowercase hexadecimal string.

```ml
b = bytes(4)
b[0] = 0
b[1] = 17
b[2] = 170
b[3] = 255
print hex(b) // "0011aaff"
```

#### fromHex(string) -> bytes
Parses a hexadecimal string into a `bytes` object. Accepts an optional leading `0x` / `0X` prefix,
case-insensitive hex digits, and ignores common separators: spaces, tabs, newlines, `_`, `-`, `:`.
Current runtime behavior: invalid input returns `void`.

```ml
b = fromHex("00 11 aa ff")
print len(b) // 4
print hex(b) // "0011aaff"
```



#### std.encoding.base64

The stdlib module `std.encoding.base64` provides Base64 encode/decode:

```ml
import std.encoding.base64 as b64

b = b64.fromBase64("SGVsbG8=")   // bytes("Hello")
if typeof(b) == "bytes" then
  print decode(b)                // "Hello"
  print b64.toBase64(b)          // "SGVsbG8="
end if
```

Notes:
- `fromBase64(text)` ignores whitespace and returns `bytes` on success, `void` on invalid input.
- `toBase64(bytes)` returns a string on success, `void` on invalid args.


#### slice(bytes, offset, length) -> bytes
Returns a new `bytes` object containing a copy of `length` bytes starting at `offset`.

Rules:
- `offset` and `length` must be integers.
- `offset` may be negative (like indexing): `offset < 0` means `offset += len(bytes)`.
- Bounds are **strict** (no clamping): requires `0 <= offset <= len(bytes)` and `0 <= length` and `offset + length <= len(bytes)`.
- On any type/bounds error, returns `void`.


```ml
b = fromHex("00 11 22 33 44 55")
print hex(slice(b, 2, 3))   // "223344"
print hex(slice(b, -2, 2))  // "4455"
```

#### copyBytes(dst, dstOff, src, srcOff, len) -> void
Copies raw bytes from one `bytes` object into another.

Rules:
- `dst` and `src` must be `bytes`.
- `dstOff`, `srcOff`, and `len` must be non-negative integers.
- The effective copy length is clamped to the remaining tail room of both buffers:
  `min(len, len(dst) - dstOff, len(src) - srcOff)`.
- If an offset is already at or past the end of its buffer, or any argument is invalid, the call is a no-op and still returns `void`.
- Treat source/destination ranges as non-overlapping; overlap behavior is not guaranteed.

```ml
src = fromHex("00 11 22 33 44")
dst = bytes(5, 0)
copyBytes(dst, 1, src, 2, 3)
print hex(dst) // "0022334400"
```

#### fillBytes(dst, off, len, fill) -> void
Fills a range inside a `bytes` object with a repeated byte value.

Rules:
- `dst` must be `bytes`.
- `off` and `len` must be non-negative integers.
- `fill` must be an integer in the range `0..255`.
- The effective fill length is clamped to the remaining tail room of `dst`.
- If `off` is at/past the end, or any argument is invalid, the call is a no-op and still returns `void`.

```ml
b = bytes(6, 0)
fillBytes(b, 2, 10, 0xAB)
print hex(b) // "0000abababab"
```

#### Low-level string and bytes helpers

The runtime also exposes the primitives used to implement `std.string`,
`std.string_builder`, `std.bytes`, and hash maps: `stringHash`, `bytesHash`,
`stringSlice`, `stringIndexOf`, `stringLastIndexOf`, `stringStartsWith`,
`stringEndsWith`, `stringRepeat`, the ASCII trim/case/reverse helpers,
`stringEqualsIgnoreCaseAscii`, `stringJoin`, `bytesStartsWith`, `bytesEndsWith`,
`bytesIndexOf`, `bytesLastIndexOf`, `bytesCompare`, and `copyStringBytes`.
Application code should normally prefer the checked wrappers in the
corresponding `std.*` modules.

#### File I/O
The native runtime currently does not expose low-level file-handle builtins.

File I/O is provided by the **standard library** module `std.fs`, with convenience helpers like:
- `writeAllText`, `readAllText`, `readAllLines`, `appendAllText`
- `writeAllBytes`, `readAllBytes`
- `exists`, `delete`, `fileSize`, `copyFile`, `moveFile`

Most functions that can fail return either their normal value or `error(...)`.
A few APIs return plain `bool` (e.g. `exists`, `delete`).

Example:

```ml
import std.fs as fs
import std.string as s

p = "hello.txt"
chk = try(fs.writeAllText(p, "hello\nworld\n"))
if typeof(chk) != "error" then
  r = try(fs.readAllText(p))
  if typeof(r) != "error" and s.startsWith(r, "hello") then
    print "ok"
  end if
end if
```

### 13.4 Heap / GC debug

These builtins are intended for debugging and validating the generated runtime.

#### heap_count()
Returns the number of *currently live* heap blocks (objects that are not marked as `free`).

#### heap_bytes_used()
Returns the current bump pointer offset: `heap_ptr - heap_base`.
Note: after GC + optional shrink, `heap_ptr` may move backwards (trim-from-top).

#### heap_bytes_committed()
Returns the currently committed heap bytes: `heap_end - heap_base`.

#### heap_bytes_reserved()
Returns the reserved heap address space: `heap_reserve_end - heap_base`.

#### heap_free_bytes()
Returns the total number of bytes in the free-list (sum of free blocks).

#### heap_free_blocks()
Returns the number of blocks currently in the free-list.

#### gc_collect()
Runs the mark/sweep collector and returns `void`.

#### gc_set_limit(limitBytes)
Sets the allocation threshold for the **periodic** GC trigger and returns
`void`.

- A positive integer enables periodic collection with that byte limit.
- Zero, a negative value, or a non-integer disables the periodic trigger.
- The allocation-failure/OOM retry collector remains enabled.
- The current periodic-allocation counter is reset when the limit changes.

Notes (when does GC run?):
- The GC runs **automatically** when an allocation cannot be satisfied and the heap can’t grow further; the runtime triggers a `fn_gc_collect` once and retries the allocation.
- You can also trigger it manually via `gc_collect()`.

Notes:
- The allocator reuses freed blocks via a free-list and falls back to bump allocation.
- If the bump pointer would exceed the committed end, the runtime commits more pages (up to the reserved limit).
- If `--heap-shrink` is enabled, the runtime may decommit unused pages at the top of the heap after GC (trim-from-top).

---


### 13.5 Call profiling (optional)

When compiling with `--profile-calls`, the compiler instruments **user functions** with call counters.
At runtime you can query them via `callStats()`.

```ml
stats = callStats()
if typeof(stats) == "array" then
  for each s in stats
    // each entry is a small struct-like record; print it to inspect fields
    print s
  end for
end if
```

Notes:
- Without `--profile-calls`, `callStats()` is not meaningful (and may return `void`).
- Instrumentation adds overhead; use it for profiling/debugging, not for release benchmarking.


## 14. extern

The native compiler can generate PE imports from `extern` declarations.


### extern function

Syntax:

```ml
extern function <Name>(<params...>) from "<dll>" [symbol "<exportedName>"] [returns <type>]
```

Parameter forms:
- `<type>` (type-only)
- `<name> as <type>` (named, type-checked)
- `out <type>` / `out <name> as <type>` (**experimental**, see below)

Supported ABI types for direct-call inputs:
- `int` / `i64` / `u64` / `i32` / `u32`
- `double`
- `bool` (accepts `bool` or `int` at the call site)
- `ptr` / `pointer` (accepts a native pointer value, `int`, or `void`;
  `void` becomes `NULL`)
- `cstr` / `cstring` (MiniLang `string` → `char*` UTF-8; `void` becomes `NULL`)
- `wstr` / `wstring` (MiniLang `string` → `wchar_t*` UTF-16LE; `void` becomes `NULL`)
- `bytes` / `buffer` / `bytebuffer` (MiniLang `bytes` → pointer to its
  mutable payload; `void` becomes `NULL`)

Supported return types:
- `void` / `none`
- `int` / `i64` / `u64` / `i32` / `u32`
- `ptr` / `pointer`
- `double`
- `bool`
- `cstr` (reads a NUL-terminated `char*` and converts to a MiniLang `string`; `NULL` → `void`)
- `wstr` (reads a NUL-terminated `wchar_t*` and converts to a MiniLang `string`; `NULL` → `void`)

Notes:
- Arity mismatches are a **compile error**.
- Type mismatches at runtime currently return `void` (no exceptions yet).
- `wstr` arguments use a fixed temporary UTF-16 buffer. Very long strings may fail and return `void`.
- If the DLL or symbol can’t be resolved, Windows will usually refuse to start the program (loader error) because imports are resolved by the OS loader.

Example: MessageBox

```ml
extern function MessageBoxW(hwnd as ptr, text as wstr, caption as wstr, style as int)
  from "user32.dll" symbol "MessageBoxW" returns int

MessageBoxW(void, "Hello from MiniLang!", "MiniLang", 0)
```

Example: GetTickCount

```ml
extern function GetTickCount() from "kernel32.dll" returns u32
print GetTickCount()
```

### Native callbacks

`nativeBytesPtr(bytes)` returns a native pointer to the payload of a MiniLang
`bytes` value. The result is represented as a MiniLang `int` so it can be passed
to `ptr` extern parameters or stored in native interop structures. For non-bytes
arguments it returns a null pointer value.

`nativeRawValue(value)` returns a MiniLang `int` containing the raw tagged
MiniLang value. `nativeValueFromRaw(int)` performs the inverse conversion.
These are low-level interop helpers for native APIs that store an opaque
application value and later return it unchanged.

`nativeCallback(fn, "wndproc")` returns a native Win64 callback pointer for a top-level MiniLang function.
The supported mode currently targets Win32 `WNDPROC` callbacks:

```ml
extern function CallWindowProcW(prev as ptr, hwnd as ptr, msg as u32, wParam as ptr, lParam as ptr) from "user32.dll" symbol "CallWindowProcW" returns ptr

function myWndProc(hwnd, msg, wParam, lParam)
  return msg
end function

cb = nativeCallback(myWndProc, "wndproc")
print CallWindowProcW(cb, 0, 1024, 0, 0)
```

Rules:
- The first argument must be a top-level MiniLang function.
- `"wndproc"` callbacks must accept exactly four parameters: `hwnd`, `msg`, `wParam`, `lParam`.
- The callback return value is converted back to native `LRESULT`; `int` and `bool` are supported, other values return `0`.

### extern struct (experimental)

The frontend also accepts `extern struct` declarations to describe an ABI layout:

```ml
extern struct POINT
  x as i32
  y as i32
end struct
```

Layouts use Win64 C-style sequential placement, natural field alignment and a
maximum alignment of eight bytes. Supported fields are `i8/u8`, `i16/u16`,
`i32/u32`, `i64/u64`, `int`, `bool` (Win32 `BOOL`) and `ptr/pointer`. Structs returned
through an implicit `out` parameter are copied into a normal GC-managed
MiniLang struct, so they remain valid after the native call returns. Automatic
managed-field marshaling currently supports `int/i64/u64`, `i32/u32`,
`bool`, and `ptr`; for layouts containing `i8/u8` or `i16/u16`, pass
an explicit `bytes` buffer and decode those fields in MiniLang.

### out parameters (experimental)

You can mark trailing parameters as `out`:

```ml
extern function GetCursorPos(out p as POINT) from "user32.dll" returns bool
```

Rules:
- `out` parameters must appear **at the end** of the parameter list (so they can be implicitly handled at call sites).
- A direct call may omit all trailing `out` arguments. Storage is allocated in
  the current thread's stack frame and is therefore thread-safe and valid for
  the duration of the native call.
- One omitted `out` value becomes the call result. Multiple omitted values are
  returned as a MiniLang array in declaration order.
- If such a call has native return type `bool`, a false result becomes a
  catchable MiniLang `error`; otherwise the native status/result is discarded
  in favor of the marshaled out value(s).
- Full-arity calls remain accepted for backward compatibility. Automatic out
  allocation/marshaling is enabled by omission at a direct call site; indirect
  extern function values retain their declared full arity.

---

## 15. Error handling: `error` & `try`

MiniLang uses **error values** for lightweight error handling (no exception mechanism).  
An error is a normal value with:

- `.code` (int)
- `.message` (string)

### 15.1 Creating an error value

Use the builtin `error(code, message)`:

```ml
return error(2, "bad input")
```

You can also construct and return errors from within helper functions and stdlib code.

### 15.2 Automatic propagation (implicit bubbling)

If a **function call** evaluates to an `error` value, the caller will **automatically return that error** immediately (as if an implicit `return <that error>` happened).

This continues up the call stack until the error is handled or it reaches top-level.

```ml
function parseInt(s)
  // ... on failure:
  return error(100, "not a number")
end function

function loadConfig(path)
  // If parseInt(...) returns an error, loadConfig(...) returns it automatically.
  port = parseInt("oops")
  return port
end function

// If unhandled, an error that reaches top-level terminates the program.
loadConfig("cfg.txt")
```

### 15.2.1 Optional APIs (`void` as absence/failure)

Some builtins intentionally return `void` to indicate failure/absence, e.g.:
- `fromHex(str)`
- `slice(bytes, off, len)`
- `decode(bytes, encoding)`

If you prefer strict behavior, use the stdlib wrappers that return `error(...)` instead:
- `std.encoding.hex.decodeOrError(s)`
- `std.bytes.fromHexOrError(s)`
- `std.bytes.subOrError(b, off, len)`
- `std.bytes.decodeUtf8OrError(b)`

### 15.3 Catching propagation with `try(expr)`

Use `try(expr)` to **stop** the automatic propagation and get back either the normal value or the `error` value.

`try(...)` is a **special form** (its argument is evaluated lazily so it can intercept the propagation).

```ml
e = try(loadConfig("cfg.txt"))

if typeof(e) == "error" then
  print "config error: " + e.message
else
  print "config ok, port=" + e
end if
```

Typical pattern:

- call with `try(...)`
- check `typeof(x) == "error"`
- handle / recover, or re-`return x` to propagate manually

### 15.4 Toolchain diagnostics

The toolchain reports errors with:

- filename
- line/column (when available)
- the relevant source line
- a `^` marker (when available)

#### Parse errors (frontend)
- `ParseError` (syntax / parsing)

#### Compile errors (native backend)
- `CompileError` (code generation / backend validation)

Example (schematic):

```
ParseError: unexpected token
  at main.ml:3:10
  x = 5 / ?
           ^
```

---

## 16. Syntax Reference (short)

### Statements
Statements are separated by newlines or `;`.

- `print <expr>`
- `const <ident> = <expr>` (top-level/namespace requires `constexpr`)
- `synchronized <ident> = <expr>` (top-level/namespace shared binding)
- `<lvalue> = <expr>`
  - `<ident> = ...`
  - `<expr>.<field> = ...`
  - `<expr>[<index>] = ...` (multiline indexing allowed)
- `function name(a,b) ... end function` (multiline params allowed, trailing comma optional)
- `function synchronized name(a,b) ... end function` (process-wide recursive monitor)
- optional entrypoint: `function main(args) ... end function`
- `return` / `return <expr>` / `return;` (and bare `return` directly before `end/else/case` in inline blocks)
- `defer <call-expression>` (inside functions; LIFO cleanup on every function exit)
- `global x, y, z` (inside functions; trailing comma optional; names may be qualified like `foo.bar.x`)
- `if <expr> then ... end if` (block or inline)
- `while <expr> ... end while`
- `loop ... while <expr> end loop` (legacy: `loop ... end loop while <expr>`)
- `for i = <expr> to <expr> ... end for`
- `for each x in <expr> ... end for`
- `break` / `break <int>`
- `continue`
- `switch <expr> ... end switch`
- `struct Name ... end struct` (optional legacy `are` after the name)
- `enum Name ... end enum` (optional legacy `are` after the name; native supports optional `= <constexpr>` values)
- `namespace Name ... end namespace` (top-level or nested in namespaces; imported modules remain declaration-oriented, but top-level global assignments are allowed; native compiler)
- `package foo.bar` (top-level only; must be the first statement; native compiler)
- `import "relative/or/absolute/path.ml" [as <alias>]` (top-level only; native compiler)
- `import foo.bar [as <alias>]` (module-style import; resolves to `foo/bar.ml`; native compiler)
- `extern struct Name ... end struct` (native compiler; experimental)
- `extern function Name(...) from "dll" ...`

### Expressions
- literals: number, string, `true/false`, `[ ... ]` (multiline + trailing comma allowed)
- variable: `name`
- call: `f(a,b)` (multiline args + trailing comma allowed)
- native thread: `Thread(topLevelFunction)`; methods `Start`, `Stop`, `Join`, `Status`, `IsAlive`, `Id`, `Close`
- index: `arr[i]`
- member: `obj.field`
- unary: `-x`, `not x`, `~x`
- binary: `+ - * / % == != > < >= <= and or`
- bitwise: `<< >> & | ^`

Newlines are allowed after operators/unary operators and in common "list" positions (see [3.1](#31-newlines--statement-separators)).

---

## 17. Examples

### 17.1 FizzBuzz

```ml
for i = 1 to 30
  if i % 15 == 0 then
    print "FizzBuzz"
  else if i % 3 == 0 then
    print "Fizz"
  else if i % 5 == 0 then
    print "Buzz"
  else
    print i
  end if
end for
```

### 17.2 Functions + array processing

```ml
function sum(arr)
  total = 0
  for each x in arr
    total = total + x
  end for
  return total
end function

nums = [1,2,3,4]
print sum(nums)
```

### 17.3 Struct + switch

```ml
struct User
  name
  role
end struct

u = User("Nina", "Admin")

switch u.role
  case "Admin"
    print u.name + " is admin"
  end case

  case default
    print u.name + " is user"
  end case
end switch
```

### 17.4 Enum

```ml
enum Role
  Admin
  Guest
end enum

r = Role.Admin
print r
```
## Native compiler status

The Windows x64 native backend generates deterministic PE32+ executables for
the console (default) or Windows GUI subsystem.

What works:
- core types: int, float, bool, string, array, bytes, void
- control flow: `if/else`, `while`, `loop ... while ... end loop`, `for ... to`, `for each ... in`, `switch/case`, `break`/`break n`, `continue`
- LIFO deferred cleanup with `defer`, including return/fall-through/error exits
- bounded source-level `inline` functions with callable fallback bodies
- first-class functions: user functions and many builtins are values; direct **and** indirect calls are supported
- real Win32 threads with cooperative cancellation, data/result handoff,
  native and logical ids, status/join APIs, private stacks, a process-wide
  thread-safe GC heap, synchronized globals/functions and managed thread pools
- nested functions + closures (captured vars are boxed and stored in an environment frame)
- `main(args)` entrypoint (argv[1..] as `array<string>`, `return int` -> process exit code)
- `global` declarations inside functions (required for accessing globals from a function; resolves to package/namespace-qualified globals; missing globals are auto-created as `void`)
- `struct` (constructors + field read/write)
- `enum` (values like `Color.Red`, comparisons, printing, `switch`)
- `namespace` blocks (compile-time name qualification)
- `package` + `import` (compile-time multi-file merge; imported modules support runtime-initialized globals, self-import ignore, and harmless import cycles)
- `const` (write-once bindings; top-level/namespace consts are evaluated at compile time)
- `enum` explicit values (constexpr) + auto-increment for missing int values
- `extern function` via the PE import table (IAT), ABI-layout
  `extern struct`, omitted trailing `out` parameters and Win64 callbacks
- TOML project manifests with conservative exact-hit artifact caching
- builtins / special forms: `len`, `input`, `toNumber`, `toFloat`, `str`,
  `typeof`, `typeName`, `error`, `try`, `array`, `bytes`/`byteBuffer`,
  `decode`, `decodeZ`, `decode16Z`, `hex`, `fromHex`, `slice`, `copyBytes`,
  `fillBytes`, native string/bytes helpers, `Thread` and its worker helpers,
  `nativeBytesPtr`, `nativeRawValue`, `nativeValueFromRaw`, `nativeCallback`,
  plus debug helpers: `heap_count`, `heap_bytes_used`, `heap_bytes_committed`, `heap_bytes_reserved`, `heap_free_bytes`, `heap_free_blocks`, `gc_collect`, `gc_set_limit`, `callStats`

Debugging / listings:
- `--asm` writes a combined `.asm` listing
- `--asm-pe` prepends a PE header + section table dump
- `--asm-data` appends `.rdata/.data/.idata` dumps (useful to inspect constants and imports)

Heap sizing flags:
- `--heap-reserve <size>`: reserved address space
- `--heap-commit <size>`: initial committed bytes
- `--heap-grow <size>`: minimum commit growth step
- `--heap-shrink`: enable decommit after GC (trim-from-top)
- `--heap-shrink-min <size>`: minimum committed heap when shrinking

Optimizations (always-on, conservative):
- **Constant pooling**: identical `.rdata` constants are stored once and referenced by multiple sites.
- **Bounded inlining with safe fallback bodies**: eligible direct calls expand
  up to 4096 generated native bytes per callee; every function retains a normal
  callable body so imported aliases, data references and later calls remain
  valid.
- **Local representation type flow**: locals whose complete write set proves a
  stable `int`, `float`/number, `bool`, string, array, bytes or concrete struct
  representation bypass the corresponding dynamic dispatch. This includes
  direct tagged integer operations, numeric-only float arithmetic, bool
  conditions, fixed-offset struct fields and type-specialized indexing.
  Parameters, captured/boxed, synchronized, global or otherwise ambiguous
  values retain the generic checked path.
- **Loop specialization and bounds-check elimination**: small constant `for`
  loops can be unrolled; larger constant-bound loops avoid dynamic end/direction
  state. For a fixed-length local array or bytes value, an inclusive range
  proven inside `0..len(value)-1` loads the container base once and removes the
  per-iteration target, index-tag and bounds checks. Negative or unproven
  indices retain normalization and full bounds validation.
- **GC-root liveness and prologues**: expression roots are unpublished as soon
  as their lifetime ends, call spills are sized to actual arity, and tiny root
  frames use straight-line initialization.
- **Branch/peephole optimization**: resolved backward edges use x64 short
  branches when in range, jumps to the immediately following label disappear,
  and local redundant instruction patterns are folded.
- **Helper pruning**: only referenced `fn_*` runtime helpers are emitted.

GC flags:
- `--gc-limit <size>` overrides the periodic GC threshold (default: `1m` in the current backend).
- `--no-gc-periodic` disables periodic GC triggering (GC runs only on allocation failure / OOM path).
