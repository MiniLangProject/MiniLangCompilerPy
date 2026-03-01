# MiniLang (ML) - Documentation

MiniLang (`.ml`) is a small, dynamically typed language that compiles to a native Windows x64 console executable (PE32+) via the Win64 compiler tool (`mlc_win64.py`).

It is completely developed with the help of generative AI (ChatGPT version >= 5.2)

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
- [10. struct](#10-struct)
- [11. enum](#11-enum)
- [12. Modules, namespace & import](#12-modules-namespace--import)
- [13. Standard Library & Builtins](#13-standard-library--builtins)
  - [13.1 Stdlib modules (std.*)](#131-stdlib-modules-std)
  - [13.2 Builtins: basics](#132-builtins-basics)
  - [13.3 Bytes / Encoding / File I/O](#133-bytes--encoding--file-io)
  - [13.4 Heap / GC debug](#134-heap--gc-debug-native-compiler)
- [14. extern](#14-extern-native-compiler)
- [15. Error handling: `error` & `try`](#15-error-handling-error--try)
- [16. Syntax Reference (short)](#16-syntax-reference-short)
- [17. Examples](#17-examples)
- [Native compiler status](#native-compiler-status)

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

Notes:
- Flags can appear before or after the positional arguments.
- On non-Windows hosts you can still compile, but running the resulting `.exe` requires Wine.
```

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

**Heap / GC tuning (native runtime)**
- `--heap-reserve <size>` reserve heap address space (e.g. `256m`)
- `--heap-commit <size>` initial committed heap bytes (e.g. `16m`)
- `--heap-grow <size>` minimum commit growth step when the heap needs to grow (e.g. `1m`)
- `--heap-shrink` enable decommit after GC (trim-from-top). Default: off
- `--heap-shrink-min <size>` minimum committed heap when shrinking (default: initial commit)
- `--gc-limit <size>` bytes allocated between periodic GC runs (default: backend constant)
- `--no-gc-periodic` disable periodic GC trigger (collect only on OOM)

**Profiling**
- `--profile-calls` instrument user functions with call counters; enables `callStats()`

Tip: `python mlc_win64.py --help` prints the full option list.

Notes (current implementation):
- Targets Windows x64 console (PE32+).
- Heap parameters can be configured via `--heap-*` flags (reserve/commit/grow/shrink).
- If a top-level `function main(args)` exists, the native entrypoint will call it after top-level code has executed. `args` is `argv[1..]` as an array of strings. The returned int becomes the process exit code (void -> 0).
- The native runtime uses a VirtualAlloc heap with **separate reserve/commit**: it reserves a large address range and commits pages on demand.
- Listing order is stable: optional PE dump -> `.text` listing -> optional section dumps.
- The compiler uses the shared MiniLang frontend for parsing (tokenizer/parser).


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

### void (internal)
Functions can end without returning a value -> the result is `void` (not directly writable).

As a language rule, `void` must not be:
- assigned to a variable
- printed
- used as a condition (`if`, `while`)
- used with operators (`+`, `-`, ...)

Example (invalid):

```ml
function foo()
  print "hi"
end function

x = foo()      // invalid (void)
print foo()    // invalid (void)
```

---

## 5. Variables & Assignments

### Assignment

```ml
name = "Max"
score = 100
```

Variables do not need to be declared.

### const (write-once bindings)

**Native compiler:** supported (top-level and inside functions).  

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
  - otherwise -> string concatenation (both sides are converted to strings automatically; there is currently no `str()` builtin)

### Comparisons

| Operator |
|---------:|
| `==` |
| `!=` |
| `>` |
| `<` |
| `>=` |
| `<=` |

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
6. `==`, `!=`
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
```

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

### Assigning to an index

```ml
arr = [1, 2, 3]
arr[1] = 99
print arr // [1, 99, 3]
```

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


### Inline functions (`inline`)

You can mark **top-level functions** and **struct methods** as `inline`:

```ml
function inline clamp01(x)
  if x < 0 then return 0 end if
  if x > 1 then return 1 end if
  return x
end function
```

When you write a **direct** call like `clamp01(v)`, the compiler expands the callee body at the call site (no call/ret overhead).

Current behavior / limits:
- Only supported for **top-level functions** and **struct methods** (`function inline ...`).
- Only **direct calls** are inlined. Calls through a variable (e.g. `f = clamp01; f(v)`) are not inlined.
- Inline bodies must not capture variables (no closures / env hops / boxed captures).
- Inline bodies must not contain nested `function` definitions.
- Inline recursion / mutual recursion is rejected.
- `return <expr>` returns from the *inline call* (the call yields the return value).
- The inline expansion uses an isolated scope so it won't clobber caller locals.


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

Native compiler:
- Direct **and** indirect calls are supported (functions are values; you can store/pass/call them).


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
- The entrypoint call happens **after** top-level statements have executed (so you can keep top-level setup code).


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




Native compiler:
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

Native compiler backend: supported.

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
**Inline methods:** You can also write `function inline name(...)` inside a `struct` to force full body inlining for direct calls (see [9. Functions](#9-functions)).


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

Native notes:

- Struct constructors are calls: `Person(arg0, arg1, ...)` (argument count must match the field count).
- Field reads/writes are supported: `p.name`, `p.age = ...`.
- The native backend currently has no exceptions: type errors typically evaluate to `void` (reads) or become no-ops (writes).

---

## 11. enum

Native compiler backend: supported (ordinal enums + optional explicit values).

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


### namespace (top-level only)

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
- Imported modules must be **declaration-only** (libraries). At top-level (and inside `namespace` blocks) only declarations are allowed:
  - `package`, `import`, `namespace`
  - `function`, `struct`, `enum`
  - `extern function` / `extern struct`
  - global `const` and global assignments **only with `constexpr` initializers** (side-effect free; literals, simple arithmetic/bitwise ops, references to other `const`s/enum values, …)
  - enum variants with explicit `= <value>` must also be `constexpr`
  Anything that would execute code at import-time (e.g. `print`, function calls, `if/while/for`, non-constexpr initializers) is rejected.
- Import cycles are detected and rejected.
- `import ... as <alias>` is supported: it creates a compile-time alias for the imported module’s `package` name, so you can write e.g. `g.add()` instead of `geom.vec.add()`. The imported file must declare `package ...`.
- Alias names must be valid identifiers and must not be reserved (`try`, `error`).
- If an imported file declares `package foo.bar`, its location must match that package when resolved via a stable root (importing directory or `-I` root): the file should be found as `foo/bar.ml` under that root. (Absolute-path imports skip this check.)


### package (top-level only)

A file can declare its *package name* once at the very top:

```ml
package foo.bar
```

This is used by the native compiler’s import system (for `import ... as <alias>` and for verifying that a module’s file path matches its declared package when resolved via an import root).

Notes:
- `package` must be the **first** statement in the file (before `import`, `namespace`, `function`, etc.).
- It is compile-time only (no runtime effect).

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

Common modules (subset; evolves over time):

- **std.core**: small helpers (e.g. `min/max/clamp`, …)
- **std.assert**: assertions for tests and small programs
- **std.result**: `Option` and `Result` (methods like `isOk/isErr`, `isSome/isNone`, `map`, `unwrapOr`, `unwrapOrElse`, …)
- **std.string**: string utilities (`trim`, `split`, `join`, `replaceAll`, …)
- **std.bytes**: bytes helpers (`concat`, `equals`, `ctEquals`, …)
- **std.encoding.hex**, **std.encoding.base64**: encoding helpers
- **std.array**, **std.sort**, **std.random**, **std.math**, **std.fmt**
- **std.time**: monotonic `ticks()` / `sleep(ms)`, Win32 wall-clock wrappers `std.time.win32.GetLocalTime()` / `GetSystemTime()` (returns `SystemTime`), plus `Date/Time/DateTime` helpers
- **std.fs**: file system & file I/O (see [13.3](#133-bytes--encoding--file-io))
- **std.net**: TCP/UDP networking
- **std.ds.\***: stack/queue/hashmap/set

Stdlib APIs that can fail (I/O, networking, parsing, …) typically return a `Result` instead of throwing exceptions:

```ml
import std.fs as fs

w = fs.writeAllText("demo.txt", "hello
")
if not w.isOk() then
  print "write failed"
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

Native compiler behavior (current): unsupported types return `0` (no exceptions yet).

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

Native compiler behavior (current): invalid inputs return `void` (no exceptions yet).

Not allowed:
- `toNumber(true/false)`
- `toNumber(void)`
- non-parsable strings

#### typeof(x)
Returns a string describing the type of `x`.

Type strings: `int`, `float`, `bool`, `string`, `array`, `bytes`, `void`, `function`, `enum`, `struct`, `error`, `unknown`.  

```ml
print typeof(123)      // "int"
print typeof("hi")     // "string"
print typeof([1,2,3])  // "array"

// error values
err = error(2, "bad input")
print typeof(err) // "error"
```

#### error(code, message) -> error value

Constructs an `error` value (fields: `.code` and `.message`).  
See **Chapter 15** for full semantics (automatic propagation and `try(...)`).

#### try(expr) -> value

Stops automatic error propagation for the given expression and returns either the normal value or the `error` value.  
See **Chapter 15** for full details.

### 13.3 Bytes / Encoding / File I/O

Native compiler backend: **bytes() / byteBuffer() supported**. File I/O is provided via the stdlib module `std.fs` (see “File I/O” below).

#### bytes(...) / byteBuffer(...)
Creates a mutable `bytes` buffer.

Native compiler backend (current):
- `bytes(size[, fill])` and `byteBuffer(size[, fill])` allocate `size` bytes, filled with `fill` (default 0).

- `bytes(...)` supports additional forms: `bytes()` (empty), `bytes(string)` (UTF-8), `bytes(list[int])`, and `bytes(bytes)` (copy).
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

- Accepts `bytes()` (and legacy `list[int]`).
- Honors `encoding` using Python's codec names (e.g. `"utf-8"`, `"latin-1"`, ...).

Native compiler backend (current):
- Expects a `bytes` object.
- Treats the payload as UTF-8.
- If `encoding` is provided it must be a string, but the value is currently ignored (UTF-8 only).

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
Native compiler behavior (current): invalid input returns `void` (no exceptions yet).

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

Rules (native compiler backend, current):
- `offset` and `length` must be integers.
- `offset` may be negative (like indexing): `offset < 0` means `offset += len(bytes)`.
- Bounds are **strict** (no clamping): requires `0 <= offset <= len(bytes)` and `0 <= length` and `offset + length <= len(bytes)`.
- On any type/bounds error, returns `void`.


```ml
b = fromHex("00 11 22 33 44 55")
print hex(slice(b, 2, 3))   // "223344"
print hex(slice(b, -2, 2))  // "4455"
```

#### File I/O
The native runtime currently does not expose low-level file-handle builtins.

File I/O is provided by the **standard library** module `std.fs`, with convenience helpers like:
- `writeAllText`, `readAllText`, `readAllLines`, `appendAllText`
- `writeAllBytes`, `readAllBytes`
- `exists`, `delete`, `fileSize`, `copyFile`, `moveFile`

Most functions return a `Result` (`.isOk()/.isErr()` and `.value` on success).
A few return plain `bool` (e.g. `exists`, `delete`).

Example:

```ml
import std.fs as fs
import std.string as s

p = "hello.txt"
chk = fs.writeAllText(p, "hello\nworld\n")
if chk.isOk() then
  r = fs.readAllText(p)
  if r.isOk() and s.startsWith(r.value, "hello") then
    print "ok"
  end if
end if
```

### 13.4 Heap / GC debug

Native compiler only (for debugging / validating the runtime).

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

Supported ABI types (inputs):
- `int` / `i64` / `u64` / `i32` / `u32`
- `bool` (accepts `bool` or `int` at the call site)
- `ptr` (accepts `ptr`, `int`, or `void`; `void` becomes `NULL`)
- `cstr` (MiniLang `string` → `char*` UTF-8; `void` becomes `NULL`)
- `wstr` (MiniLang `string` → `wchar_t*` UTF-16LE; `void` becomes `NULL`)
- `bytes` (MiniLang `bytes` → pointer to the payload; `void` becomes `NULL`)

Supported return types:
- `void`
- `int` / `i64` / `u64` / `i32` / `u32` / `ptr`
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

### extern struct (experimental)

The frontend also accepts `extern struct` declarations to describe an ABI layout:

```ml
extern struct POINT
  x as i32
  y as i32
end struct
```

This is intended for future interop features (e.g. passing/receiving structured data via pointers / out-params).  
Current status: declarations are parsed and validated, but full marshaling support is still WIP.

### out parameters (experimental)

You can mark trailing parameters as `out`:

```ml
extern function GetCursorPos(out p as POINT) from "user32.dll" returns bool
```

Rules:
- `out` parameters must appear **at the end** of the parameter list (so they can be implicitly handled at call sites).
- Current status: the compiler validates `out` declarations, but code generation is still WIP.

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
- `const <ident> = <expr>` (native compiler; top-level/namespace requires `constexpr`)
- `<lvalue> = <expr>`
  - `<ident> = ...`
  - `<expr>.<field> = ...`
  - `<expr>[<index>] = ...` (multiline indexing allowed)
- `function name(a,b) ... end function` (multiline params allowed, trailing comma optional)
- (native) optional entrypoint: `function main(args) ... end function`
- `return` / `return <expr>` / `return;` (and bare `return` directly before `end/else/case` in inline blocks)
- `global x, y, z` (inside functions; native compiler only; trailing comma optional; names may be qualified like `foo.bar.x`)
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
- `namespace Name ... end namespace` (top-level or nested in namespaces; declarations only; native compiler)
- `package foo.bar` (top-level only; must be the first statement; native compiler)
- `import "relative/or/absolute/path.ml" [as <alias>]` (top-level only; native compiler)
- `import foo.bar [as <alias>]` (module-style import; resolves to `foo/bar.ml`; native compiler)
- `extern struct Name ... end struct` (native compiler; experimental)
- `extern function Name(...) from "dll" ...`

### Expressions
- literals: number, string, `true/false`, `[ ... ]` (multiline + trailing comma allowed)
- variable: `name`
- call: `f(a,b)` (multiline args + trailing comma allowed)
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

### 17.3 Struct + switch (works in native compiler)

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

The Windows x64 native backend generates a PE32+ console executable.

What works:
- core types: int, float, bool, string, array, bytes, void
- control flow: `if/else`, `while`, `loop ... while ... end loop`, `for ... to`, `for each ... in`, `switch/case`, `break`/`break n`, `continue`
- first-class functions: user functions and many builtins are values; direct **and** indirect calls are supported
- nested functions + closures (captured vars are boxed and stored in an environment frame)
- `main(args)` entrypoint (argv[1..] as `array<string>`, `return int` -> process exit code)
- `global` declarations inside functions (required for accessing globals from a function; resolves to package/namespace-qualified globals; missing globals are auto-created as `void`)
- `struct` (constructors + field read/write)
- `enum` (values like `Color.Red`, comparisons, printing, `switch`)
- `namespace` blocks (compile-time name qualification)
- `package` + `import` (compile-time multi-file merge; imported files must be declaration-only)
- `const` (write-once bindings; top-level/namespace consts are evaluated at compile time)
- `enum` explicit values (constexpr) + auto-increment for missing int values
- `extern function` via the PE import table (IAT)
- builtins / special forms: `len`, `input`, `toNumber`, `typeof`, `error`, `try`, `bytes`/`byteBuffer`, `decode`, `decodeZ`, `decode16Z`, `hex`, `fromHex`, `slice`,
  plus debug helpers: `heap_count`, `heap_bytes_used`, `heap_bytes_committed`, `heap_bytes_reserved`, `heap_free_bytes`, `heap_free_blocks`, `gc_collect`

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
- **Peephole optimization** in the asm emitter (local rewrites only; no control-flow changes).
- **Helper pruning**: only referenced `fn_*` runtime helpers are emitted.

GC flags:
- `--gc-limit <size>` overrides the periodic GC threshold (default: `1m` in the current backend).
- `--no-gc-periodic` disables periodic GC triggering (GC runs only on allocation failure / OOM path).
