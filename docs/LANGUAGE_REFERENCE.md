# MiniLang language reference

This reference covers language syntax, runtime behavior, standard-library basics,
native interop and examples. For installation, compiler commands and current
release information, see the [repository README](../README.md).
For classes, inheritance, interfaces and overrides, see the
[OOP guide](OOP.md).

Run the example commands from the repository root unless a section says otherwise.

## Contents

- [Comments](#comments) · [Types and literals](#types--literals) · [Variables and assignments](#variables--assignments)
- [Operators](#operators--expressions) · [Arrays](#arrays) · [Control flow](#control-flow)
- [Functions](#functions) · [Structs](#struct) · [Enums](#enum)
- [Modules and imports](#modules-namespace--import) · [Standard library and builtins](#standard-library--builtins)
- [Native interop](#extern) · [Error handling](#error-handling-error--try)
- [Syntax summary](#syntax-reference-short) · [Examples](#examples)

## Comments

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

### Declaration comments and MiniDoc

`///` documents the declaration immediately following it. MiniDoc reads these
comments from the original source while both compilers omit them from the
executable AST, so documentation has no runtime cost.

```ml
/// Loads a user by identifier.
/// @param id Stable user identifier.
/// @returns The matching user.
function loadUser(id as int) returns User
  // ...
end function
```

Use `//!` for file-level documentation. `/** ... */` and `/*! ... */` are the
block forms for declaration and file documentation. MiniDoc also accepts a
legacy `//` or `/* ... */` block directly before a declaration, but `///` is
preferred because its intent is explicit. Supported structured tags include
`@param`, `@returns`, `@error`, `@deprecated`, `@see`, `@since`, `@example`,
`@group`, and `@internal`.

The repository contains a ready-to-use `minidoc-std.toml` configuration. With
a sibling MiniDoc checkout, regenerate the standard-library API reference:

```powershell
..\MiniDoc\build\minidoc.exe --config .\minidoc-std.toml
```

Generated HTML and Markdown are written below `docs/api/std`. The checked-in
configuration disables generation timestamps, so unchanged standard-library
sources and revisions produce byte-identical trees on independent runs.

### Newlines & statement separators

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

## Types & Literals

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

See [bytes and file I/O](#bytes--encoding--file-io) for details and file / encoding examples.

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

## Variables & Assignments

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

## Operators & Expressions

### Arithmetic

| Operator | Meaning |
|---------:|---------|
| `+` | add / string concat / array concat / bytes concat |
| `-` | subtraction |
| `*` | multiplication |
| `/` | division |
| `%` | modulo |
| `div` | integer floor division |

Important:
- `-`, `*`, `/`, `%` work only with numbers (not `bool`).
- `div` requires two `int` operands and always returns an `int`. It floors
  negative quotients (`-7 div 2 == -4`) and is therefore safe to use directly
  as an array index. Use `std.math.toIntExact`, `floorInt`, `ceilInt`,
  `truncInt`, or `roundInt` when converting a `float` explicitly.
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
11. unary: `not`, `+x`, `-x`, `~x`

Parentheses override precedence.

Newlines may appear after operators (see [newlines and statement separators](#newlines--statement-separators)).

### User-defined operators

Structs may overload MiniLang's existing operator symbols. Declarations are
static functions: every operand is explicit, there is no implicit `this`, and
`inline` requests the same bounded expansion as an inline function.

```ml
struct Vector2
  x as int,
  y as int,

  operator inline +(left as Vector2, right as Vector2) returns Vector2
    return Vector2(left.x + right.x, left.y + right.y)
  end operator

  operator ==(left as Vector2, right as Vector2) returns bool
    return left.x == right.x and left.y == right.y
  end operator
end struct

sum = Vector2(1, 2) + Vector2(3, 4)
sum += Vector2(5, 6)
```

The overloadable binary symbols are `+ - * / % == != < <= > >= & | ^ << >>`.
The overloadable unary symbols are `+ - not ~`. Multiple signatures may be
declared for one symbol, for example `Vector2 + Vector2` and `Vector2 + int`.
Comparison overloads and unary `not` must return `bool`.

Resolution is compile-time-only and exact:

- every operand parameter and the result must have a required, non-optional
  declared type, and the result cannot be `void`;
- the first operand must be the struct that contains the declaration;
- aliases such as `integer` and `int` denote the same type, but no implicit
  numeric, string or object conversion is attempted;
- a missing exact signature or two matching canonical signatures is a compile
  error whenever the owning struct type is statically known;
- without an applicable struct declaration, the existing built-in operator
  behavior is unchanged. Built-in unary `+value` is the numeric identity.

Variable compound assignments `+= -= *= /= %= &= |= ^= <<= >>=` use the
corresponding binary overload and assign its result. Member and index compound
assignments are intentionally not accepted, so a side-effecting receiver or
index can never be evaluated twice implicitly. Write the read, operation and
assignment explicitly when needed.

`and` and `or` remain fixed short-circuit control-flow operators. Assignment,
`is`, `is not`, `as`, `??` and member/index access cannot be overloaded, and
programs cannot add new symbols or precedence levels. These limits keep parsing,
evaluation order and generated code deterministic across both compilers.

---

## Arrays

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

Index must be an int (not bool). A statically known non-int index, or a
constant index outside a statically known array length, is a compile error.
Dynamic cases retain the catchable runtime check.

Out of bounds indexing (or indexing a non-indexable value) raises a runtime `error`
that you can catch with `try(...)`.

### Assigning to an index

```ml
arr = [1, 2, 3]
arr[1] = 99
arr[1] = void // clear a normal array slot
print arr // [1, 99, 3]
```

Invalid index assignment (wrong target type, non-int index, out of bounds, invalid byte value)
raises a runtime `error` (catchable via `try(...)`).

`std.array.getOr`, `getOption`, `setIfPresent`, and `getOrError` provide safe
access without hand-written bounds checks. `getOption` distinguishes a missing
slot from a valid slot containing `void`. Byte buffers remain strict and do not
accept `void` elements.

### Concatenation

```ml
x = [1,2]
y = [3,4]
z = x + y
print z // [1,2,3,4]
```

---

## Control Flow

### if / else if / else

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

### while

```ml
while <cond>
  ...
end while
```

### loop ... while ... end loop (do-while)
Body executes at least once.

```ml
loop
  ...
while <cond>
end loop
```

### for ... to

```ml
for <var> = <start> to <end>
  ...
end for
```

- `start` and `end` must be int
- runs automatically up or down (step +1 or -1)

### for each ... in
Iterates over arrays, strings, or bytes.

```ml
for each <var> in <iterable>
  ...
end for
```

### break / continue

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

### switch / case

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

## Functions

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

### Modern language extensions

MiniLang remains dynamically typed, but declarations may add runtime-checked
contracts. A failed parameter, return, annotated initializer or typed
struct-constructor field
contract produces error `1308` and propagates like every other MiniLang error;
wrap an operation in `try(...)` when the error is expected.

```ml
function sum(first as int, second as int = 0, rest...) returns int
  total = first + second
  for each value in rest
    total = total + value
  end for
  return total
end function

maybeName as string? = void
print sum(second = 2, first = 1)
print sum(1, 2, 3, 4)
```

The optional marker follows the type (`Person?`). `void` is accepted only by
an optional contract. Default and named arguments are available for directly
resolved MiniLang functions and methods; struct constructors accept field names.
A final `name...` parameter receives surplus positional arguments as an array.
Dynamic callable values intentionally do not accept named arguments because
their runtime representation has no parameter-name metadata.

Non-optional annotations also feed the optimizer after their entry guard has
succeeded. Proven integer, float, boolean, string, array, bytes and concrete
struct values can therefore use the same specialized machine-code paths as
locally inferred values. A proven primitive return expression also omits its
otherwise redundant return-contract check; entry guards remain the dynamic
call boundary.

Expression lambdas use the existing closure implementation and may capture
lexical variables:

```ml
factor = 4
multiply = function(value as int) returns int => value * factor
print multiply(3)
```

Lambda calls are positional. Lambda parameters support type annotations, but
defaults and variadic tails are intentionally reserved for declared functions,
whose signatures the compiler can resolve at the call site. Small expression
lambdas and fully typed expression functions are automatically considered for
the same bounded inliner as explicit `inline` declarations; every function
still retains its normal callable body when the budget or eligibility check
requires a fallback.

Optional access and fallback expressions avoid manual `void` checks. `?.`
short-circuits both field access and method calls, and `??` evaluates its right
side only when the left side is `void`:

```ml
label = user?.profile?.displayName ?? "anonymous"
```

`match` provides deterministic value, list and inclusive-range matching. It is
the pattern-oriented spelling of `switch`; cases do not fall through and the
current version deliberately has no destructuring or guard clauses.

```ml
match status
  case 0
    print "idle"
  end case
  case 1 to 3
    print "busy"
  end case
  case default
    print "unknown"
  end case
end match
```

Iterator functions collect yielded values into an array with geometric buffer
growth. Prefixing the declaration with `lazy` instead returns a zero-argument
pull closure: each call produces one value and exhaustion returns `void`.
`for each` accepts both eager arrays and these pull closures, so a lazy iterator
does not materialize an intermediate collection. In both forms, `returns T` is
the yielded-value contract and explicit `return` statements are rejected.
Lazy state machines currently support `yield` in straight-line code, `if`,
`while`, `do while`, `for` and `for each`; `yield` inside `match`/`switch` or
`synchronized`, `defer`, and multi-level `break` are rejected at compile time.

```ml
iterator function numbers(limit as int) returns int
  for i = 0 to limit
    yield i
  end for
end function

lazy iterator function largeNumbers(limit as int) returns int
  for i = 0 to limit
    yield i
  end for
end function
```

For a directly resolved variadic call, the compiler proves whether the tail can
escape the callee. Read-only, call-scoped tails use an immutable stack array
view; returned, captured, mutated or forwarded tails keep the normal managed
heap array. This optimization does not change source semantics.

Interfaces declare method contracts. `implements` checks every required
instance method, including its parameter, variadic, optional and return types.
Objects implementing an interface can be tested with `is Interface` and held in
variables typed as that interface. Interfaces have no fields or default methods.

```ml
interface Named
  function name() returns string
end interface

struct Person implements Named
  value as string
  function name() returns string
    return this.value
  end function
end struct
```

The [classes and interfaces guide](OOP.md) has complete examples and
constructor, override, and visibility rules.

Classes provide single inheritance with `extends`. A subclass inherits fields,
field defaults, methods and implemented interfaces. An overriding method must
use `override function` and keep the inherited signature. Inside an override,
`super.method(...)` calls the nearest inherited implementation. Calls through a
base-typed variable dispatch to the concrete object's override; `is Base` also
recognizes descendants. Classes share the existing struct object representation,
so `typeof(instance)` remains `"struct"`. `super` calls accept positional and
named arguments, including inherited defaults.

`function init(...)` defines the constructor parameters. Every class field must
have a default when `init` is present; the constructor fills the fields, then
calls the most-derived `init` method. An inherited `init` is used when no
override exists, and an override can call `super.init(...)`. Initializers return
`void`. Without `init`, the constructor accepts only public fields, in inherited
field order followed by own fields. Nonpublic fields must have defaults. Direct
calls support named arguments and defaults; a class value accepts positional
arguments in the constructor's supported arity range. Omitted positional
arguments require trailing defaults.

`abstract class` cannot be constructed and may declare signature-only
`abstract function` methods. A concrete subclass must implement all of them.
`final class` cannot be extended; `final function` cannot be overridden.
Members are `public` by default. Prefix a field or method with `private` to
expose it only in its declaring class, or `protected` to expose it there and in
subclasses. Overrides preserve visibility. Access checks cover `this`, stable
instance aliases, typed parameters and qualified static calls. Interfaces
require public methods and may inherit other interfaces with `extends`.

```ml
interface Speakable
  function speak() returns string
end interface

class Animal
  name as string
  function speak() returns string
    return this.name
  end function
end class

class Dog extends Animal implements Speakable
  override function speak() returns string
    return super.speak() + "!"
  end function
end class

dog = Dog(name = "Bello")
print dog.speak()          // Bello!
print dog is Animal       // true
print dog is Speakable    // true
```

Async functions use one compiler-managed four-worker `ThreadPool` per program
and are available on Windows and Linux. Calling one submits a job and returns a
`ThreadPoolJob` immediately instead of creating a native thread per call.
`await` accepts pool jobs, ordinary `Thread` handles and non-thread values;
`select` accepts jobs and threads and returns the zero-based index of the first
completed item (`-1` for an empty list). Async declarations are currently
limited to module or namespace scope; async struct methods and combined
`async iterator` declarations are rejected. Workers retain MiniLang's shared
GC heap and private-stack model. A retained async handle owns native
synchronization resources; call `Dispose()` after its result is no longer
needed, as with an explicitly submitted `ThreadPoolJob`.

```ml
async function fetch(id as int) returns string
  return "item-" + id
end function

first = fetch(1)
second = fetch(id = 2)
winner = select(first, second)
print await first
print await second
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
optimization request, not a guarantee. Small fully typed expression functions
and generated expression lambdas are also eligible automatically; explicit
`inline` remains useful for larger hand-selected bodies.

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


### Typed inline x64 assembly

`asm x64(...) returns Type ... end asm` embeds typed symbolic x64 instructions
at the current expression. It accepts every MiniLang value category as an
operand or result. Direct byte-buffer writes require `asm unsafe x64` and
caller-side bounds checks. See [syntax, supported instructions, and GC rules](INLINE_ASM.md).

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

### Native threads & synchronization

`Thread(function[, logicalId])` creates a real native Windows/Linux thread object without
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

- `Start()` or `Start(value)` atomically claims and starts a newly created
  thread once and returns `bool`; concurrent calls on the same object can
  produce only one worker. Its argument count must match the entry function's
  zero/one arity.
- `Stop()` atomically requests cooperative cancellation and returns whether an
  alive thread changed to `StopRequested`, including the short startup-publication window.
- `Join()` waits indefinitely; `Join(timeoutMs)` waits at most the given number
  of milliseconds. Explicit timeouts must be integers in the portable range
  `0..2147483647`; invalid values produce a catchable `error`. Both return
  `true` only when the thread terminated. A Join
  racing Start waits for native-handle publication instead of failing early;
  concurrent joins on one object share a single native join operation safely.
- `Status()` returns `Created`, `Running`, `StopRequested`, `Completed`,
  `Stopped`, or `Failed`.
- `IsAlive()` is true for `Running` and `StopRequested`.
- `Id()` returns the native thread id (`0` before a successful start).
- `LogicalId()` returns the user-defined logical id. `SetLogicalId(value)` can
  replace it while the thread is still in `Created`; the constructor's optional
  second argument sets the initial value. Logical ids do not change the native
  operating-system thread id. The update and Start's state claim are atomic
  with respect to one another.
- `Result()` returns the worker's result (`void` until it publishes one). Use
  `try(t.Result())` when a failed worker returned an `error` value.
- `Close()` closes the native handle after termination. Concurrent calls are
  safe and exactly one can claim a live handle; cleanup also verifies that the
  native worker has fully exited before clearing its registered roots. A `Join`
  that already acquired the handle remains valid while `Close` waits for it;
  later joins observe the close claim and return `false`. Blocking cleanup is
  excluded from stop-the-world GC participation, preventing a terminal worker's
  TLAB-retirement safepoint from deadlocking with its closer. Status metadata
  remains valid as long as the `Thread` object is reachable. `Close()` also
  accepts a never-started `Created` thread: it atomically changes it to
  `Stopped`, clears its payload and prevents a later `Start()` or
  `SetLogicalId()`. A second close returns `false`.
- Thread control records are managed heap objects. Their registry is weak:
  unreachable never-started or fully terminated threads are reclaimed by GC,
  including cycles, logical ids and unclaimed results. GC also closes abandoned
  terminated native handles. Running workers remain rooted until their native
  epilogue has finished, even without a language-level reference. Explicit
  `Join()`/`Close()` is still recommended for timely native resource release.

Worker helpers:

- `threadStopRequested()` reports whether the current worker was asked to stop
  (and returns `false` on the main thread).
- `threadLogicalId()` returns the logical id of the current worker (`void` on
  the main thread).
- `threadSleep(milliseconds)` calls the native sleep primitive for an integer
  in `0..2147483647`; invalid values produce a catchable `error` instead of
  being truncated by a target ABI.

`Stop()` is safe and cooperative: the compiler inserts cancellation checks at
statement boundaries. It never uses asynchronous thread termination. Long
native calls may finish before cancellation is observed, but a thread in a
blocking native call does not prevent another thread from collecting garbage.

All threads allocate into one process-wide, non-moving managed heap. Each OS
thread owns only its native stack, a private GC root chain, temporary root slots
and a 64 KiB thread-local allocation buffer (TLAB) carved from that shared heap.
Objects up to 256 bytes including their GC header use a lock-free cursor fast
path; larger objects, TLAB refills, heap growth and free-list access use the
serialized central allocator. A TLAB is only an allocation reservation, never a
private object heap, so references can be published between threads unchanged.

Collection is cooperative stop-the-world: generated function and loop
safepoints park managed threads, while threads inside known native calls publish
a stable root chain. The collector traces globals, active thread contexts and
reachable managed objects (including retained `Thread` results and logical ids),
retires active TLAB ownership, and then sweeps the ordinary shared heap block
chain. The registry does not keep inactive threads alive indefinitely. A
terminating worker returns its unused TLAB tail to the central free list.

When collections arrive back-to-back, a worker that observes the next request
while resuming reacquires the coordination monitor and republishes `Parked`
before waiting again. This keeps the collector's context scan and the worker's
wait state consistent even during sustained allocation churn at full hardware
thread concurrency.

Each thread context also retains its four most recent allocation results as
handoff roots. This closes the short lifetime gap while nested object graphs
are being assembled, before a precise stack or global root owns them. These
slots are GC metadata; they are not a private managed heap. Once values have
precise published roots, generated GC safepoints, explicit `gc_collect()` and
user native-call boundaries clear stale handoffs; worker exit clears scratch
roots as well. Runtime allocation helpers keep their handoffs while assembling
objects. An idle thread therefore does not retain an otherwise dead graph just
because it was among its last allocations.

Consequently, an object created by a worker remains valid after that worker
terminates whenever it is still reachable from a global, another live object,
a thread result or another registered root. `heap_bytes_used()`,
`heap_bytes_committed()` and `heap_bytes_reserved()` report the same global heap
from every thread. `Thread.Close()` releases the native handle and clears roots
owned by the thread object; it does not invalidate objects published elsewhere.

Use a synchronized function when a whole critical section must be serialized:

```ml
import std.threading as threading

function synchronized updateSharedState()
  global jobsDone
  jobsDone = jobsDone + 1
end function

guard = threading.Lock.new()
synchronized(guard)
  // Only code using this guard is serialized.
  updateOneSharedObject()
end synchronized
```

Synchronized variables and synchronized functions share the recursive
process-wide monitor for backward compatibility. `synchronized(lock)` instead
uses the supplied `std.threading.Lock`, evaluates that expression exactly once
and releases it on fall-through, `return` and propagated `error` exits. A failed
acquire propagates error `1101`; `break` and `continue` cannot leave this block.
Independent locks allow unrelated critical sections to proceed concurrently.

Managed object identity is shared across threads; no copy is made when a
reference is published. Concurrent writes to the same object, array slot or
unsynchronized global are data races. Use the appropriate synchronized form or
the primitives/collections in the next section to define the required critical
section. Console and other process-wide I/O should also be serialized when
multiple workers can use it.

For closed programs that never reference `Thread`, the compiler selects a
single-thread fast path. Generated hot code then omits cancellation and GC
safepoint polls, thread-local root/debug handoffs, managed/native transition
wrappers and allocator/world-lock traffic. Programs that can construct a
`Thread` retain the fully synchronized shared-heap runtime above; after all
workers have exited, uncontended allocation also bypasses the heap lock again.
This selection is automatic and does not change source semantics.

### Thread-safe standard-library types

`std.threading` exposes native process-wide synchronization objects:

- `Lock.new()` creates a native recursive mutex on either target. Methods are `acquire()`,
  `tryAcquire()`, `acquireFor(timeoutMs)`, `release()`, `isClosed()` and
  `close()`. `Acquire`, `TryAcquire`, `AcquireFor` and `Release` aliases are
  also available.
- `Semaphore.new(initialCount, maximumCount)` provides `acquire()`,
  `tryAcquire()`, `acquireFor(timeoutMs)`, `release()`,
  `releaseMany(count)`, `isClosed()` and `close()`.
- `Event.new(manualReset, initialState)` provides `wait()`, `tryWait()`,
  `waitFor(timeoutMs)`, `set()`, `reset()`, `isClosed()` and `close()`.

All timed waits accept integer milliseconds in `0..2147483647`; invalid values
return `false`, and an ordinary timeout is also reported as `false`.
`Semaphore.new` uses the same upper bound for its maximum count. On Windows, a lock
acquired after `WAIT_ABANDONED` is treated as successfully acquired and must be
released.

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

### Managed thread pools

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
- Pending jobs use a geometrically growing circular buffer, keeping total queue
  growth linear even when producers temporarily outrun every worker.
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

### Tasks, cancellation and bounded channels

`std.concurrent.task` layers `Future` values over an existing thread pool.
`run(pool, callback, data)` schedules a conventional callback;
`runCancellable` calls `callback(data, token)`. Futures provide `Wait`,
`WaitFor`, `IsDone`, `Cancel`, `Dispose` plus lowercase `status()` and
`result()`. `whenAll` preserves input order, while `whenAny` and `whenAnyFor`
return the first completed index.

`std.concurrent.cancellation` provides `CancellationTokenSource` and its
read-only `CancellationToken`. Cancellation is idempotent and cooperative:
`IsCancellationRequested`, `Wait`/`WaitFor` and `Check` let running code observe
the request; `Check` returns error `1650`. Cancelling a queued future removes
the job directly, whereas running work must inspect its token.

`std.concurrent.channel.Channel.new(capacity)` creates a bounded,
multi-producer/multi-consumer FIFO with backpressure. `Send`/`Receive` wait,
`SendFor`/`ReceiveFor` use millisecond timeouts and `TrySend`/`TryReceive` do not
block. A receive returns `ChannelReceive(received, value)`, so a valid `void`
message remains distinguishable from a closed and drained channel. `close()`
seals the writer side; queued values remain readable. Call `Dispose` only after
blocked users have returned and the channel has drained. Timed channel and
`whenAnyFor` waits use monotonic elapsed time; a deadline is not a guarantee
of exact wake-up time under OS scheduling.

```ml
import std.concurrent.channel as channels
import std.concurrent.task as tasks
import std.concurrent.thread_pool as threadPool

function work(value, token)
  if token.IsCancellationRequested() then return token.Check() end if
  return value * 2
end function

pool = threadPool.ThreadPool.withQueueCapacity(4, 128)
future = tasks.runCancellable(pool, work, 21)
future.Wait()
print future.result() // 42
future.Dispose()

channel = channels.Channel.new(64)
channel.Send("ready")
item = channel.Receive()
if item.received then print item.value end if
channel.close()
channel.Dispose()

pool.Shutdown()
pool.AwaitTermination()
pool.Dispose()
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
- `args` contains `argv[1..]` (arguments after the executable name). Windows
  uses `CommandLineToArgvW` quoting; Linux consumes the kernel-provided `argv`.
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

## struct

```ml
struct Person
  name
  age as int = 0
end struct

p = Person("Alice", 30)
print p.name
p.age = p.age + 1
print p.age
```

### Methods (OOP-style)
**Inline methods:** You can also write `function inline name(...)` inside a
`struct` to request the same bounded direct-call expansion described in
[Functions](#functions).


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

- Struct constructors are calls: `Person(arg0, arg1, ...)`. Fields may declare
  default expressions with `field [as Type] = expression`; omitted trailing or
  named arguments use those defaults. Named arguments use `name = value`.
- Field reads/writes are supported: `p.name`, `p.age = ...`.
- Statically known constructor, method, and field mistakes are diagnosed during
  compilation; dynamic invalid operations follow the runtime's normal
  `error`/`void` behavior.

---

## enum

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

## Modules, namespace & import

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

## Standard Library & Builtins

### Stdlib modules (std.*)

MiniLang ships with a source-based standard library in `std/`. You import it the same way you import your own modules:

```ml
import std.string as s
import std.time as t
import std.fs as fs
```

The stdlib is compiled together with your program (there is no separate link
step). Its public modules work on both supported targets. `std.fs`, `std.net`,
`std.time`, `std.threading` and the shared-value helpers select Win32 or
glibc/POSIX implementations at compile time while keeping one MiniLang API.
Cryptography uses Windows CNG on Windows and OpenSSL 3 (`libcrypto.so.3`) on
Linux. TLS uses Schannel on Windows and OpenSSL 3 (`libssl.so.3`) on Linux.
Linux images that use only libc-backed modules need no dependency beyond the
normal x64 glibc runtime; importing `std.crypto` or `std.tls` additionally
requires the OpenSSL 3 runtime package.

The current library contains 53 source modules with matching source content
in both compiler repositories:

- **Core:** `std.core`, `std.assert`, `std.test`, `std.array`, `std.sort`,
  `std.math`, `std.random`, `std.fmt`
- **Text and bytes:** `std.string`, `std.string_builder`, `std.bytes`,
  `std.encoding.hex`, `std.encoding.base64`, `std.compress`,
  `std.compress.lz4`, `std.compress.rle`
- **System APIs:** `std.platform`, `std.path`, `std.process`, `std.console`,
  `std.time`, `std.fs`, `std.io.file`, `std.net`, `std.uuid`, `std.tls`,
  `std.video` and `std.audio`
- **Collections:** `std.ds.list`, `std.ds.stack`, `std.ds.queue`,
  `std.ds.hashmap`, `std.ds.set`
- **Concurrency:** `std.threading`, `std.concurrent.thread_pool`,
  `std.concurrent.task`, `std.concurrent.cancellation`,
  `std.concurrent.channel`, `std.ds.concurrent_list`,
  `std.ds.concurrent_hashmap`
- **Native primitives:** `std.cpu`, `std.checksum.crc32c`,
  `std.checksum.crc32`, `std.crypto`, `std.crypto.aes_gcm`,
  `std.crypto._cng`, `std.crypto._openssl`, `std.tls._schannel` and
  `std.tls._openssl` (internal platform backends)
- **Compatibility helpers:** `std.result` provides `Option` and `Result`;
  `std.concurrent.shared_value` provides a legacy unmanaged snapshot codec;
  `std._linux_fs` is the internal POSIX filesystem backend.

**Random numbers**

`autoSeeded()` is available in the source and native packages.

`std.random.seeded(seed)` creates a reproducible xorshift32 generator.
`std.random.autoSeeded()` creates a new independent generator using four bytes
from `std.crypto.secureRandom` (Windows CNG / Linux OpenSSL 3). A zero seed is
rejected and sampled again because xorshift32 cannot leave state zero.

```ml
import std.random as random

function main(args)
  rng = try(random.autoSeeded())
  if typeof(rng) == "error" then
    print rng.message
    return 1
  end if
  print rng.rangeInt(1, 7) // 1 through 6
  print rng.nextFloat()   // [0, 1)
  return 0
end function
```

Provider failures propagate as errors; there is no clock-based or fixed-seed
fallback. Automatic seeding does **not** make xorshift32 cryptographically
secure: use `std.crypto.secureRandom(length)` directly for secrets.
Seeds may collide; neither seeds nor generated values are unique identifiers.
Initialize once and reuse the generator, normally one per thread. Sharing an
RNG's mutable state requires synchronization. Explicit `seeded(...)` behavior
and sequences are unchanged. Linux automatic seeding needs `libcrypto.so.3`.

`std.sort.sortBy` is stable with O(n log n) comparisons and O(n) temporary
storage; `sortFastBy` is an unstable in-place quicksort with a bounded work
stack. Ordinary and thread-safe hash maps update existing keys without
growing and periodically rebuild deleted-slot-heavy tables.

`std.io.file` is the durable random-access API intended for databases and
servers: it provides positional reads/writes, truncation, flush, whole-file
advisory locks, atomic replacement and directory synchronization. `std.tls`
provides a built-in target-native Schannel/OpenSSL transport through
`connect(socket, options)` and `accept(socket, options)`. The original
provider-neutral callback contract remains available for custom transports.
See [Platform services](PLATFORM_SERVICES.md) for certificate references,
trust behavior, socket ownership and the native integration test.
Portable native sleep, socket and synchronization timeouts use the common
millisecond range `0..2147483647`. `std.time.sleep` treats values outside that
range as a no-op; APIs returning a result reject them as documented.

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

### Native audio and video playback

`std.video` and `std.audio` provide portable player APIs backed by Media
Foundation and WinMM on Windows and GStreamer 1.x on Linux. Decoding, clocks
and audio output remain in the native media stack. Backend threads never call
into managed MiniLang code;
`Player.pollEvent()` drains a bounded native queue on the application thread.

```ml
import std.video as video

options = video.PlayerOptions.defaults()
options.volume = 0.8
player = video.Player.open("intro.mp4", options)
defer player.close()

// For visible output, attach a GUI-owned native child handle before play().
// player.attach(nativeWindowHandle)
player.play()

event = player.pollEvent()
if event is not void and event.kind == video.EventKind.Error then
  print event.message
end if
```

The player supports play, pause, stop, millisecond seek, loop, mute, volume,
playback rate, duration/position queries, stream discovery and decoded video
dimensions. Opening does not begin playback. Headless playback remains clocked
for audio, metadata probes and automated tests. Network URIs are disabled by
default and require `PlayerOptions.allowNetwork = true`.

For audio-only programs, `std.audio` provides the same deterministic ownership
model with an audio-specific type surface and format detection. WAV, MP3 and
Standard MIDI Files are the portable named formats:

```ml
import std.audio as audio

music = try(audio.Player.open("music.mid"))
defer music.close()
music.setLoop(true)
music.play()
```

Local MIDI playback uses the WinMM sequencer on Windows and GStreamer on
Linux. Windows MIDI does not accept network URIs, and per-player MIDI volume
depends on the installed sequencer; the implementation deliberately never
changes the process-wide MIDI mapper volume.
On Ubuntu, MIDI additionally needs `gstreamer1.0-plugins-bad`,
`libwildmidi-config` and `freepats`.

Deploy `minilang_video.dll` beside a Windows executable or
`libminilang_video.so` beside a Linux executable. Windows 10/11 supplies the
Media Foundation runtime; Linux needs GStreamer 1.x plus the plugins for the
formats the application accepts. Open, control and close calls for one player
must stay serialized on the same application thread, and `close()` should be
called deterministically.
Build, deployment, UI-handle and integration-test details are in the
[native media bridge guide](../native/video/README.md).

### Unit testing with `std.test` and `mltest`

`std.test` is the portable unit-test runtime. It is linked only into programs
which import it, so production executables have no test-framework overhead.
Assertions return MiniLang `error` values and therefore stop the current test
through normal error propagation while the runner catches the failure and
continues with the remaining cases.

Tests can be registered manually with `test.Suite`, or discovered without any
compiler extension. The `mltest` source tool reads explicit declaration
comments and generates a normal MiniLang entrypoint with explicit registrations:

```ml
package tests.math

import std.test as test

/// Verifies integer addition.
/// @testmethod addition
/// @category unit
/// @covers app.math.add
/// @timeout 1000
function additionWorks()
  test.assertEqual(2 + 3, 5)
end function
```

Discovery recognizes synchronous zero-argument top-level functions and
synchronous zero-argument static struct methods. The tagged declaration header
must keep its function name and parameter list on one line. Test source files
must declare a package. Supported metadata is
`@testmethod`, `@beforeall`, `@afterall`, `@beforeeach`, `@aftereach`,
`@category`, `@covers`, `@timeout`, and `@skip`. Tags remain ordinary
`///` or `/** ... */` documentation, so both compilers require no special
syntax or runtime reflection.

Run discovery, compilation, and execution on Windows:

```powershell
.\scripts\run_mltest.ps1 -TestRoot .\tests\mltest_fixture
```

On Linux:

```bash
bash ./scripts/run_mltest.sh tests/mltest_fixture --category unit
```

The generated executable accepts `--filter TEXT`, `--category NAME`,
`--exclude-category NAME`, `--repeat N`, `--seed N`, `--fail-fast`,
`--list`, and `--quiet`. Console output is the default; machine-readable
reports use `--format json --output results.json` or
`--format junit --output results.xml`. The exit code is 0 for a successful
run, 1 when any test failed, and 2 for invalid runner configuration. JSON and
JUnit reports retain discovered categories and coverage declarations. Listing
does not execute fixtures or test callbacks.

The assertion API includes `assertTrue`, `assertFalse`, `assertEqual`,
`assertNotEqual`, `assertSame`, `assertNull`, `assertNotNull`,
`assertType`, `assertContains`, `assertApproxEqual`, `assertError`,
`assertErrorCode`, and `fail`. Runs are deterministic and sequential;
`--seed` changes test order reproducibly. A positive `@timeout` executes that
case on a bounded test thread.

### Builtins: basics

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

### Bytes / Encoding / File I/O

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

#### copyArray(dst, dstOff, src, srcOff, len) -> void
Copies tagged values between arrays in one native operation. The copy is
shallow: strings, nested arrays, structs, and other managed objects remain the
same shared objects.

Rules:
- `dst` and `src` must be arrays.
- `dstOff`, `srcOff`, and `len` must be non-negative integers.
- The effective length is clamped to the remaining tail room of both arrays.
- Invalid arguments or offsets at/past an array end are a no-op.
- Treat source and destination ranges as non-overlapping; overlap behavior is
  not guaranteed.

```ml
src = [10, "twenty", true]
dst = array(5, 0)
copyArray(dst, 1, src, 0, len(src))
print dst // [0, 10, "twenty", true, 0]
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

`std.fs.appendAllBytes` and `appendAllText` append through native file
handles without re-reading the existing file. Whole-file reads fill their
result buffer directly. Linux `copyFile` uses in-kernel copying when suitable
and otherwise a bounded 1-MiB transfer buffer; Windows uses the native copy
operation. For bounded positional I/O with reusable buffers,
including nonzero buffer offsets, use `std.io.file`; for reusable TCP and UDP
receive buffers, use `std.net.tcpRecvInto` and `udpRecvFromInto`.

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

### Heap / GC debug

These builtins are intended for debugging and validating the generated runtime.

#### heap_count()
Returns allocated blocks not marked as free, including unreachable objects
awaiting collection. This is not a reachability count.

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
Runs the mark/sweep collector, waits for completion, and returns `void`.
With `--gc-concurrent`, the calling thread waits while other managed threads
continue between the collector's short stop-the-world handshakes.

#### gc_collect_async()
Requests collection and returns `void`. With `--gc-concurrent`, a persistent
native worker traces and sweeps the heap in the background. Requests made while
a cycle is active coalesce into that cycle; they do not queue another snapshot.
Without that compiler option this builtin falls back to synchronous collection.
Both direct calls and first-class builtin references are supported.

Both compiler implementations support `--gc-concurrent` on `windows-x64`. Their SATB
deletion barriers cover array/member writes, captured variables, Thread
references and `copyArray`. Root capture, marking termination, weak-context
cleanup and free-list publication still require short cooperative pauses.
Allocations after the snapshot are protected until the next cycle. In the
development tree, an immutable exclusion bitmap keeps snapshot-free ranges
available to the allocator, including TLAB refills and split blocks below the
snapshot frontier. At each snapshot a compact bitmap scan coalesces adjacent
ranges and redistributes them into 64 power-of-two size classes. Allocations
search the smallest suitable class before larger ones; this is not an exact
best-fit allocator within a class. TLAB refills can reuse whole ranges between
4 KiB and 64 KiB, instead of splitting a large buffer hole whenever a free
range is slightly smaller than 64 KiB. Pressure and byte counters account for
the actual refill capacity. The bin heads cost 512 bytes per concurrent image.
Blocks newly reclaimed by the worker become available at publication. If bitmap
allocation fails, that cycle safely falls back to withholding old free blocks.
Allocation failure still waits for reclamation.

The extra bitmap lives outside the managed heap and uses one bit per eight
heap bytes (about 1.56% of the used frontier), plus page rounding and a sentinel
word. Its capacity grows geometrically and is retained for reuse. This is
additional process memory, not part of `heap_bytes_committed()`.

The mode cannot be combined with `--heap-shrink`: it reuses dead blocks but
retains committed pages and the heap frontier. Native code must not overwrite
managed reference slots through raw pointers, because such writes bypass the
compiler's barrier. Rooted byte buffers used for native I/O remain supported.
The Linux target rejects this optional mode; its default collector and the
synchronous fallback of `gc_collect_async()` remain supported. A Linux-hosted
ML compiler can still generate Windows programs with the concurrent option.

The reference log defaults to 8 MiB outside the managed heap.
`--gc-satb-limit <size>` adjusts it, clamped to 64 bytes through 64 MiB and rounded
down to whole 8-byte entries. If the log overflows, the worker conservatively
retains every allocated snapshot block for that cycle and reports the overflow;
it never silently drops a reference and then reclaims its target.

#### gc_stat(index)

Reads one scalar diagnostic without allocating or taking the heap lock. Invalid
indices or non-integers return `void`. A disabled periodic limit is reported as
`-1`. Separate reads are not a transactional snapshot: another thread may
collect between them, and collection-local fields can be observed while being
updated. Synchronize application sampling if necessary.

With background collection, live-byte statistics describe the collected
snapshot, not an instantaneous census: objects allocated after that snapshot
are counted in a later cycle, including allocations into reused free ranges.

| Index | Meaning |
| ---: | --- |
| 0 | Started collection count |
| 1 | Reachable block bytes in the latest sweep, including headers |
| 2 | Previously allocated block bytes reclaimed in the latest sweep |
| 3 | Largest coalesced free-list block after the latest sweep |
| 4 | Maximum pending worklist entries in the latest collection |
| 5 | Cumulative central allocator requests, excluding retries/fast-path hits |
| 6 | Cumulative free-list nodes examined |
| 7 | Cumulative central TLAB refill requests |
| 8 | Unused TLAB bytes returned by explicit retirement, not GC revocation |
| 9 | Current overall periodic allocation threshold |
| 10 | Current small-object periodic allocation threshold |
| 11 | Adaptive defaults active: 1; explicit policy: 0 |
| 12 | Cumulative central requested block bytes, including prepaid TLAB batches |
| 13 | Committed mark-worklist capacity, in 8-byte entries |
| 14 | Bytes successfully submitted for interior-page discard in the latest GC |
| 15 | Retained worker contexts after the latest GC, excluding the main thread |

Concurrent builds additionally expose:

| Index | Meaning |
| ---: | --- |
| 16 | Completed background collection count |
| 17 | Phase: 0 idle, 1 marking, 2 sweeping, 3 queued, 4 overflow retention |
| 18 | Cumulative cooperative-pause ticks, using QueryPerformanceCounter |
| 19 | Longest cooperative pause in ticks |
| 20 | Cumulative cycles retaining the snapshot after reference-log overflow |
| 21 | Pointer-bearing mark work items popped in the current cycle |

Divide ticks by `QueryPerformanceFrequency` to obtain seconds. Pause timers
include waiting for managed safepoints and work under the world-stop handshake;
they exclude waiting to acquire the heap monitor. These indices return `void`
in builds without `--gc-concurrent`.

These are diagnostic counters, not allocation totals or process RSS. Index 3
excludes the unused bump tail and is a post-GC sample, not a current allocator
index. Central counts charge each TLAB range once, not each object. Reclaimed
bytes exclude already-free blocks and unused TLAB tails. Counters use the
signed tagged integer range.

Hot per-allocation/probe counters and detailed mark/reclaim accounting are
omitted from generated code when no emitted application code references
`gc_stat`, including first-class references. No runtime switch is required.
Adaptive thresholds still use live-byte accounting in either case.

Without explicit GC settings, thresholds start at 64 MiB overall and 8 MiB for
small objects. After full GC they become
`clamp(liveBlockBytes / 2, 64 MiB, 256 MiB)` and
`clamp(liveBlockBytes / 4, 8 MiB, 64 MiB)`.
This threshold policy is independent of the optional concurrent collector.
`--gc-limit`, `--no-gc-periodic` and any `gc_set_limit()` call disable adaptation.
Explicit settings retain prior behavior, including OOM retry collection.

The worklist reserves the existing 64-MiB maximum outside the managed heap,
initially commits 64 KiB, and doubles committed capacity on demand. Growth never
invokes managed allocation. Reference-free leaves are marked without queuing.
By default this reusable high-water capacity is retained for throughput. With
`--heap-shrink`, eight consecutive collections using at most one quarter of its
capacity trigger trimming to a power-of-two capacity of at least twice the
latest peak (minimum 64 KiB). The mark bitmap also decommits surplus coverage
when at least 64 KiB can be returned; coverage for all committed heap pages is
retained. These native metadata commitments are outside the managed-heap counters.

With `--heap-shrink`, full pages inside dead blocks spanning at least 4 MiB
(after excluding edge pages) may also
be discarded. Headers, free-list links and live neighbors are excluded.
Windows uses `MEM_RESET` (a reclaim hint, not guaranteed immediate RSS reduction);
Linux uses `MADV_DONTNEED` without changing access permissions. Reuse needs no
recommit, but constructors must initialize contents. Interior hints do not lower
the committed-heap counter; top trimming still decommits. This is not compaction
or an independently managed large-object heap.

#### gc_set_limit(limitBytes)
Sets the allocation threshold for the **periodic** GC trigger and returns
`void`.

- A positive integer enables periodic collection with that byte limit.
- Zero, a negative value, or a non-integer disables the periodic trigger.
- The allocation-failure/OOM retry collector remains enabled.
- The current periodic-allocation counter is reset when the limit changes.
- The calling thread's current TLAB is retired, so a new positive limit applies
  to its next allocation rather than its next buffer refill.

Notes (when does GC run?):
- The GC runs **automatically** when an allocation cannot be satisfied and the heap can’t grow further; the runtime triggers a `fn_gc_collect` once and retries the allocation.
- You can also trigger it manually via `gc_collect()`.

Notes:
- Small objects in threaded programs use 64 KiB TLABs; the whole refill is
  charged to periodic/young-allocation pressure once.
- The central allocator reuses freed blocks via a free-list and falls back to
  bump allocation. Repeated exact-size successful searches skip an already
  examined undersized prefix; GC and TLAB retirement invalidate this cursor.
  Mixed-size searches can still be linear; this is not a size-class allocator.
- If the bump pointer would exceed the committed end, the runtime commits more
  pages up to the reserved limit. Growth quanta are page-rounded preferences:
  a request fitting the reservation succeeds even if the full preferred quantum
  would exceed it. Requests exceeding the reservation still fail.
- If `--heap-shrink` is enabled, the runtime may decommit unused top pages and
  discard large interior dead-page ranges as described above.

---


### Call profiling (optional)

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


## extern

The native compiler generates Windows PE imports and library-specific,
runtime-resolved Linux ELF import slots from `extern` declarations.


### extern function

Syntax:

```ml
extern function <Name>(<params...>) from "<library>" [symbol "<exportedName>"] [returns <type>]
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
- Declarations that name the same physical library/symbol with incompatible
  integer/floating-point ABI classes are a compile error; compatible aliases are allowed.
- Type mismatches at runtime currently return `void` (no exceptions yet).
- `wstr` arguments use a fixed temporary UTF-16 buffer. Very long strings may fail and return `void`.
- Windows imports are resolved by the PE loader, so a missing DLL or symbol
  normally prevents startup. Linux preserves the exact `from` spelling,
  resolves it through `dlopen`/`dlsym`, and returns a catchable MiniLang error
  when the library or symbol is unavailable. Lazy Linux resolution is claimed
  atomically, so concurrent first calls share one result; failed lookups are
  cached and a library opened for a missing symbol is closed immediately.

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

## Error handling: `error` & `try`

MiniLang uses **error values** for lightweight error handling (no exception mechanism).
An error is a normal value with:

- `.code` (int)
- `.message` (string)
- `.script` (source path or `void`)
- `.func` (function name or `void`)
- `.line` (source line or `void`)

Runtime-created errors capture their origin. Unhandled errors print that source
location before terminating. For a live call-by-call diagnostic trace, compile
with `--trace-calls`; this is intentionally opt-in because it adds I/O to every
function entry.

### Creating an error value

Use the builtin `error(code, message)`:

```ml
return error(2, "bad input")
```

You can also construct and return errors from within helper functions and stdlib code.

### Automatic propagation (implicit bubbling)

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

### Optional APIs (`void` as absence/failure)

Some builtins intentionally return `void` to indicate failure/absence, e.g.:
- `fromHex(str)`
- `slice(bytes, off, len)`
- `decode(bytes, encoding)`

If you prefer strict behavior, use the stdlib wrappers that return `error(...)` instead:
- `std.encoding.hex.decodeOrError(s)`
- `std.bytes.fromHexOrError(s)`
- `std.bytes.subOrError(b, off, len)`
- `std.bytes.decodeUtf8OrError(b)`

### Catching propagation with `try(expr)`

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

### Toolchain diagnostics

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

## Syntax Reference (short)

### Compile-time directives
- `#option NAME: bool|int|string = <compile-expression>`
- `#const NAME = <compile-expression>`
- `#if <bool-expression>` / `#elif` / `#else` / `#endif`
- `#error <string-expression>`
- CLI override: `-DNAME[=VALUE]` or `--define NAME[=VALUE]`

### Statements
Statements are separated by newlines or `;`.

- `print <expr>`
- `const <ident> = <expr>` (top-level/namespace requires `constexpr`)
- `synchronized <ident> = <expr>` (top-level/namespace shared binding)
- `<lvalue> = <expr>`
  - `<ident> = ...`
  - `<expr>.<field> = ...`
  - `<expr>[<index>] = ...` (multiline indexing allowed)
- compound variable assignment: `x += value`, `x -= value`, `x *= value`, `x /= value`, `x %= value`, `x &= value`, `x |= value`, `x ^= value`, `x <<= value`, or `x >>= value`
- `function name(a,b) ... end function` (multiline params allowed, trailing comma optional)
- `function name(a as int, b as string? = void, rest...) returns int ... end function`
- `async function name(...) ... end function` / `[lazy] iterator function name(...) ... end function`
- `interface Name ... end interface`; `struct Name implements Interface ... end struct`
- `interface Name [extends BaseInterface, ...] ... end interface`
- `class Name [extends Base] [implements Interface] ... end class` (`override function` for overrides)
- `abstract class` / `final class`; `abstract function` / `final function`; `public` / `protected` / `private` members; `function init(...)`
- `operator [inline] <symbol>(typed operands) returns <type> ... end operator` (inside a struct)
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
- `match <expr> ... end match` (value/list/range/default cases)
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
- call: `f(a,b)` or `f(second = 2, first = 1)` (multiline args + trailing comma allowed)
- lambda: `function(x as int) returns int => x + 1`
- optional access/fallback: `value?.member`, `value?.method()`, `left ?? fallback`
- async wait: `await handle`; first completion: `select(handle1, handle2)`
- native thread: `Thread(topLevelFunction)`; methods `Start`, `Stop`, `Join`, `Status`, `IsAlive`, `Id`, `Close`
- index: `arr[i]`
- member: `obj.field`
- unary: `+x`, `-x`, `not x`, `~x`
- binary: `+ - * / % == != > < >= <= and or`
- bitwise: `<< >> & | ^`

Newlines are allowed after operators/unary operators and in common "list" positions (see [newlines and statement separators](#newlines--statement-separators)).

---

## Examples

### FizzBuzz

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

### Functions + array processing

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

### Struct + switch

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

### Enum

```ml
enum Role
  Admin
  Guest
end enum

r = Role.Admin
print r
```
