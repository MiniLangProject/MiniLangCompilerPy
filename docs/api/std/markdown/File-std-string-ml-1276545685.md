# `std/string.ml`

[Home](README.md) · [Files](Files.md)

Provides the std string package.

Package: [`std.string`](Package-std-string-55421397.md)

Reachable from entry: **no**

## Imports

- `std/string_builder.ml` as `sb` → [std/string_builder.ml](File-std-string-builder-ml-412876577.md)

## Declarations

<a id="function-function-std-string-contains-function-contains-s-needle-std-string-ml-890712776"></a>
### contains

```ml
function contains(s, needle)
```

Checks whether s contains needle.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `s` | `dynamic` | — | Value supplied for `s`. |
| `needle` | `dynamic` | — | Value supplied for `needle`. |


Source: `std/string.ml:301`

<a id="function-function-std-string-countof-function-countof-s-needle-std-string-ml-1466834176"></a>
### countOf

```ml
function countOf(s, needle)
```

Counts non-overlapping occurrences of needle in s.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `s` | `dynamic` | — | Value supplied for `s`. |
| `needle` | `dynamic` | — | Value supplied for `needle`. |


Source: `std/string.ml:489`

<a id="function-function-std-string-endswith-function-endswith-s-suffix-std-string-ml-1833247770"></a>
### endsWith

```ml
function endsWith(s, suffix)
```

Checks whether s ends with suffix.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `s` | `dynamic` | — | Value supplied for `s`. |
| `suffix` | `dynamic` | — | Value supplied for `suffix`. |


Source: `std/string.ml:264`

<a id="function-function-std-string-equalsignorecaseascii-function-equalsignorecaseascii-a-b-std-string-ml-2118708601"></a>
### equalsIgnoreCaseAscii

```ml
function equalsIgnoreCaseAscii(a, b)
```

Compares two strings case-insensitively (ASCII).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | First input value. |
| `b` | `dynamic` | — | Second input value. |


Source: `std/string.ml:579`

<a id="function-function-std-string-indexof-function-indexof-s-needle-start-std-string-ml-1830793656"></a>
### indexOf

```ml
function indexOf(s, needle, start)
```

Finds needle in s starting from start.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `s` | `dynamic` | — | Value supplied for `s`. |
| `needle` | `dynamic` | — | Value supplied for `needle`. |
| `start` | `dynamic` | — | Value supplied for `start`. |


Source: `std/string.ml:272`

<a id="function-function-std-string-isalnumascii-function-isalnumascii-ch-std-string-ml-991856061"></a>
### isAlnumAscii

```ml
function isAlnumAscii(ch)
```

Checks whether a character is ASCII alphanumeric.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `ch` | `dynamic` | — | Value supplied for `ch`. |


Source: `std/string.ml:560`

<a id="function-function-std-string-isalphaascii-function-isalphaascii-ch-std-string-ml-69464141"></a>
### isAlphaAscii

```ml
function isAlphaAscii(ch)
```

Checks whether a character is an ASCII letter (A-Z or a-z).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `ch` | `dynamic` | — | Value supplied for `ch`. |


Source: `std/string.ml:548`

<a id="function-function-std-string-isblank-function-isblank-s-std-string-ml-1002423985"></a>
### isBlank

```ml
function isBlank(s)
```

Checks whether a string is blank (empty after trim).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `s` | `dynamic` | — | Value supplied for `s`. |


Source: `std/string.ml:329`

<a id="function-function-std-string-isdigitascii-function-isdigitascii-ch-std-string-ml-1642095953"></a>
### isDigitAscii

```ml
function isDigitAscii(ch)
```

Checks whether a character is an ASCII digit.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `ch` | `dynamic` | — | Value supplied for `ch`. |


Source: `std/string.ml:536`

<a id="function-function-std-string-isempty-function-isempty-s-std-string-ml-464897055"></a>
### isEmpty

```ml
function isEmpty(s)
```

Checks whether a string is empty.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `s` | `dynamic` | — | Value supplied for `s`. |


Source: `std/string.ml:232`

<a id="function-function-std-string-join-function-join-parts-sep-std-string-ml-1383969706"></a>
### join

```ml
function join(parts, sep)
```

Joins string parts with a separator.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `parts` | `dynamic` | — | Value supplied for `parts`. |
| `sep` | `dynamic` | — | Value supplied for `sep`. |


Source: `std/string.ml:388`

<a id="function-function-std-string-lastindexof-function-lastindexof-s-needle-std-string-ml-183528886"></a>
### lastIndexOf

```ml
function lastIndexOf(s, needle)
```

Finds the last occurrence of needle in s.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `s` | `dynamic` | — | Value supplied for `s`. |
| `needle` | `dynamic` | — | Value supplied for `needle`. |


Source: `std/string.ml:288`

<a id="function-function-std-string-ltrim-function-ltrim-s-std-string-ml-1358329729"></a>
### ltrim

```ml
function ltrim(s)
```

Trims ASCII whitespace on the left.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `s` | `dynamic` | — | Value supplied for `s`. |


Source: `std/string.ml:311`

<a id="function-function-std-string-removeall-function-removeall-s-needle-std-string-ml-1652900222"></a>
### removeAll

```ml
function removeAll(s, needle)
```

Removes all occurrences of needle from s.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `s` | `dynamic` | — | Value supplied for `s`. |
| `needle` | `dynamic` | — | Value supplied for `needle`. |


Source: `std/string.ml:520`

<a id="function-function-std-string-repeat-function-repeat-s-count-std-string-ml-194349680"></a>
### repeat

```ml
function repeat(s, count)
```

Repeats a string count times.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `s` | `dynamic` | — | Value supplied for `s`. |
| `count` | `dynamic` | — | Number of items to process. |


Source: `std/string.ml:242`

<a id="function-function-std-string-replaceall-function-replaceall-s-needle-repl-std-string-ml-840926615"></a>
### replaceAll

```ml
function replaceAll(s, needle, repl)
```

Replaces all occurrences of needle with repl.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `s` | `dynamic` | — | Value supplied for `s`. |
| `needle` | `dynamic` | — | Value supplied for `needle`. |
| `repl` | `dynamic` | — | Value supplied for `repl`. |


Source: `std/string.ml:396`

<a id="function-function-std-string-replacefirst-function-replacefirst-s-needle-repl-std-string-ml-1457517015"></a>
### replaceFirst

```ml
function replaceFirst(s, needle, repl)
```

Replaces the first occurrence of needle with repl.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `s` | `dynamic` | — | Value supplied for `s`. |
| `needle` | `dynamic` | — | Value supplied for `needle`. |
| `repl` | `dynamic` | — | Value supplied for `repl`. |


Source: `std/string.ml:446`

<a id="function-function-std-string-reverse-function-reverse-s-std-string-ml-478686905"></a>
### reverse

```ml
function reverse(s)
```

Reverses a string.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `s` | `dynamic` | — | Value supplied for `s`. |


Source: `std/string.ml:526`

<a id="function-function-std-string-rtrim-function-rtrim-s-std-string-ml-2074447113"></a>
### rtrim

```ml
function rtrim(s)
```

Trims ASCII whitespace on the right.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `s` | `dynamic` | — | Value supplied for `s`. |


Source: `std/string.ml:317`

<a id="function-function-std-string-split-function-split-s-sep-std-string-ml-439300297"></a>
### split

```ml
function split(s, sep)
```

Splits a string by a separator.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `s` | `dynamic` | — | Value supplied for `s`. |
| `sep` | `dynamic` | — | Value supplied for `sep`. |


Source: `std/string.ml:336`

<a id="function-function-std-string-startswith-function-startswith-s-prefix-std-string-ml-864273261"></a>
### startsWith

```ml
function startsWith(s, prefix)
```

Checks whether s starts with prefix.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `s` | `dynamic` | — | Value supplied for `s`. |
| `prefix` | `dynamic` | — | Value supplied for `prefix`. |


Source: `std/string.ml:257`

<a id="function-function-std-string-substr-function-substr-s-start-length-std-string-ml-1364948665"></a>
### substr

```ml
function substr(s, start, length)
```

Returns a substring of s.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `s` | `dynamic` | — | Value supplied for `s`. |
| `start` | `dynamic` | — | Value supplied for `start`. |
| `length` | `dynamic` | — | Number of elements or bytes to process. |


Source: `std/string.ml:250`

<a id="function-function-std-string-tolowerascii-function-tolowerascii-s-std-string-ml-2007062345"></a>
### toLowerAscii

```ml
function toLowerAscii(s)
```

Converts a string to lowercase (ASCII).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `s` | `dynamic` | — | Value supplied for `s`. |


Source: `std/string.ml:566`

<a id="function-function-std-string-toupperascii-function-toupperascii-s-std-string-ml-994049617"></a>
### toUpperAscii

```ml
function toUpperAscii(s)
```

Converts a string to uppercase (ASCII).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `s` | `dynamic` | — | Value supplied for `s`. |


Source: `std/string.ml:572`

<a id="function-function-std-string-trim-function-trim-s-std-string-ml-2004823441"></a>
### trim

```ml
function trim(s)
```

Trims ASCII whitespace on both sides.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `s` | `dynamic` | — | Value supplied for `s`. |


Source: `std/string.ml:323`
