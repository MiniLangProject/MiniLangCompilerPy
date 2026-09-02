# `std/core.ml`

[Home](README.md) · [Files](Files.md)

Provides the std core package.

Package: [`std.core`](Package-std-core-572909411.md)

Reachable from entry: **yes**

## Declarations

<a id="function-function-std-core-abs-function-abs-x-std-core-ml-390262774"></a>
### abs

```ml
function abs(x)
```

Absolute value.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |


Source: `std/core.ml:125`

<a id="function-function-std-core-clamp-function-clamp-x-lo-hi-std-core-ml-150268134"></a>
### clamp

```ml
function clamp(x, lo, hi)
```

Clamp a value into [lo, hi].

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |
| `lo` | `dynamic` | — | Value supplied for `lo`. |
| `hi` | `dynamic` | — | Value supplied for `hi`. |


Source: `std/core.ml:113`

<a id="function-function-std-core-coalesce-function-coalesce-x-fallback-std-core-ml-1995835884"></a>
### coalesce

```ml
function coalesce(x, fallback)
```

Returns fallback if x is void, otherwise x.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |
| `fallback` | `dynamic` | — | Value supplied for `fallback`. |


Source: `std/core.ml:82`

<a id="function-function-std-core-isarray-function-isarray-x-std-core-ml-378530128"></a>
### isArray

```ml
function isArray(x)
```

Checks whether a value is an array.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |


Source: `std/core.ml:69`

<a id="function-function-std-core-isbool-function-isbool-x-std-core-ml-877919882"></a>
### isBool

```ml
function isBool(x)
```

Checks whether a value is a bool.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |


Source: `std/core.ml:57`

<a id="function-function-std-core-isfloat-function-isfloat-x-std-core-ml-313162674"></a>
### isFloat

```ml
function isFloat(x)
```

Checks whether a value is a float.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |


Source: `std/core.ml:44`

<a id="function-function-std-core-isfunction-function-isfunction-x-std-core-ml-1168317218"></a>
### isFunction

```ml
function isFunction(x)
```

Checks whether a value is a function.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |


Source: `std/core.ml:75`

<a id="function-function-std-core-isint-function-isint-x-std-core-ml-935704364"></a>
### isInt

```ml
function isInt(x)
```

Checks whether a value is an int.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |


Source: `std/core.ml:38`

<a id="function-function-std-core-isnumber-function-isnumber-x-std-core-ml-1560296318"></a>
### isNumber

```ml
function isNumber(x)
```

Checks whether a value is a number (int or float).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |


Source: `std/core.ml:50`

<a id="function-function-std-core-isstring-function-isstring-x-std-core-ml-2010892826"></a>
### isString

```ml
function isString(x)
```

Checks whether a value is a string.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |


Source: `std/core.ml:63`

<a id="function-function-std-core-isvoid-function-isvoid-x-std-core-ml-1825949782"></a>
### isVoid

```ml
function isVoid(x)
```

Checks whether a value is void.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |


Source: `std/core.ml:32`

<a id="function-function-std-core-max-function-max-a-b-std-core-ml-735947893"></a>
### max

```ml
function max(a, b)
```

Maximum of two comparable values.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | First input value. |
| `b` | `dynamic` | — | Second input value. |


Source: `std/core.ml:102`

<a id="function-function-std-core-min-function-min-a-b-std-core-ml-1618154621"></a>
### min

```ml
function min(a, b)
```

Minimum of two comparable values.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | First input value. |
| `b` | `dynamic` | — | Second input value. |


Source: `std/core.ml:92`

<a id="function-function-std-core-safelen-function-safelen-x-fallback-std-core-ml-2007178136"></a>
### safeLen

```ml
function safeLen(x, fallback)
```

Safe len(): returns len(x) if x supports it, otherwise fallback.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |
| `fallback` | `dynamic` | — | Value supplied for `fallback`. |


Source: `std/core.ml:147`

<a id="function-function-std-core-safetonumber-function-safetonumber-x-fallback-std-core-ml-527887072"></a>
### safeToNumber

```ml
function safeToNumber(x, fallback)
```

Safe toNumber(): returns converted value or fallback.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |
| `fallback` | `dynamic` | — | Value supplied for `fallback`. |


Source: `std/core.ml:158`

<a id="function-function-std-core-sign-function-sign-x-std-core-ml-1151146318"></a>
### sign

```ml
function sign(x)
```

Sign of a number.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |


Source: `std/core.ml:134`
