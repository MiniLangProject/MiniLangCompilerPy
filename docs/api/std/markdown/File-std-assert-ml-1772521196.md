# `std/assert.ml`

[Home](README.md) · [Files](Files.md)

Provides the std assert package.

Package: [`std.assert`](Package-std-assert-1056679750.md)

Reachable from entry: **no**

## Declarations

<a id="function-function-std-assert-assertapprox-function-assertapprox-actual-expected-eps-label-std-assert-ml-916027518"></a>
### assertApprox

```ml
function assertApprox(actual, expected, eps, label)
```

Asserts that two numbers are approximately equal.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `actual` | `dynamic` | — | Value supplied for `actual`. |
| `expected` | `dynamic` | — | Value supplied for `expected`. |
| `eps` | `dynamic` | — | Value supplied for `eps`. |
| `label` | `dynamic` | — | Value supplied for `label`. |


Source: `std/assert.ml:130`

<a id="function-function-std-assert-asserteq-function-asserteq-actual-expected-label-std-assert-ml-808850792"></a>
### assertEq

```ml
function assertEq(actual, expected, label)
```

Asserts that two values are equal (==).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `actual` | `dynamic` | — | Value supplied for `actual`. |
| `expected` | `dynamic` | — | Value supplied for `expected`. |
| `label` | `dynamic` | — | Value supplied for `label`. |


Source: `std/assert.ml:59`

<a id="function-function-std-assert-assertfalse-function-assertfalse-cond-label-std-assert-ml-1917626464"></a>
### assertFalse

```ml
function assertFalse(cond, label)
```

Asserts that a condition is false.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `cond` | `dynamic` | — | Value supplied for `cond`. |
| `label` | `dynamic` | — | Value supplied for `label`. |


Source: `std/assert.ml:44`

<a id="function-function-std-assert-assertgt-function-assertgt-a-b-label-std-assert-ml-51991933"></a>
### assertGt

```ml
function assertGt(a, b, label)
```

Asserts that a is greater than b.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | First input value. |
| `b` | `dynamic` | — | Second input value. |
| `label` | `dynamic` | — | Value supplied for `label`. |


Source: `std/assert.ml:93`

<a id="function-function-std-assert-assertlt-function-assertlt-a-b-label-std-assert-ml-756131789"></a>
### assertLt

```ml
function assertLt(a, b, label)
```

Asserts that a is less than b.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | First input value. |
| `b` | `dynamic` | — | Second input value. |
| `label` | `dynamic` | — | Value supplied for `label`. |


Source: `std/assert.ml:111`

<a id="function-function-std-assert-assertne-function-assertne-actual-expected-label-std-assert-ml-221639904"></a>
### assertNe

```ml
function assertNe(actual, expected, label)
```

Asserts that two values are not equal (!=).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `actual` | `dynamic` | — | Value supplied for `actual`. |
| `expected` | `dynamic` | — | Value supplied for `expected`. |
| `label` | `dynamic` | — | Value supplied for `label`. |


Source: `std/assert.ml:77`

<a id="function-function-std-assert-assertnotvoid-function-assertnotvoid-x-label-std-assert-ml-1841061316"></a>
### assertNotVoid

```ml
function assertNotVoid(x, label)
```

Asserts that a value is not void.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |
| `label` | `dynamic` | — | Value supplied for `label`. |


Source: `std/assert.ml:154`

<a id="function-function-std-assert-asserttrue-function-asserttrue-cond-label-std-assert-ml-1187416750"></a>
### assertTrue

```ml
function assertTrue(cond, label)
```

Asserts that a condition is true.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `cond` | `dynamic` | — | Value supplied for `cond`. |
| `label` | `dynamic` | — | Value supplied for `label`. |


Source: `std/assert.ml:30`
