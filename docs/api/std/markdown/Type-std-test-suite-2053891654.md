# `std.test.Suite`

[Home](README.md) · [Source file](File-std-test-ml-828131286.md)

<a id="struct-struct-std-test-suite-struct-suite-std-test-ml-1225261483"></a>
## Suite

```ml
struct Suite
```

A named set of tests and optional lifecycle callbacks.


Source: `std/test.ml:248`

## Members

<a id="method-method-std-test-suite-add-function-add-name-callback-std-test-ml-1211349449"></a>
### add

```ml
function add(name, callback)
```

Register a test callback using default metadata.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | `dynamic` | — | Display name. |
| `callback` | `dynamic` | — | Zero-argument test function. |


Source: `std/test.ml:280`

<a id="method-method-std-test-suite-addcase-function-addcase-test-case-std-test-ml-1923928176"></a>
### addCase

```ml
function addCase(test_case)
```

Register a fully configured test case.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `test_case` | `dynamic` | — | TestCase to append. |


Source: `std/test.ml:271`

<a id="field-field-std-test-suite-after-all-after-all-std-test-ml-1717980127"></a>
### after_all

```ml
after_all
```

Optional suite-level cleanup callback.


Source: `std/test.ml:256`

<a id="field-field-std-test-suite-after-each-after-each-std-test-ml-1666292567"></a>
### after_each

```ml
after_each
```

Optional per-test cleanup callback.


Source: `std/test.ml:260`

<a id="field-field-std-test-suite-before-all-before-all-std-test-ml-1234210229"></a>
### before_all

```ml
before_all
```

Optional suite-level setup callback.


Source: `std/test.ml:254`

<a id="field-field-std-test-suite-before-each-before-each-std-test-ml-400138663"></a>
### before_each

```ml
before_each
```

Optional per-test setup callback.


Source: `std/test.ml:258`

<a id="field-field-std-test-suite-cases-cases-std-test-ml-1484325443"></a>
### cases

```ml
cases
```

Registered TestCase values.


Source: `std/test.ml:252`

<a id="field-field-std-test-suite-name-name-std-test-ml-125367025"></a>
### name

```ml
name
```

Suite display name.


Source: `std/test.ml:250`

<a id="static_method-static-method-std-test-suite-new-static-function-new-name-std-test-ml-1686384689"></a>
### new

```ml
static function new(name)
```

Create an empty suite.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | `dynamic` | — | Suite display name. |


Source: `std/test.ml:264`

<a id="method-method-std-test-suite-setafterall-function-setafterall-callback-std-test-ml-1919038420"></a>
### setAfterAll

```ml
function setAfterAll(callback)
```

Set the callback executed once after this suite.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `callback` | `dynamic` | — | Zero-argument cleanup function. |


Source: `std/test.ml:295`

<a id="method-method-std-test-suite-setaftereach-function-setaftereach-callback-std-test-ml-1141614794"></a>
### setAfterEach

```ml
function setAfterEach(callback)
```

Set the callback executed after every selected test.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `callback` | `dynamic` | — | Zero-argument cleanup function. |


Source: `std/test.ml:309`

<a id="method-method-std-test-suite-setbeforeall-function-setbeforeall-callback-std-test-ml-161451938"></a>
### setBeforeAll

```ml
function setBeforeAll(callback)
```

Set the callback executed once before this suite.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `callback` | `dynamic` | — | Zero-argument setup function. |


Source: `std/test.ml:288`

<a id="method-method-std-test-suite-setbeforeeach-function-setbeforeeach-callback-std-test-ml-923959146"></a>
### setBeforeEach

```ml
function setBeforeEach(callback)
```

Set the callback executed before every selected test.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `callback` | `dynamic` | — | Zero-argument setup function. |


Source: `std/test.ml:302`
