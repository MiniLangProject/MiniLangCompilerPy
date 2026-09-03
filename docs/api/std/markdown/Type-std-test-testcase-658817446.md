# `std.test.TestCase`

[Home](README.md) · [Source file](File-std-test-ml-828131286.md)

<a id="struct-struct-std-test-testcase-struct-testcase-std-test-ml-1399475893"></a>
## TestCase

```ml
struct TestCase
```

One executable test plus source and discovery metadata.


Source: `std/test.ml:217`

## Members

<a id="field-field-std-test-testcase-callback-callback-std-test-ml-92275433"></a>
### callback

```ml
callback
```

Zero-argument function executed by the runner.


Source: `std/test.ml:221`

<a id="field-field-std-test-testcase-categories-categories-std-test-ml-619685363"></a>
### categories

```ml
categories
```

Categories used by runner filters.


Source: `std/test.ml:233`

<a id="field-field-std-test-testcase-covers-covers-std-test-ml-2010190059"></a>
### covers

```ml
covers
```

Qualified API symbols covered by this test.


Source: `std/test.ml:235`

<a id="field-field-std-test-testcase-line-line-std-test-ml-835165051"></a>
### line

```ml
line
```

One-based declaration line.


Source: `std/test.ml:225`

<a id="field-field-std-test-testcase-name-name-std-test-ml-61076661"></a>
### name

```ml
name
```

Display name shown by reporters.


Source: `std/test.ml:219`

<a id="static_method-static-method-std-test-testcase-new-static-function-new-name-callback-std-test-ml-1889384904"></a>
### new

```ml
static function new(name, callback)
```

Create a test with portable default metadata.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | `dynamic` | — | Display name. |
| `callback` | `dynamic` | — | Zero-argument test function. |


Source: `std/test.ml:240`

<a id="field-field-std-test-testcase-skip-reason-skip-reason-std-test-ml-1965380191"></a>
### skip_reason

```ml
skip_reason
```

Explanation attached to a skipped test.


Source: `std/test.ml:229`

<a id="field-field-std-test-testcase-skipped-skipped-std-test-ml-768396451"></a>
### skipped

```ml
skipped
```

Whether the test is deliberately disabled.


Source: `std/test.ml:227`

<a id="field-field-std-test-testcase-source-source-std-test-ml-91860317"></a>
### source

```ml
source
```

Project-relative source path when discovered by `mltest`.


Source: `std/test.ml:223`

<a id="field-field-std-test-testcase-timeout-ms-timeout-ms-std-test-ml-1164269403"></a>
### timeout_ms

```ml
timeout_ms
```

Per-test timeout in milliseconds, or zero when unlimited.


Source: `std/test.ml:231`
