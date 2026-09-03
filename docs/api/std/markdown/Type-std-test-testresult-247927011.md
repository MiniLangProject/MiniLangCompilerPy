# `std.test.TestResult`

[Home](README.md) · [Source file](File-std-test-ml-828131286.md)

<a id="struct-struct-std-test-testresult-struct-testresult-std-test-ml-1809688773"></a>
## TestResult

```ml
struct TestResult
```

Result of one test or lifecycle callback.


Source: `std/test.ml:345`

## Members

<a id="field-field-std-test-testresult-categories-categories-std-test-ml-1816047890"></a>
### categories

```ml
categories
```

Categories assigned to the test.


Source: `std/test.ml:361`

<a id="field-field-std-test-testresult-covers-covers-std-test-ml-982627850"></a>
### covers

```ml
covers
```

Coverage declarations assigned to the test.


Source: `std/test.ml:363`

<a id="field-field-std-test-testresult-duration-ms-duration-ms-std-test-ml-1437970146"></a>
### duration_ms

```ml
duration_ms
```

Elapsed execution time in milliseconds.


Source: `std/test.ml:353`

<a id="field-field-std-test-testresult-line-line-std-test-ml-2040947546"></a>
### line

```ml
line
```

One-based source line recorded during discovery.


Source: `std/test.ml:359`

<a id="field-field-std-test-testresult-message-message-std-test-ml-2065982894"></a>
### message

```ml
message
```

Failure or skip description.


Source: `std/test.ml:355`

<a id="field-field-std-test-testresult-name-name-std-test-ml-258265472"></a>
### name

```ml
name
```

Test or lifecycle callback display name.


Source: `std/test.ml:349`

<a id="field-field-std-test-testresult-source-source-std-test-ml-1625667844"></a>
### source

```ml
source
```

Source file recorded during discovery.


Source: `std/test.ml:357`

<a id="field-field-std-test-testresult-status-status-std-test-ml-729565510"></a>
### status

```ml
status
```

One of the STATUS_* constants.


Source: `std/test.ml:351`

<a id="field-field-std-test-testresult-suite-suite-std-test-ml-568492878"></a>
### suite

```ml
suite
```

Suite display name.


Source: `std/test.ml:347`
