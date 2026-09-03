# `std.test.RunSummary`

[Home](README.md) · [Source file](File-std-test-ml-828131286.md)

<a id="struct-struct-std-test-runsummary-struct-runsummary-std-test-ml-887311257"></a>
## RunSummary

```ml
struct RunSummary
```

Aggregate counts and detailed results from a completed run.


Source: `std/test.ml:367`

## Members

<a id="field-field-std-test-runsummary-duration-ms-duration-ms-std-test-ml-691772892"></a>
### duration_ms

```ml
duration_ms
```

Elapsed duration of the complete run in milliseconds.


Source: `std/test.ml:375`

<a id="method-method-std-test-runsummary-exitcode-function-exitcode-std-test-ml-1038758472"></a>
### exitCode

```ml
function exitCode()
```

Return the process exit code expected by test automation.


Source: `std/test.ml:385`

<a id="field-field-std-test-runsummary-failed-failed-std-test-ml-1351910958"></a>
### failed

```ml
failed
```

Number of failed results.


Source: `std/test.ml:371`

<a id="field-field-std-test-runsummary-passed-passed-std-test-ml-126724548"></a>
### passed

```ml
passed
```

Number of passed results.


Source: `std/test.ml:369`

<a id="field-field-std-test-runsummary-results-results-std-test-ml-558766260"></a>
### results

```ml
results
```

Detailed TestResult values in execution order.


Source: `std/test.ml:377`

<a id="field-field-std-test-runsummary-skipped-skipped-std-test-ml-193997996"></a>
### skipped

```ml
skipped
```

Number of skipped results.


Source: `std/test.ml:373`

<a id="method-method-std-test-runsummary-total-function-total-std-test-ml-305676144"></a>
### total

```ml
function total()
```

Return the total number of recorded results.


Source: `std/test.ml:380`
