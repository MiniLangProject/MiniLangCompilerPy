# `std/test.ml`

[Home](README.md) · [Files](Files.md)

Provides assertions, suites, fixtures, filtering, timing, and portable console, JSON, and JUnit reporting for MiniLang tests.

Package: [`std.test`](Package-std-test-298069872.md)

Reachable from entry: **no**

## Imports

- `std/fs.ml` as `fs` → [std/fs.ml](File-std-fs-ml-1285967051.md)
- `std/string.ml` as `strings` → [std/string.ml](File-std-string-ml-1276545685.md)
- `std/string_builder.ml` as `builders` → [std/string_builder.ml](File-std-string-builder-ml-412876577.md)
- `std/time.ml` as `time` → [std/time.ml](File-std-time-ml-975894601.md)

## Declarations

<a id="function-function-std-test-assertapproxequal-function-assertapproxequal-actual-expected-epsilon-message-std-test-ml-1132070524"></a>
### assertApproxEqual

```ml
function assertApproxEqual(actual, expected, epsilon, message = "")
```

Assert approximate numeric equality.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `actual` | `dynamic` | — | Observed numeric value. |
| `expected` | `dynamic` | — | Required numeric value. |
| `epsilon` | `dynamic` | — | Maximum absolute difference. |
| `message` | `dynamic` | `""` | Optional diagnostic label. |


Source: `std/test.ml:167`

<a id="function-function-std-test-assertcontains-function-assertcontains-container-expected-message-std-test-ml-825710629"></a>
### assertContains

```ml
function assertContains(container, expected, message = "")
```

Assert that a string or array contains a requested value.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `container` | `dynamic` | — | String or array to search. |
| `expected` | `dynamic` | — | Requested substring or element. |
| `message` | `dynamic` | `""` | Optional diagnostic label. |


Source: `std/test.ml:143`

<a id="function-function-std-test-assertequal-function-assertequal-actual-expected-message-std-test-ml-356634818"></a>
### assertEqual

```ml
function assertEqual(actual, expected, message = "")
```

Assert value equality using MiniLang's ordinary equality semantics.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `actual` | `dynamic` | — | Observed value. |
| `expected` | `dynamic` | — | Required value. |
| `message` | `dynamic` | `""` | Optional diagnostic label. |


Source: `std/test.ml:79`

<a id="function-function-std-test-asserterror-function-asserterror-callback-message-std-test-ml-550210097"></a>
### assertError

```ml
function assertError(callback, message = "")
```

Assert that invoking a zero-argument callback produces an error value.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `callback` | `dynamic` | — | Operation expected to fail. |
| `message` | `dynamic` | `""` | Optional diagnostic label. |


Source: `std/test.ml:183`

<a id="function-function-std-test-asserterrorcode-function-asserterrorcode-callback-expected-code-message-std-test-ml-1026261057"></a>
### assertErrorCode

```ml
function assertErrorCode(callback, expected_code, message = "")
```

Assert that invoking a callback produces an error with a requested code.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `callback` | `dynamic` | — | Operation expected to fail. |
| `expected_code` | `dynamic` | — | Required MiniLang error code. |
| `message` | `dynamic` | `""` | Optional diagnostic label. |


Source: `std/test.ml:196`

<a id="function-function-std-test-assertfalse-function-assertfalse-condition-message-std-test-ml-88733509"></a>
### assertFalse

```ml
function assertFalse(condition, message = "")
```

Assert that a value is false.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `condition` | `dynamic` | — | Condition expected to be false. |
| `message` | `dynamic` | `""` | Optional diagnostic label. |


Source: `std/test.ml:69`

<a id="constant-constant-std-test-assertion-error-const-assertion-error-1800-std-test-ml-249620278"></a>
### ASSERTION_ERROR

```ml
const ASSERTION_ERROR = 1800
```

Error code returned by an assertion that does not hold.


Source: `std/test.ml:28`

<a id="function-function-std-test-assertnotequal-function-assertnotequal-actual-unexpected-message-std-test-ml-1259841807"></a>
### assertNotEqual

```ml
function assertNotEqual(actual, unexpected, message = "")
```

Assert that two values are different.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `actual` | `dynamic` | — | Observed value. |
| `unexpected` | `dynamic` | — | Value which must not be observed. |
| `message` | `dynamic` | `""` | Optional diagnostic label. |


Source: `std/test.ml:90`

<a id="function-function-std-test-assertnotnull-function-assertnotnull-value-message-std-test-ml-1381145391"></a>
### assertNotNull

```ml
function assertNotNull(value, message = "")
```

Assert that a value is not void.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `value` | `dynamic` | — | Observed value. |
| `message` | `dynamic` | `""` | Optional diagnostic label. |


Source: `std/test.ml:121`

<a id="function-function-std-test-assertnull-function-assertnull-value-message-std-test-ml-1376579519"></a>
### assertNull

```ml
function assertNull(value, message = "")
```

Assert that a value is void.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `value` | `dynamic` | — | Observed value. |
| `message` | `dynamic` | `""` | Optional diagnostic label. |


Source: `std/test.ml:111`

<a id="function-function-std-test-assertsame-function-assertsame-actual-expected-message-std-test-ml-1020169278"></a>
### assertSame

```ml
function assertSame(actual, expected, message = "")
```

Assert managed-object or callable identity rather than structural equality.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `actual` | `dynamic` | — | Observed value. |
| `expected` | `dynamic` | — | Required identical value. |
| `message` | `dynamic` | `""` | Optional diagnostic label. |


Source: `std/test.ml:101`

<a id="function-function-std-test-asserttrue-function-asserttrue-condition-message-std-test-ml-139217435"></a>
### assertTrue

```ml
function assertTrue(condition, message = "")
```

Assert that a value is truthy.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `condition` | `dynamic` | — | Condition expected to be true. |
| `message` | `dynamic` | `""` | Optional diagnostic label. |


Source: `std/test.ml:60`

<a id="function-function-std-test-asserttype-function-asserttype-value-expected-type-message-std-test-ml-1636061718"></a>
### assertType

```ml
function assertType(value, expected_type, message = "")
```

Assert the public runtime category returned by `typeof`.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `value` | `dynamic` | — | Observed value. |
| `expected_type` | `dynamic` | — | Expected runtime category. |
| `message` | `dynamic` | `""` | Optional diagnostic label. |


Source: `std/test.ml:131`

<a id="constant-constant-std-test-configuration-error-const-configuration-error-1802-std-test-ml-1804814304"></a>
### CONFIGURATION_ERROR

```ml
const CONFIGURATION_ERROR = 1802
```

Error code returned for an invalid test-framework argument or declaration.


Source: `std/test.ml:32`

<a id="function-function-std-test-execute-function-execute-suites-options-std-test-ml-1764874293"></a>
### execute

```ml
function execute(suites, options)
```

Execute selected suites without rendering a report.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `suites` | `dynamic` | — | Array of Suite values. |
| `options` | `dynamic` | — | Effective RunOptions. |


Source: `std/test.ml:512`

<a id="function-function-std-test-fail-function-fail-message-test-failed-std-test-ml-285971369"></a>
### fail

```ml
function fail(message = "test failed")
```

Fail the current test immediately.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `message` | `dynamic` | `"test failed"` | Failure detail. |


Source: `std/test.ml:212`

<a id="function-function-std-test-parseoptions-function-parseoptions-args-std-test-ml-1147878359"></a>
### parseOptions

```ml
function parseOptions(args)
```

Parse portable runner switches.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `args` | `dynamic` | — | Command-line arguments passed to the test executable. |


Source: `std/test.ml:729`

<a id="function-function-std-test-printconsole-function-printconsole-summary-std-test-ml-1165059960"></a>
### printConsole

```ml
function printConsole(summary)
```

Render a human-readable console report.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `summary` | `dynamic` | — | Completed RunSummary. |


Source: `std/test.ml:696`

<a id="function-function-std-test-run-function-run-suites-args-std-test-ml-695526029"></a>
### run

```ml
function run(suites, args = [])
```

Execute suites, render the selected report, and return a process exit code.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `suites` | `dynamic` | — | Array of Suite values. |
| `args` | `dynamic` | `[]` | Runner command-line switches. |


Source: `std/test.ml:765`

- [std.test.RunOptions](Type-std-test-runoptions-1972408287.md) — struct
- [std.test.RunSummary](Type-std-test-runsummary-1084060661.md) — struct
<a id="constant-constant-std-test-status-failed-const-status-failed-failed-std-test-ml-885630280"></a>
### STATUS_FAILED

```ml
const STATUS_FAILED = "failed"
```

Status assigned to a failed test result.


Source: `std/test.ml:37`

<a id="constant-constant-std-test-status-passed-const-status-passed-passed-std-test-ml-1171109675"></a>
### STATUS_PASSED

```ml
const STATUS_PASSED = "passed"
```

Status assigned to a successful test result.


Source: `std/test.ml:35`

<a id="constant-constant-std-test-status-skipped-const-status-skipped-skipped-std-test-ml-2350847"></a>
### STATUS_SKIPPED

```ml
const STATUS_SKIPPED = "skipped"
```

Status assigned to a deliberately skipped test result.


Source: `std/test.ml:39`

- [std.test.Suite](Type-std-test-suite-2053891654.md) — struct
- [std.test.TestCase](Type-std-test-testcase-658817446.md) — struct
- [std.test.TestResult](Type-std-test-testresult-247927011.md) — struct
<a id="constant-constant-std-test-timeout-error-const-timeout-error-1801-std-test-ml-1922440569"></a>
### TIMEOUT_ERROR

```ml
const TIMEOUT_ERROR = 1801
```

Error code returned when a timed test does not finish before its deadline.


Source: `std/test.ml:30`

<a id="function-function-std-test-tojson-function-tojson-summary-std-test-ml-1607339476"></a>
### toJson

```ml
function toJson(summary)
```

Render detailed JSON suitable for archival and custom automation.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `summary` | `dynamic` | — | Completed RunSummary. |


Source: `std/test.ml:646`

<a id="function-function-std-test-tojunit-function-tojunit-summary-std-test-ml-760967806"></a>
### toJUnit

```ml
function toJUnit(summary)
```

Render a JUnit-compatible XML test suite.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `summary` | `dynamic` | — | Completed RunSummary. |


Source: `std/test.ml:662`
