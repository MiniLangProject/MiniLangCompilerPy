# `std.test.RunOptions`

[Home](README.md) · [Source file](File-std-test-ml-828131286.md)

<a id="struct-struct-std-test-runoptions-struct-runoptions-std-test-ml-82442413"></a>
## RunOptions

```ml
struct RunOptions
```

Effective settings for one test run.


Source: `std/test.ml:316`

## Members

<a id="field-field-std-test-runoptions-category-category-std-test-ml-1108435530"></a>
### category

```ml
category
```

Required category, or an empty string.


Source: `std/test.ml:320`

<a id="static_method-static-method-std-test-runoptions-defaults-static-function-defaults-std-test-ml-1314628537"></a>
### defaults

```ml
static function defaults()
```

Return deterministic default settings.


Source: `std/test.ml:339`

<a id="field-field-std-test-runoptions-excluded-category-excluded-category-std-test-ml-717543914"></a>
### excluded_category

```ml
excluded_category
```

Excluded category, or an empty string.


Source: `std/test.ml:322`

<a id="field-field-std-test-runoptions-fail-fast-fail-fast-std-test-ml-253985606"></a>
### fail_fast

```ml
fail_fast
```

Whether the run stops after its first failure.


Source: `std/test.ml:328`

<a id="field-field-std-test-runoptions-filter-filter-std-test-ml-216615270"></a>
### filter

```ml
filter
```

Case-insensitive substring matched against suite and test names.


Source: `std/test.ml:318`

<a id="field-field-std-test-runoptions-format-format-std-test-ml-1102417340"></a>
### format

```ml
format
```

Report format: console, json, or junit.


Source: `std/test.ml:334`

<a id="field-field-std-test-runoptions-list-only-list-only-std-test-ml-1281222586"></a>
### list_only

```ml
list_only
```

Whether selected tests are listed without being executed.


Source: `std/test.ml:330`

<a id="field-field-std-test-runoptions-output-output-std-test-ml-1719576348"></a>
### output

```ml
output
```

Report destination used by JSON and JUnit formats.


Source: `std/test.ml:336`

<a id="field-field-std-test-runoptions-quiet-quiet-std-test-ml-1750478754"></a>
### quiet

```ml
quiet
```

Whether console reporting is suppressed.


Source: `std/test.ml:332`

<a id="field-field-std-test-runoptions-repeat-repeat-std-test-ml-284532504"></a>
### repeat

```ml
repeat
```

Number of times to execute each selected test.


Source: `std/test.ml:324`

<a id="field-field-std-test-runoptions-seed-seed-std-test-ml-439076372"></a>
### seed

```ml
seed
```

Deterministic shuffle seed; zero preserves declaration order.


Source: `std/test.ml:326`
