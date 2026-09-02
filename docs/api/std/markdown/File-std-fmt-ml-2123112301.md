# `std/fmt.ml`

[Home](README.md) · [Files](Files.md)

Provides the std fmt package.

Package: [`std.fmt`](Package-std-fmt-186156495.md)

Reachable from entry: **no**

## Imports

- `std/string_builder.ml` as `sb` → [std/string_builder.ml](File-std-string-builder-ml-412876577.md)

## Declarations

<a id="function-function-std-fmt-center-function-center-s-width-ch-std-fmt-ml-887357416"></a>
### center

```ml
function center(s, width, ch)
```

Centers a string within a given width.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `s` | `dynamic` | — | Value supplied for `s`. |
| `width` | `dynamic` | — | Value supplied for `width`. |
| `ch` | `dynamic` | — | Value supplied for `ch`. |


Source: `std/fmt.ml:66`

<a id="function-function-std-fmt-line-function-line-ch-width-std-fmt-ml-1807299147"></a>
### line

```ml
function line(ch, width)
```

Creates a horizontal line.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `ch` | `dynamic` | — | Value supplied for `ch`. |
| `width` | `dynamic` | — | Value supplied for `width`. |


Source: `std/fmt.ml:130`

<a id="function-function-std-fmt-padleft-function-padleft-s-width-ch-std-fmt-ml-1234037328"></a>
### padLeft

```ml
function padLeft(s, width, ch)
```

Pads a string on the left to a desired width.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `s` | `dynamic` | — | Value supplied for `s`. |
| `width` | `dynamic` | — | Value supplied for `width`. |
| `ch` | `dynamic` | — | Value supplied for `ch`. |


Source: `std/fmt.ml:36`

<a id="function-function-std-fmt-padright-function-padright-s-width-ch-std-fmt-ml-842685836"></a>
### padRight

```ml
function padRight(s, width, ch)
```

Pads a string on the right to a desired width.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `s` | `dynamic` | — | Value supplied for `s`. |
| `width` | `dynamic` | — | Value supplied for `width`. |
| `ch` | `dynamic` | — | Value supplied for `ch`. |


Source: `std/fmt.ml:51`

<a id="function-function-std-fmt-quote-function-quote-s-std-fmt-ml-1511859179"></a>
### quote

```ml
function quote(s)
```

Returns a JSON-like quoted string with minimal escaping.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `s` | `dynamic` | — | Value supplied for `s`. |


Source: `std/fmt.ml:84`

<a id="function-function-std-fmt-repeat-function-repeat-ch-count-std-fmt-ml-28025468"></a>
### repeat

```ml
function repeat(ch, count)
```

Repeats a string `ch` exactly `count` times.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `ch` | `dynamic` | — | Value supplied for `ch`. |
| `count` | `dynamic` | — | Number of items to process. |


Source: `std/fmt.ml:28`
