# `std.random.RNG`

[Home](README.md) · [Source file](File-std-random-ml-66683891.md)

<a id="struct-struct-std-random-rng-struct-rng-std-random-ml-963688333"></a>
## RNG

```ml
struct RNG
```

Deterministic per-instance pseudorandom number generator.


Source: `std/random.ml:29`

## Members

<a id="method-method-std-random-rng-nextbool-function-nextbool-std-random-ml-792594308"></a>
### nextBool

```ml
function nextBool()
```

Generates a random boolean.


Source: `std/random.ml:83`

<a id="method-method-std-random-rng-nextfloat-function-nextfloat-std-random-ml-266740162"></a>
### nextFloat

```ml
function nextFloat()
```

Generates a float in [0, 1).


Source: `std/random.ml:77`

<a id="method-method-std-random-rng-nextint-function-nextint-maxexclusive-std-random-ml-549682610"></a>
### nextInt

```ml
function nextInt(maxExclusive)
```

Generates an integer in [0, maxExclusive).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `maxExclusive` | `dynamic` | — | Value supplied for `maxExclusive`. |


Source: `std/random.ml:66`

<a id="method-method-std-random-rng-nextu32-function-nextu32-std-random-ml-1111191742"></a>
### nextU32

```ml
function nextU32()
```

Generates the next 32-bit unsigned value.


Source: `std/random.ml:55`

<a id="method-method-std-random-rng-rangefloat-function-rangefloat-mininclusive-maxexclusive-std-random-ml-375016824"></a>
### rangeFloat

```ml
function rangeFloat(minInclusive, maxExclusive)
```

Generates a float in [minInclusive, maxExclusive).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `minInclusive` | `dynamic` | — | Value supplied for `minInclusive`. |
| `maxExclusive` | `dynamic` | — | Value supplied for `maxExclusive`. |


Source: `std/random.ml:103`

<a id="method-method-std-random-rng-rangeint-function-rangeint-mininclusive-maxexclusive-std-random-ml-1648743864"></a>
### rangeInt

```ml
function rangeInt(minInclusive, maxExclusive)
```

Generates an integer in [minInclusive, maxExclusive).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `minInclusive` | `dynamic` | — | Value supplied for `minInclusive`. |
| `maxExclusive` | `dynamic` | — | Value supplied for `maxExclusive`. |


Source: `std/random.ml:90`

<a id="static_method-static-method-std-random-rng-seed-static-function-seed-seed-std-random-ml-1525826490"></a>
### Seed

```ml
static function Seed(seed)
```

Creates a deterministic RNG from a seed.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `seed` | `dynamic` | — | Value supplied for `seed`. |


Source: `std/random.ml:35`

<a id="field-field-std-random-rng-state-state-std-random-ml-225453968"></a>
### state

```ml
state
```

Stores the state member of `RNG`.


Source: `std/random.ml:31`
