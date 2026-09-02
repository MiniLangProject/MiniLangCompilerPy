# `std/random.ml`

[Home](README.md) · [Files](Files.md)

Provides the std random package.

Package: [`std.random`](Package-std-random-1697424507.md)

Reachable from entry: **no**

## Declarations

<a id="function-function-std-random-choice-function-choice-rng-xs-std-random-ml-362850290"></a>
### choice

```ml
function choice(rng, xs)
```

Picks a random element from an array.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `rng` | `dynamic` | — | Value supplied for `rng`. |
| `xs` | `dynamic` | — | Value supplied for `xs`. |


Source: `std/random.ml:136`

<a id="constant-constant-std-random-default-seed-const-default-seed-1831565813-std-random-ml-1317203572"></a>
### DEFAULT_SEED

```ml
const DEFAULT_SEED = 1831565813
```

Stores the default seed.


Source: `std/random.ml:24`

- [std.random.RNG](Type-std-random-rng-1201142756.md) — struct
<a id="function-function-std-random-seeded-function-seeded-seed-std-random-ml-2021080487"></a>
### seeded

```ml
function seeded(seed)
```

Constructs a seeded RNG.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `seed` | `dynamic` | — | Value supplied for `seed`. |


Source: `std/random.ml:110`

<a id="function-function-std-random-shuffleinplace-function-shuffleinplace-rng-xs-std-random-ml-2030459042"></a>
### shuffleInPlace

```ml
function shuffleInPlace(rng, xs)
```

Shuffles an array in place using Fisher-Yates.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `rng` | `dynamic` | — | Value supplied for `rng`. |
| `xs` | `dynamic` | — | Value supplied for `xs`. |


Source: `std/random.ml:117`

<a id="constant-constant-std-random-u32-mask-const-u32-mask-4294967295-std-random-ml-450705152"></a>
### U32_MASK

```ml
const U32_MASK = 4294967295
```

Std.random Simple deterministic PRNG (xorshift32). - Deterministic across runs. - Not cryptographically secure.


Source: `std/random.ml:22`

<a id="constant-constant-std-random-u32-range-float-const-u32-range-float-4294967296-std-random-ml-1703609829"></a>
### U32_RANGE_FLOAT

```ml
const U32_RANGE_FLOAT = 4294967296.
```

Stores the u32 range float.


Source: `std/random.ml:26`
