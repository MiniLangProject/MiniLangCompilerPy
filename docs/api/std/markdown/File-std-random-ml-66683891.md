# `std/random.ml`

[Home](README.md) · [Files](Files.md)

Provides deterministic or securely auto-seeded non-cryptographic generators.

Package: [`std.random`](Package-std-random-1697424507.md)

Reachable from entry: **no**

## Imports

- `std/crypto.ml` as `crypto` → [std/crypto.ml](File-std-crypto-ml-1263151193.md)

## Declarations

<a id="function-function-std-random-autoseeded-function-autoseeded-std-random-ml-320500032"></a>
### autoSeeded

```ml
function autoSeeded()
```

Create an independent RNG seeded by the platform's secure random provider. Returns RNG on success; provider errors propagate and can be caught with try. The generated sequence is still non-cryptographic; use std.crypto.secureRandom for secrets. Linux requires OpenSSL 3. Do not share a mutable RNG across threads without synchronization; normally create one instance per thread.


Source: `std/random.ml:135`

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


Source: `std/random.ml:161`

<a id="constant-constant-std-random-default-seed-const-default-seed-1831565813-std-random-ml-1317203572"></a>
### DEFAULT_SEED

```ml
const DEFAULT_SEED = 1831565813
```

Track the default seed value used by this standard-library module.


Source: `std/random.ml:25`

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


Source: `std/random.ml:111`

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


Source: `std/random.ml:142`

<a id="constant-constant-std-random-u32-mask-const-u32-mask-4294967295-std-random-ml-450705152"></a>
### U32_MASK

```ml
const U32_MASK = 4294967295
```

Std.random Simple deterministic PRNG (xorshift32). - Deterministic across runs. - Not cryptographically secure.


Source: `std/random.ml:23`

<a id="constant-constant-std-random-u32-range-float-const-u32-range-float-4294967296-std-random-ml-1703609829"></a>
### U32_RANGE_FLOAT

```ml
const U32_RANGE_FLOAT = 4294967296.
```

Track the u32 range float value used by this standard-library module.


Source: `std/random.ml:27`
