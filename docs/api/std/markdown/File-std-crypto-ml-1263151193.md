# `std/crypto.ml`

[Home](README.md) · [Files](Files.md)

Provides the std crypto package.

Package: [`std.crypto`](Package-std-crypto-59860101.md)

Reachable from entry: **no**

## Imports

- `std/crypto/_cng.ml` as `cng` → [std/crypto/_cng.ml](File-std-crypto-cng-ml-1099901917.md)

## Declarations

<a id="function-function-std-crypto-constanttimeequals-function-constanttimeequals-a-b-std-crypto-ml-1925949949"></a>
### constantTimeEquals

```ml
function constantTimeEquals(a, b)
```

Compare two bytes values without content-dependent early exits.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | First input value. |
| `b` | `dynamic` | — | Second input value. |


Source: `std/crypto.ml:148`

<a id="constant-constant-std-crypto-crypto-err-const-crypto-err-240-std-crypto-ml-407979147"></a>
### CRYPTO_ERR

```ml
const CRYPTO_ERR = 240
```

Stores the crypto err.


Source: `std/crypto.ml:27`

<a id="function-function-std-crypto-hkdfsha256-function-hkdfsha256-inputkeymaterial-salt-info-length-std-crypto-ml-1740727018"></a>
### hkdfSha256

```ml
function hkdfSha256(inputKeyMaterial, salt, info, length)
```

RFC-5869 HKDF-SHA-256 (extract and expand).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `inputKeyMaterial` | `dynamic` | — | Value supplied for `inputKeyMaterial`. |
| `salt` | `dynamic` | — | Value supplied for `salt`. |
| `info` | `dynamic` | — | Value supplied for `info`. |
| `length` | `dynamic` | — | Number of elements or bytes to process. |


Source: `std/crypto.ml:94`

<a id="function-function-std-crypto-hkdfsha384-function-hkdfsha384-inputkeymaterial-salt-info-length-std-crypto-ml-1751700406"></a>
### hkdfSha384

```ml
function hkdfSha384(inputKeyMaterial, salt, info, length)
```

RFC-5869 HKDF-SHA-384 (extract and expand).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `inputKeyMaterial` | `dynamic` | — | Value supplied for `inputKeyMaterial`. |
| `salt` | `dynamic` | — | Value supplied for `salt`. |
| `info` | `dynamic` | — | Value supplied for `info`. |
| `length` | `dynamic` | — | Number of elements or bytes to process. |


Source: `std/crypto.ml:103`

<a id="function-function-std-crypto-hmacsha256-function-hmacsha256-key-input-std-crypto-ml-689688099"></a>
### hmacSha256

```ml
function hmacSha256(key, input)
```

Compute HMAC-SHA-256 through the platform crypto backend.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `key` | `dynamic` | — | Value supplied for `key`. |
| `input` | `dynamic` | — | Value supplied for `input`. |


Source: `std/crypto.ml:56`

<a id="function-function-std-crypto-hmacsha384-function-hmacsha384-key-input-std-crypto-ml-1206696471"></a>
### hmacSha384

```ml
function hmacSha384(key, input)
```

Compute HMAC-SHA-384 through the platform crypto backend.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `key` | `dynamic` | — | Value supplied for `key`. |
| `input` | `dynamic` | — | Value supplied for `input`. |


Source: `std/crypto.ml:66`

<a id="function-function-std-crypto-pbkdf2sha256-function-pbkdf2sha256-password-salt-iterations-length-std-crypto-ml-1283186663"></a>
### pbkdf2Sha256

```ml
function pbkdf2Sha256(password, salt, iterations, length)
```

Derive key material using PBKDF2-HMAC-SHA-256.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `password` | `dynamic` | — | Value supplied for `password`. |
| `salt` | `dynamic` | — | Value supplied for `salt`. |
| `iterations` | `dynamic` | — | Value supplied for `iterations`. |
| `length` | `dynamic` | — | Number of elements or bytes to process. |


Source: `std/crypto.ml:123`

<a id="function-function-std-crypto-pbkdf2sha384-function-pbkdf2sha384-password-salt-iterations-length-std-crypto-ml-2002863367"></a>
### pbkdf2Sha384

```ml
function pbkdf2Sha384(password, salt, iterations, length)
```

Derive key material using PBKDF2-HMAC-SHA-384.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `password` | `dynamic` | — | Value supplied for `password`. |
| `salt` | `dynamic` | — | Value supplied for `salt`. |
| `iterations` | `dynamic` | — | Value supplied for `iterations`. |
| `length` | `dynamic` | — | Number of elements or bytes to process. |


Source: `std/crypto.ml:132`

<a id="function-function-std-crypto-securerandom-function-securerandom-length-std-crypto-ml-287450256"></a>
### secureRandom

```ml
function secureRandom(length)
```

Obtain cryptographically secure random bytes from the platform provider.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `length` | `dynamic` | — | Number of elements or bytes to process. |


Source: `std/crypto.ml:138`

<a id="function-function-std-crypto-securezero-function-securezero-buffer-std-crypto-ml-1706379390"></a>
### secureZero

```ml
function secureZero(buffer)
```

Best-effort in-place erasure. MiniLang's native fill helper performs the observable write, but callers must still avoid prior copies of key material.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `buffer` | `dynamic` | — | Buffer to process. |


Source: `std/crypto.ml:155`

<a id="function-function-std-crypto-sha256-function-sha256-input-std-crypto-ml-2117608982"></a>
### sha256

```ml
function sha256(input)
```

Compute SHA-256 through the platform crypto backend.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `input` | `dynamic` | — | Value supplied for `input`. |


Source: `std/crypto.ml:37`

<a id="function-function-std-crypto-sha384-function-sha384-input-std-crypto-ml-534054486"></a>
### sha384

```ml
function sha384(input)
```

Compute SHA-384 through the platform crypto backend.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `input` | `dynamic` | — | Value supplied for `input`. |


Source: `std/crypto.ml:46`

<a id="function-function-std-crypto-x25519-function-x25519-privatekey-peerpublickey-std-crypto-ml-1569573420"></a>
### x25519

```ml
function x25519(privateKey, peerPublicKey)
```

Derive an X25519 shared secret. CNG errors and all-zero weak results are rejected without returning secret bytes.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `privateKey` | `dynamic` | — | Value supplied for `privateKey`. |
| `peerPublicKey` | `dynamic` | — | Value supplied for `peerPublicKey`. |


Source: `std/crypto.ml:173`

<a id="function-function-std-crypto-x25519publickey-function-x25519publickey-privatekey-std-crypto-ml-664480438"></a>
### x25519PublicKey

```ml
function x25519PublicKey(privateKey)
```

Derive the RFC-7748 public key for a 32-byte X25519 private scalar.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `privateKey` | `dynamic` | — | Value supplied for `privateKey`. |


Source: `std/crypto.ml:163`
