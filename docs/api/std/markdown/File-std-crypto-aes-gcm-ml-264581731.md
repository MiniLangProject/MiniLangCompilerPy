# `std/crypto/aes_gcm.ml`

[Home](README.md) · [Files](Files.md)

Provides the std crypto aes_gcm package.

Package: [`std.crypto.aes_gcm`](Package-std-crypto-aes-gcm-1236376730.md)

Reachable from entry: **no**

## Imports

- `std/crypto/_cng.ml` as `cng` → [std/crypto/_cng.ml](File-std-crypto-cng-ml-1099901917.md)

## Declarations

<a id="constant-constant-std-crypto-aes-gcm-aes-gcm-err-const-aes-gcm-err-241-std-crypto-aes-gcm-ml-66145333"></a>
### AES_GCM_ERR

```ml
const AES_GCM_ERR = 241
```

Stores the aes gcm err.


Source: `std/crypto/aes_gcm.ml:27`

<a id="function-function-std-crypto-aes-gcm-decrypt-function-decrypt-key-nonce-ciphertext-tag-aad-std-crypto-aes-gcm-ml-485061609"></a>
### decrypt

```ml
function decrypt(key, nonce, ciphertext, tag, aad)
```

Convenience API accepting separate ciphertext and tag values.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `key` | `dynamic` | — | Value supplied for `key`. |
| `nonce` | `dynamic` | — | Value supplied for `nonce`. |
| `ciphertext` | `dynamic` | — | Value supplied for `ciphertext`. |
| `tag` | `dynamic` | — | Value supplied for `tag`. |
| `aad` | `dynamic` | — | Value supplied for `aad`. |


Source: `std/crypto/aes_gcm.ml:107`

<a id="function-function-std-crypto-aes-gcm-encrypt-function-encrypt-key-nonce-plaintext-aad-taglength-std-crypto-aes-gcm-ml-125820132"></a>
### encrypt

```ml
function encrypt(key, nonce, plaintext, aad, tagLength)
```

Convenience API returning separate ciphertext and tag fields.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `key` | `dynamic` | — | Value supplied for `key`. |
| `nonce` | `dynamic` | — | Value supplied for `nonce`. |
| `plaintext` | `dynamic` | — | Value supplied for `plaintext`. |
| `aad` | `dynamic` | — | Value supplied for `aad`. |
| `tagLength` | `dynamic` | — | Value supplied for `tagLength`. |


Source: `std/crypto/aes_gcm.ml:94`

- [std.crypto.aes_gcm.Encrypted](Type-std-crypto-aes-gcm-encrypted-938521788.md) — struct
<a id="function-function-std-crypto-aes-gcm-open-function-open-key-nonce-sealed-aad-taglength-std-crypto-aes-gcm-ml-1220352403"></a>
### open

```ml
function open(key, nonce, sealed, aad, tagLength)
```

Authenticate and decrypt ciphertext||tag. Authentication failure returns an error and the temporary plaintext buffer is wiped before it can escape.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `key` | `dynamic` | — | Value supplied for `key`. |
| `nonce` | `dynamic` | — | Value supplied for `nonce`. |
| `sealed` | `dynamic` | — | Value supplied for `sealed`. |
| `aad` | `dynamic` | — | Value supplied for `aad`. |
| `tagLength` | `dynamic` | — | Value supplied for `tagLength`. |


Source: `std/crypto/aes_gcm.ml:77`

<a id="function-function-std-crypto-aes-gcm-seal-function-seal-key-nonce-plaintext-aad-taglength-std-crypto-aes-gcm-ml-1614549846"></a>
### seal

```ml
function seal(key, nonce, plaintext, aad, tagLength)
```

Encrypt with AES-256-GCM and return ciphertext||tag.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `key` | `dynamic` | — | Value supplied for `key`. |
| `nonce` | `dynamic` | — | Value supplied for `nonce`. |
| `plaintext` | `dynamic` | — | Value supplied for `plaintext`. |
| `aad` | `dynamic` | — | Value supplied for `aad`. |
| `tagLength` | `dynamic` | — | Value supplied for `tagLength`. |


Source: `std/crypto/aes_gcm.ml:59`
