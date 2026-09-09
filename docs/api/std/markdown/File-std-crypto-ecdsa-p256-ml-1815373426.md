# `std/crypto/ecdsa_p256.ml`

[Home](README.md) · [Files](Files.md)

Provides ECDSA-P256 signature verification backed by the platform crypto provider.

Package: [`std.crypto.ecdsa_p256`](Package-std-crypto-ecdsa-p256-1946688473.md)

Reachable from entry: **no**

## Imports

- `std/crypto.ml` as `crypto` → [std/crypto.ml](File-std-crypto-ml-1263151193.md)
- `std/crypto/_cng.ml` as `backend` → [std/crypto/_cng.ml](File-std-crypto-cng-ml-1099901917.md)

## Declarations

<a id="constant-constant-std-crypto-ecdsa-p256-ecdsa-p256-err-const-ecdsa-p256-err-242-std-crypto-ecdsa-p256-ml-403266780"></a>
### ECDSA_P256_ERR

```ml
const ECDSA_P256_ERR = 242
```

Error code returned for invalid ECDSA-P256 arguments or backend failures.


Source: `std/crypto/ecdsa_p256.ml:29`

<a id="function-function-std-crypto-ecdsa-p256-verify-function-verify-publickey-message-signature-std-crypto-ecdsa-p256-ml-1397114268"></a>
### verify

```ml
function verify(publicKey, message, signature)
```

Verify a SHA-256 ECDSA-P256 signature. Public keys use the 64-byte big-endian X||Y representation. Signatures use the fixed-width 64-byte IEEE-P1363 r||s representation.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `publicKey` | `dynamic` | — | Raw P-256 public key. |
| `message` | `dynamic` | — | Message whose signature is checked. |
| `signature` | `dynamic` | — | Raw IEEE-P1363 signature. |


Source: `std/crypto/ecdsa_p256.ml:37`
