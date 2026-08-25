<!--
Copyright 2026 Nils Kopal

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0
-->

# Native checksums, cryptography, and SIMD search

MiniLang exposes reusable public modules in `std` and keeps native hot paths
behind compiler/runtime intrinsics. Argument validation stays in the public
wrapper. Programs that do not use a checksum intrinsic do not include its
helper or lookup table. Search accelerates existing first-class builtins, whose
runtime entry points remain available under the established builtin model.

## Checksums

`std.checksum.crc32c` and `std.checksum.crc32` each provide:

- `compute(buffer)`
- `computeRange(buffer, offset, length)`
- `update(previous, buffer, offset, length)`
- `verify(buffer, expected)`
- `verifyRange(buffer, offset, length, expected)`

CRC-32C uses the reflected Castagnoli polynomial `0x82F63B78`
(`0x1EDC6F41` in normal form). CRC-32/IEEE uses the reflected polynomial
`0xEDB88320` (`0x04C11DB7` in normal form). Both use initial value
`0xFFFFFFFF`, reflected input/output, and final XOR `0xFFFFFFFF`.

CRC-32C dispatches to x64 SSE4.2 `CRC32` instructions, processing eight bytes
per main-loop iteration. The bit-compatible table implementation is selected
when SSE4.2 is unavailable or disabled. CRC-32/IEEE always uses its separate
table because the x86 `CRC32` instruction does not implement IEEE CRC-32.
Range and tag checks occur once before the allocation-free raw update loop.

## Cryptography

`std.crypto` provides SHA-256, SHA-384, HMAC-SHA-256, HMAC-SHA-384,
HKDF-SHA-256, HKDF-SHA-384, PBKDF2-HMAC-SHA-256,
PBKDF2-HMAC-SHA-384, X25519, secure random bytes,
`constantTimeEquals`, and best-effort `secureZero`.
`std.crypto.aes_gcm` provides AES-256-GCM `seal`/`open` and
`encrypt`/`decrypt`.

Cryptographic operations are delegated to Windows CNG (`bcrypt.dll`) or Linux
OpenSSL 3 (`libcrypto.so.3`) rather than application-level MiniLang loops. The
public API, validation and result layout are identical on both targets. AES-GCM accepts
exactly 32-byte keys, nonces from 12 through 16 bytes, and tags from 12 through
16 bytes. Decryption returns an error and wipes its temporary output when native
authentication fails, so unauthenticated plaintext is never returned.
Ciphertext, tag, nonce, AAD, or key changes therefore fail authentication.

X25519 uses CNG's `curve25519` provider on Windows and EVP raw X25519 keys on
Linux. The Windows bridge converts CNG's raw-secret byte order to RFC 7748
order; both backends clamp a temporary private-key copy and reject an all-zero
shared secret. Random bytes use CNG's system-preferred RNG or OpenSSL
`RAND_bytes`.

`pbkdf2Sha256(password, salt, iterations, length)` and
`pbkdf2Sha384(password, salt, iterations, length)` validate positive iteration
and output counts, then call CNG `BCryptDeriveKeyPBKDF2` or OpenSSL
`PKCS5_PBKDF2_HMAC`. Password and salt are byte arrays; callers remain
responsible for choosing a protocol-specific iteration count and wiping
caller-owned secret buffers.

Security boundaries:

- `constantTimeEquals` has no content-dependent early exit for equal-length
  byte arrays; a public length mismatch is rejected immediately.
- `secureZero` overwrites the supplied mutable byte buffer, but it cannot
  erase earlier language/runtime copies. Avoid unnecessary secret copies and
  wipe caller-owned key buffers as soon as possible.
- Errors never include keys, plaintext, derived secrets, or random material.
- Linux crypto images require an x64 OpenSSL 3 installation providing
  `libcrypto.so.3`; Windows uses the system-provided CNG library.
- Protocol-level nonce uniqueness, key rotation, transcript construction, and
  trust decisions remain the caller's responsibility.

## Search dispatch

Byte and byte-indexed string `indexOf`/`lastIndexOf` use AVX2 candidate
scans in 32-byte blocks, SSE2 scans in 16-byte blocks, or a scalar fallback.
A candidate is confirmed by the existing exact memory comparison, so multi-byte
patterns and overlapping reverse matches preserve previous semantics.
`startsWith`, `endsWith`, and equality continue using the SIMD memory
comparison path. Empty patterns, clamped start positions, embedded zero bytes,
and invalid argument behavior remain unchanged.

## CPU features and testing

`std.cpu` publishes these flags: `SSE2`, `SSE42`, `AVX`, `AVX2`,
`AES_NI`, `PCLMULQDQ`, and `SHA`. Detection runs once during process
startup. AVX and AVX2 are active only when CPUID and XGETBV confirm OS support
for XMM/YMM state.

`features()` returns detected capabilities and `activeFeatures()` returns
the current dispatch mask. `setDispatchMaskForTesting(mask)` can only remove
detected features; passing `-1` restores them. It exists for deterministic
fallback tests and benchmarks, not for application feature spoofing.

The focused suites are `tests/checksum_runtime.ml`,
`tests/crypto_cng.ml`, and `tests/simd_search.ml`. Reproducible diagnostic
benchmarks and comparison guidance are in `benchmarks/`.
