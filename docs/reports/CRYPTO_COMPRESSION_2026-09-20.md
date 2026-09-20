<!--
Copyright 2026 Nils Kopal

Licensed under the Apache License, Version 2.0 (the "License");
-->

# Crypto throughput and portable compression (2026-09-20)

## Outcome

The standard library now has one-shot, dependency-free `std.compress` APIs on
Windows x64 and Linux x64. `fast` chooses standard LZ4 block encoding or raw
bytes; `compact` additionally evaluates a MiniLang byte-run codec. The
`MLC1` container records algorithm, original size, and CRC-32C. Decompression
requires an explicit maximum output size. Raw LZ4 blocks interoperate in both
directions with upstream liblz4; the container and RLE format are MiniLang
specific.

The crypto review found that Windows CNG opened and closed a hash algorithm
provider on every SHA/HMAC call. The one-shot path now uses Windows 10+
algorithm pseudo-handles; large-buffer crypto paths and Linux OpenSSL behavior
are unchanged. Existing known-answer and authentication tests remain in place,
with an additional eight-worker concurrent SHA/HMAC test.

## Measurements

Host: AMD Ryzen 9 9900X; Windows x64 and Ubuntu/glibc 2.39 under WSL2
(kernel 6.6.87.2). The benchmark uses `std.time.ticks()`, whose effective
Windows resolution is coarse for sub-20-ms phases. Results below are medians
of five separate processes on the same host; the post-change small-message
CNG check uses nine processes. Throughput is logical input MiB divided by
timed interval, not disk or network throughput.

| Operation | Windows | Linux/WSL2 |
| --- | ---: | ---: |
| SHA-256, 1 MiB | 2,723 MiB/s | 2,510 MiB/s |
| SHA-384, 1 MiB | 911 MiB/s | 1,463 MiB/s |
| AES-256-GCM seal, 1 MiB | 8,258 MiB/s | 9,846 MiB/s |
| AES-256-GCM open, 1 MiB | 8,258 MiB/s | 12,800 MiB/s |
| LZ4 fast, 1 MiB repeated, compress | 141 MiB/s | 135 MiB/s |
| LZ4 fast, 1 MiB repeated, decompress | 7,288 MiB/s | 6,671 MiB/s |
| LZ4 fast, 1 MiB patterned, compress | 136 MiB/s | 137 MiB/s |
| LZ4 fast, 1 MiB patterned, decompress | 6,244 MiB/s | 6,244 MiB/s |
| Fast mode, 1 MiB random-like, raw fallback | 2,065 MiB/s | 1,882 MiB/s |
| Compact mode, 1 MiB random-like, raw fallback | 49 MiB/s | 50 MiB/s |

Windows SHA-256 and HMAC-SHA-256 on 1-KiB inputs each took a median 31 ms
for 20,000 calls before pseudo-handles and 15 ms afterwards. The direction is
clear, but the 15-ms timer quantum makes an exact percentage misleading.
Large SHA-256 throughput remained about 2.7 GiB/s. AES-GCM did not change.
Linux OpenSSL SHA-256 measured about 1,221 MiB/s for 1-KiB calls, and HMAC
about 723 MiB/s; these are backend/OS observations, not a controlled
Windows-versus-Linux speed contest.

Additional five-run medians complete the public crypto API profile:

| Operation | Windows | Linux/WSL2 |
| --- | ---: | ---: |
| HMAC-SHA-384, 1 KiB | 416 MiB/s | 488 MiB/s |
| HKDF-SHA-256, 64-byte output | ~625,000 ops/s | ~312,500 ops/s |
| HKDF-SHA-384, 64-byte output | ~323,000 ops/s | ~227,000 ops/s |
| PBKDF2-SHA-256, 10,000 rounds | 681 ops/s | 696 ops/s |
| PBKDF2-SHA-384, 10,000 rounds | 164 ops/s | 342 ops/s |
| X25519 public-key derivation | 8,000 ops/s | 50,000 ops/s |
| X25519 agreement | 5,319 ops/s | 23,810 ops/s |
| ECDSA-P256/SHA-256 verification | 10,638 ops/s | 25,000 ops/s |
| Constant-time equality, 1 MiB | 3,282 MiB/s | 3,048 MiB/s |
| Secure random, 1 MiB | 5,447 MiB/s | 7,314 MiB/s |

The 10,000-call HKDF cases are close to the Windows timer quantum and are
only approximate. Repeated `secureZero` on a cache-resident 1-MiB buffer
completed below useful timer resolution; this benchmark does not assign it a
credible throughput number. CNG's X25519/key-import paths are a notable
remaining per-operation cost; optimizing them would need a separately
validated native-handle lifetime design. PBKDF2 speed depends deliberately
on the selected iteration count and provider.

The repeated 1-MiB fixture shrank to 4,138 bytes (including 16-byte MLC1
header), the patterned fixture to 5,897 bytes, and random-like input stayed
raw at 1,048,592 bytes. Two less synthetic raw LZ4 checks: the 309,858-byte
self-hosted compiler source `mlc/compiler.ml` became 106,488 bytes (34.4%);
its 140,388-byte README became 79,629 bytes (56.7%). LZ4 prioritizes speed,
not the highest possible compression ratio. The `compact` mode can cost
substantially more CPU because it tries both codecs; choose `fast` for
latency-sensitive paths. A 1-MiB fast decode is dominated by native bulk
copies and CRC verification after match-copy expansion was made logarithmic
in the run length.

## Correctness and compatibility

- Codec tests cover empty/tiny/64-KiB/1-MiB/8-MiB buffers, overlap copies,
  exact-size output, raw fallback, RLE selection, corrupt checksums, invalid
  headers, truncated lengths/offsets, output caps, and 512 deterministic
  malformed-block inputs per decoder.
- The optional `tests/compression_interop.py` verifies both directions
  against upstream `liblz4` on four input classes, using a program compiled
  by each compiler. No liblz4 dependency is introduced into generated apps.
- Windows PE and Linux ELF compression tests and benchmarks built by the
  Python and self-hosted compilers have matching SHA-256 per target. The
  final benchmark PE is
  `67BFE544B363542955E348897AC744A62761F49A3D4CB0A306894CCAB52D041D`;
  the ELF is
  `2BAADD1EC2BF6F7C139FC1E4D3067FDCFD5203F4EC35FE1D92941984787A5276`.
  The standard-library source files are kept identical between repositories.
- A 309,858-byte real source file produced the exact same 106,504-byte
  `MLC1` container in all four combinations (Python/self-hosted times
  Windows/Linux), SHA-256
  `EBD6870E692C6D5750FBE889A8B43B9BD2640F860C71CB13CF4E14FE71F5570F`.
  A Windows build decoded the Linux output and a Linux build decoded the
  Windows output.
- CRC-32C is an accidental-corruption check, not a MAC. Never use it as
  authentication. LZ4 raw block decoders need a trusted exact-size bound;
  `std.compress.decompress(container, maxOutputBytes)` always enforces a
  caller-supplied cap.
- The API is one-shot and retains input and output in memory; streaming
  compression and high-ratio zstd/DEFLATE are not part of this change.

The full Python compiler suite passed 151/151 with no skips. The self-hosted
PowerShell suite completed successfully in 221.203 seconds, including the new
Windows/Linux compression fixtures. MiniDoc regenerated documentation for
51 standard-library modules (1,768 symbols, zero warnings). All 51 module
sources match after line-ending normalization; all 319 generated API files
match byte-for-byte across the repositories.

Reproduce with `benchmarks/crypto_compression.ml`, and run
`tests/compression_codecs.ml`, `tests/crypto_cng.ml`, and
`tests/compression_interop.py` after compiling its MiniLang fixture.
Format reference:
[upstream LZ4 block specification](https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md).
Windows hash-provider guidance:
[BCryptOpenAlgorithmProvider](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptopenalgorithmprovider)
and [CNG pseudo-handles](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-algorithm-pseudo-handles).
