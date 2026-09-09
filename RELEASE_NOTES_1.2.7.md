# MiniLang Compiler 1.2.7

This release adds cross-platform ECDSA P-256 signature verification to the
shared MiniLang standard library. `std.crypto.ecdsa_p256.verify` hashes the
message with SHA-256 and verifies fixed-width raw public keys and signatures
through Windows CNG or OpenSSL 3 on Linux.

Both compiler repositories contain matching standard-library implementations,
documentation and positive/negative regression fixtures. The Python compiler,
self-hosted monolithic pipeline and self-hosted object pipeline produce
byte-identical Windows PE and Linux ELF images for the ECDSA fixture. The full
Python suite passes 145/145 tests and the self-hosted ported suite passes
136/136 tests.

Both CLI version switches and `MINILANG_VERSION` report 1.2.7.

Following existing Python compiler releases, GitHub publishes source archives
for this repository. Ready-to-run native Windows and Linux packages are
published by the matching MiniLangCompilerML release.
