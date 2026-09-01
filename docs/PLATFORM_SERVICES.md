<!--
Copyright 2026 Nils Kopal

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0
-->

# Platform services

MiniLang exposes the same application-facing system interfaces on
`windows-x64` and `linux-x64`. The modules select native Win32 or POSIX/glibc
operations at compile time. Existing Windows projects remain source-compatible:
`windows-x64` is still the default target and no new library is linked unless a
source module imports it.

## Platform, paths, processes and consoles

- `std.platform` reports the target OS and architecture plus path separators,
  line endings and executable/shared-library extensions.
- `std.path` provides target-aware absolute-path detection, joining, file and
  directory names, extensions and extension replacement. These functions are
  lexical and do not touch the filesystem.
- `std.process` provides the process ID, environment lookup, current directory
  lookup and current-directory changes.
- `std.console` detects interactive input, disables Windows QuickEdit when
  requested, and reads echo-free secrets or confirmed passwords. Linux secret
  input uses `getpass`; the native temporary buffer is explicitly wiped before
  returning. Call `wipe` on caller-owned secret byte arrays after use.

## Durable random-access files

`std.io.file` complements the convenience-oriented `std.fs` module. Its
`FileHandle` supports positional `readAt`, `readExactAt` and `writeAt`, append,
size, truncate, explicit flush and close. Durable open/create variants request
write-through semantics. Windows uses `CreateFileW`, `FlushFileBuffers`,
`LockFileEx` and `MoveFileExW`; Linux uses `open`, `pread`, `pwrite`, `fsync`,
`flock` and `rename`.

`lock(file, mode, wait)` takes a whole-file advisory shared or exclusive lock.
A non-blocking conflict returns error code `264`. Every participant must obey
the advisory-lock protocol. On Windows, cursor-based operations on one handle
are serialized by the caller; servers should use separate handles per worker.

`atomicMove` atomically replaces a path within the guarantees of the host
filesystem. For durable metadata updates, flush the file, perform the move and
then call `syncDirectory` on the containing directory. `readAllBytes` and
`readAllText` require an explicit maximum size to prevent accidental unbounded
allocations.

## Networking and TLS

`std.net` now exposes reusable-address, keepalive, TCP no-delay and send/receive
timeout options. `tcpListenAddress(host, port, backlog)` binds an explicit IPv4
address; `tcpListen` keeps its established all-interface behavior. Public TCP
and UDP helpers accept ports from `0` through `65535` and reject values outside
that range. TCP listeners and bound UDP sockets request exclusive port ownership
on Windows to avoid cross-process traffic routing; Linux TCP listeners retain
`SO_REUSEADDR` restart semantics. Explicit `setReuseAddress` calls remain
available to applications.

`std.tls` includes a native provider selected at compile time: Windows uses
Schannel and the system certificate stores; Linux uses OpenSSL 3
(`libssl.so.3` and `libcrypto.so.3`). `nativeProviderName()` reports the active
backend. The callback-based `provider(...)`, `connectClient(...)` and
`acceptServer(...)` contract remains available for application-specific
transports, while normal applications use `connect(socket, options)` and
`accept(socket, options)`.

Client options default to TLS 1.3, system trust and mandatory DNS-name
verification. The minimum may be changed to TLS 1.2. A 32-byte SHA-256 leaf
certificate pin is an additional fail-closed check; pinning cannot disable peer
verification. Linux optionally accepts a PEM CA bundle through `caFile`.
Schannel intentionally rejects `caFile`; install that CA in a Windows store or
use a leaf pin. Neither backend silently falls back below the configured
minimum.

Linux server options are PEM certificate-chain and private-key paths. Windows
accepts `store:<SHA1-thumbprint>` (searched in CurrentUser and LocalMachine
`MY`) or `pfx:<path>`. A PFX password is read from
`MINILANG_TLS_PFX_PASSWORD`; alternatively set `privateKeyReference` to
`env:VARIABLE_NAME`. Secret buffers and imported PFX payloads are wiped during
release. `requireClientCertificate` requests native client-certificate
validation.

TLS streams own their native security context, but never own the TCP socket.
Call `shutdown(stream)` to send `close_notify`, then `close(stream)`, and
finally `std.net.close(socket)`. `sendAll` handles partial provider writes and
`receive` returns empty bytes after a clean peer shutdown.

## Identifiers and password derivation

`std.uuid` creates RFC 4122 version-4 UUIDs with `std.crypto.secureRandom` and
provides byte/string format, parse and validation helpers. `std.crypto` adds
PBKDF2-HMAC-SHA-256 and PBKDF2-HMAC-SHA-384 backed by Windows CNG or OpenSSL 3.

## Target diagnostics and testing

An unguarded Windows `.dll` import is a compile error for `--target linux-x64`.
Use conditional compilation around platform-specific providers. The shared
`tests/platform_services.ml` acceptance fixture exercises both native targets,
including PBKDF2 vectors, UUIDs, socket options, durable file operations,
advisory lock conflicts and the TLS provider lifecycle. Run
`tests/run_tls_native.ps1 -Compiler <compiler>` with WSL/OpenSSL installed for
real positive and wrong-hostname Schannel/OpenSSL client/server handshakes.
