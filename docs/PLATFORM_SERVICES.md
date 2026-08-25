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
address; `tcpListen` keeps its established all-interface behavior.

`std.tls` is a provider-neutral stream contract, not a bundled TLS engine. A
provider supplies client/server handshake, send, receive, shutdown and close
callbacks. This lets applications put an existing Windows Schannel adapter and
a Linux OpenSSL adapter behind one API without forcing new DLL dependencies on
Windows programs. Certificate loading, trust policy, hostname verification and
protocol configuration remain provider responsibilities.

## Identifiers and password derivation

`std.uuid` creates RFC 4122 version-4 UUIDs with `std.crypto.secureRandom` and
provides byte/string format, parse and validation helpers. `std.crypto` adds
PBKDF2-HMAC-SHA-256 and PBKDF2-HMAC-SHA-384 backed by Windows CNG or OpenSSL 3.

## Target diagnostics and testing

An unguarded Windows `.dll` import is a compile error for `--target linux-x64`.
Use conditional compilation around platform-specific providers. The shared
`tests/platform_services.ml` acceptance fixture exercises both native targets,
including PBKDF2 vectors, UUIDs, socket options, durable file operations,
advisory lock conflicts and the TLS provider lifecycle.
