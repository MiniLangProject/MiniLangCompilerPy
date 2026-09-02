# `std/threading.ml`

[Home](README.md) · [Files](Files.md)

Provides the std threading package.

Package: [`std.threading`](Package-std-threading-978326764.md)

Reachable from entry: **no**

## Declarations

- [std.threading.Event](Type-std-threading-event-883500562.md) — struct
<a id="constant-constant-std-threading-infinite-const-infinite-4294967295-std-threading-ml-1276851716"></a>
### INFINITE

```ml
const INFINITE = 4294967295
```

Stores the infinite.


Source: `std/threading.ml:29`

- [std.threading.Lock](Type-std-threading-lock-164120817.md) — struct
<a id="constant-constant-std-threading-max-native-semaphore-count-const-max-native-semaphore-count-2147483647-std-threading-ml-1785319903"></a>
### MAX_NATIVE_SEMAPHORE_COUNT

```ml
const MAX_NATIVE_SEMAPHORE_COUNT = 2147483647
```

Stores the max native semaphore count.


Source: `std/threading.ml:18`

<a id="constant-constant-std-threading-max-portable-timeout-ms-const-max-portable-timeout-ms-2147483647-std-threading-ml-371616799"></a>
### MAX_PORTABLE_TIMEOUT_MS

```ml
const MAX_PORTABLE_TIMEOUT_MS = 2147483647
```

Native timeout/count parameters are signed 32-bit values on at least one supported target. Keeping the shared API inside this range avoids truncation and platform-dependent interpretations of the high bit.


Source: `std/threading.ml:16`

- [std.threading.Semaphore](Type-std-threading-semaphore-750847000.md) — struct
<a id="constant-constant-std-threading-wait-abandoned-const-wait-abandoned-128-std-threading-ml-991282822"></a>
### WAIT_ABANDONED

```ml
const WAIT_ABANDONED = 128
```

Stores the wait abandoned.


Source: `std/threading.ml:25`

<a id="constant-constant-std-threading-wait-object-0-const-wait-object-0-0-std-threading-ml-2017049799"></a>
### WAIT_OBJECT_0

```ml
const WAIT_OBJECT_0 = 0
```

Native Win32 synchronization primitives. All MiniLang objects live in the process-wide managed heap; these handles serialize access between the OS threads and their private stacks. Close only after users/waiters have stopped.


Source: `std/threading.ml:23`

<a id="constant-constant-std-threading-wait-timeout-const-wait-timeout-258-std-threading-ml-955567050"></a>
### WAIT_TIMEOUT

```ml
const WAIT_TIMEOUT = 258
```

Stores the wait timeout.


Source: `std/threading.ml:27`
