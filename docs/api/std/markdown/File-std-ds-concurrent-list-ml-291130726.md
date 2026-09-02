# `std/ds/concurrent_list.ml`

[Home](README.md) · [Files](Files.md)

Provides the std ds concurrent_list package.

Package: [`std.ds.concurrent_list`](Package-std-ds-concurrent-list-265784845.md)

Reachable from entry: **no**

## Imports

- `std/threading.ml` as `threading` → [std/threading.ml](File-std-threading-ml-508437988.md)

## Declarations

<a id="constant-constant-std-ds-concurrent-list-default-capacity-const-default-capacity-8-std-ds-concurrent-list-ml-1439213488"></a>
### DEFAULT_CAPACITY

```ml
const DEFAULT_CAPACITY = 8
```

A growable list whose managed backing array lives in the process-wide GC heap. Every public operation is serialized by a recursive Lock, so arbitrary MiniLang values (including arrays and structs) retain identity across threads.


Source: `std/ds/concurrent_list.ml:13`

- [std.ds.concurrent_list.ThreadSafeList](Type-std-ds-concurrent-list-threadsafelist-78742376.md) — struct
