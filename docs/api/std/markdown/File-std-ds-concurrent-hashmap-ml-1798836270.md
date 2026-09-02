# `std/ds/concurrent_hashmap.ml`

[Home](README.md) · [Files](Files.md)

Provides the std ds concurrent_hashmap package.

Package: [`std.ds.concurrent_hashmap`](Package-std-ds-concurrent-hashmap-1876233881.md)

Reachable from entry: **no**

## Imports

- `std/threading.ml` as `threading` → [std/threading.ml](File-std-threading-ml-508437988.md)

## Declarations

<a id="constant-constant-std-ds-concurrent-hashmap-default-buckets-const-default-buckets-64-std-ds-concurrent-hashmap-ml-304108078"></a>
### DEFAULT_BUCKETS

```ml
const DEFAULT_BUCKETS = 64
```

A Lock-protected open-addressing hash map in the process-wide managed heap. Keys remain int/string/bytes; values may be arbitrary MiniLang object graphs.


Source: `std/ds/concurrent_hashmap.ml:13`

- [std.ds.concurrent_hashmap.Entry](Type-std-ds-concurrent-hashmap-entry-1600904835.md) — struct
- [std.ds.concurrent_hashmap.ThreadSafeHashMap](Type-std-ds-concurrent-hashmap-threadsafehashmap-551487914.md) — struct
