# `std/cpu.ml`

[Home](README.md) · [Files](Files.md)

Provides the std cpu package.

Package: [`std.cpu`](Package-std-cpu-1015646110.md)

Reachable from entry: **no**

## Declarations

<a id="function-function-std-cpu-activefeatures-function-activefeatures-std-cpu-ml-774821314"></a>
### activeFeatures

```ml
function activeFeatures()
```

Return the feature mask currently used by runtime dispatch.


Source: `std/cpu.ml:42`

<a id="constant-constant-std-cpu-aes-ni-const-aes-ni-16-std-cpu-ml-222885170"></a>
### AES_NI

```ml
const AES_NI = 16
```

Stores the aes ni.


Source: `std/cpu.ml:30`

<a id="constant-constant-std-cpu-avx-const-avx-4-std-cpu-ml-2010030883"></a>
### AVX

```ml
const AVX = 4
```

Stores the avx.


Source: `std/cpu.ml:26`

<a id="constant-constant-std-cpu-avx2-const-avx2-8-std-cpu-ml-626354591"></a>
### AVX2

```ml
const AVX2 = 8
```

Stores the avx2.


Source: `std/cpu.ml:28`

<a id="function-function-std-cpu-features-function-features-std-cpu-ml-440708594"></a>
### features

```ml
function features()
```

Return capabilities detected once during process startup.


Source: `std/cpu.ml:37`

<a id="constant-constant-std-cpu-pclmulqdq-const-pclmulqdq-32-std-cpu-ml-1357320056"></a>
### PCLMULQDQ

```ml
const PCLMULQDQ = 32
```

Stores the pclmulqdq.


Source: `std/cpu.ml:32`

<a id="function-function-std-cpu-setdispatchmaskfortesting-function-setdispatchmaskfortesting-mask-std-cpu-ml-816780596"></a>
### setDispatchMaskForTesting

```ml
function setDispatchMaskForTesting(mask)
```

Restrict dispatch for differential tests and benchmarks. The mask cannot enable unsupported instructions. A negative value restores all detected features; the previous active mask is returned.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `mask` | `dynamic` | — | Value supplied for `mask`. |


Source: `std/cpu.ml:48`

<a id="constant-constant-std-cpu-sha-const-sha-64-std-cpu-ml-2038744909"></a>
### SHA

```ml
const SHA = 64
```

Stores the sha.


Source: `std/cpu.ml:34`

<a id="constant-constant-std-cpu-sse2-const-sse2-1-std-cpu-ml-918334046"></a>
### SSE2

```ml
const SSE2 = 1
```

Stores the sse2.


Source: `std/cpu.ml:22`

<a id="constant-constant-std-cpu-sse42-const-sse42-2-std-cpu-ml-1435193437"></a>
### SSE42

```ml
const SSE42 = 2
```

Stores the sse42.


Source: `std/cpu.ml:24`
