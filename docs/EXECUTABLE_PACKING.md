# Dependency-free executable packing

Both compilers provide the same built-in packer for their Windows x64 PE and
Linux x64 ELF output. `--pack` needs no UPX installation, external executable,
or compression library at build or run time. Packing is optional and off by
default. Existing unpacked builds retain their normal layout and behavior.

## Commands

```powershell
python mlc_win64.py app.ml app.exe --pack
python mlc_win64.py --pack-exe app.exe app-packed.exe
python mlc_win64.py --unpack-exe app-packed.exe app-original.exe
```

The native compiler uses the same flags. For Linux output, add
`--target linux-x64`; the produced ELF must run on Linux. Standalone output
paths must not exist, and an in-place standalone transformation is refused.
Compile-time `--pack` replaces only the compiler-owned output after validation.

The old UPX method is still available explicitly:

```powershell
python mlc_win64.py app.ml app-upx.exe --pack=upx --upx C:\Tools\upx.exe
python mlc_win64.py --unpack-exe app-upx.exe app-original.exe --upx C:\Tools\upx.exe
```

`--pack --upx PATH` is also accepted for the legacy method. `MINILANG_UPX`
is consulted only when the UPX method is requested. Old `MLPACK01` files
require their matching UPX executable for explicit restoration. No UPX binary
is included or needed for the built-in method.

## How the built-in image starts

The compiler first emits and links a normal executable. The packer compresses
its `.text` code with a deterministic LZ4 block encoder. It keeps PE headers,
imports, ELF program headers, dynamic linker metadata, read-only constants and
writable data in their original virtual locations. A small checked-in x64
startup stub lives in a new executable section/segment. The compressed code
lives in a separate read-only section/segment.

On startup, the operating system maps the packed PE/ELF normally and resolves
its imports. The stub checks the compressed block with FNV-1a, temporarily
makes the original code pages writable, decompresses the LZ4 block directly
into those pages, restores read-and-execute protection, then jumps to the
original entry point. Windows
uses its imported `VirtualProtect`; Linux uses the `mprotect` syscall. The
program does not extract another executable to disk or load a second process.
The stub is embedded in the compiler; its reproducible assembly source is
`mlc/pack_stubs/loader.S`. No assembler runs when compiling applications.

Only compiler-generated fixed-address x64 images are accepted. Existing older
PE files without the `VirtualProtect` import must be rebuilt by a compiler
containing the built-in packer before standalone native packing. Images that
cannot be represented safely or do not shrink are rejected. A failed
compile-time pack leaves the valid unpacked output in place.

## Exact restoration and validation

A `MLNPACK1` footer contains the original header, lengths and CRC32 checksums.
To restore, `--unpack-exe` decodes the code block, places the unchanged raw
sections/segments back at their original file offsets and verifies the whole
original image. The packer performs this exact roundtrip before publishing a
packed result. For the same source, target, flags and compiler version, Python
and self-hosted compilers produce byte-identical packed images.

Inputs are limited to 1 GiB. Checksums detect accidental corruption; they are
not authentication or a sandbox. Pack only trusted compiler-generated inputs.
The normal file permissions are preserved on Linux without setuid/setgid bits.
Packing changes a code signature, so sign the final packed artifact. An
unmodified packed file can be restored byte-for-byte; appended signatures or
other data after packing are outside that guarantee.

## Performance and deployment

Packing reduces file/download size, not the live MiniLang heap. Startup must
read and decompress the code, and peak resident memory can increase because
more code pages are touched. The compressed code is LZ4 for fast startup; it
can be larger than a UPX file. The packer declines to replace an executable
when its complete packed image is not smaller. Keep an unpacked build for
debugging and compatibility testing.

The native packer regressions check Windows/Linux execution, OOP and standard
library imports, corruption, exact cross-compiler restoration and byte parity.
See the [packing evaluation](reports/NATIVE_PACKING_2026-11-14.md) for measured
size and startup costs on compiler images.
The legacy UPX integration remains in `tests/check_compaction_packing.py` and
its `MLPACK01` metadata tests remain active.
