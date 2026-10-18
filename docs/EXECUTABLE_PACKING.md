# Optional executable packing

Both compilers accept the same optional UPX workflow for Windows x64 PE and
Linux x64 ELF. Packing is **off by default** and does not change language
semantics or the normal uncompressed build. The packed image contains UPX's
startup decompressor; the end user does not need UPX installed.

## Usage

Download a trusted host-compatible [UPX distribution](https://upx.github.io/).
The validated version is **5.2.1**. Nothing is downloaded or installed by the
compiler. Supply an explicit executable path, or set `MINILANG_UPX`.

Python compiler, Windows example:

```powershell
python mlc_win64.py app.ml app.exe --pack --upx C:\Tools\upx.exe
python mlc_win64.py --pack-exe app.exe app-packed.exe --upx C:\Tools\upx.exe
python mlc_win64.py --unpack-exe app-packed.exe app-original.exe --upx C:\Tools\upx.exe
```

The first command already packs its output; the second is an **alternative**
for an independently built, unpacked executable.

Native compiler, Linux example:

```sh
./mlc app.ml app --target linux-x64 --pack --upx /opt/upx/upx
./mlc --unpack-exe app app-original --upx /opt/upx/upx
```

The executable name of the native compiler can differ by installation.
`--pack=upx` is an alias for `--pack`. The host UPX executable must support
the requested target format; the Windows and Linux UPX 5.2.1 builds were tested.

## Guarantees and boundaries

- Normal code-generation optimizations run before packing. For the same source,
  target, flags and **same UPX build/options**, both compilers generate the same
  packed bytes. Windows PE and Linux ELF are different formats, not identical files.
- The compiler runs UPX with fixed options:
  `--no-env --no-progress --best --no-lzma --overlay=copy`.
  It tests and unpacks the compressed payload before publication.
- `--unpack-exe` restores the **exact original bytes** of an unmodified
  MiniLang-packed file, including header/import-table bytes that plain UPX may
  normalize. Ordinary `upx -d` alone does not provide this guarantee.
- Standalone output paths must not exist; in-place transforms are refused.
  Intermediate files live in an exclusively created sibling directory.
  Publication is atomic and temporary files are removed on ordinary success
  and error paths. A hard process termination can leave that private directory.
- Compile-time packing replaces only the just-generated output after validation.
  On a packing failure, compilation returns an error and retains the valid
  **unpacked** output. A result that is not smaller is rejected.
- Packed project builds bypass the incremental output cache, because UPX is an
  external input not covered by the ordinary cache key.
- Inputs are limited to 1 GiB and restoration metadata to 16 MiB. Only trusted
  executables and a trusted UPX binary belong in this workflow. The checksums
  detect corruption; they are **not authentication or a sandbox**.
- Linux ordinary file permissions are preserved without setuid/setgid bits.
  Packing changes an existing code signature. Sign the final distribution
  artifact, not the input; explicit MiniLang unpacking supports the unmodified
  packed output, not signatures or arbitrary data appended afterwards.

## Trade-offs

Packing reduces the **file/download size**, not the program's live managed
heap. Startup needs decompression, and resident/private memory can increase.
Debugging and executable inspection become less convenient. Some deployment
policies or virus scanners reject packed images or produce false positives.
Keep an unpacked artifact for debugging and offer it when compatibility matters.

See the [UPX manual](https://github.com/upx/upx/blob/devel/doc/upx.pod) for format
limitations and the [UPX discussion of scanner reports](https://github.com/upx/upx/discussions/884).
This is an optional size trade-off, not a promise of faster execution.

## Restoration format (MLPACK01)

A checked overlay follows the ordinary UPX payload. It contains six
little-endian u32 fields: original length, payload length, UPX-roundtrip length,
original CRC32, payload CRC32 and record count. Each record stores a u32 offset,
u32 length and the original bytes of one changed block (at most 4096 bytes).

The footer is `MLPACK01`, metadata length and metadata CRC32. Lengths,
checksums, sorted nonoverlapping records and complete consumption are checked
before calling the external unpacker. After restoring the blocks, the whole
original-image checksum is verified. No timestamps, paths or random values enter
the packed image or metadata.

## Regression checks

`tests/check_compaction_packing.py` compares monolithic/MLO and Python/native
output, executes packed PE/ELF images, checks exact cross-compiler restoration,
and tests corrupt metadata, existing destinations, unsuitable tools and cleanup.
`tests/test_packing.py` (Python) and `tests/packing_format.ml` (MiniLang)
exercise boundary lengths and malformed restoration records without UPX.

Run the optional integration check with an explicitly installed tool:

```powershell
python tests/check_compaction_packing.py --compiler build/mlc-compact-final.exe --reference ../MiniLangCompilerPy/mlc_win64.py --upx C:\Tools\upx.exe --linux
```

Replace `--compiler` with your verified native compiler path. Linux hosts can
run the same script with a Linux compiler and UPX; omit `--linux` there.
Measured results are recorded in the
[code-generation and packing evaluation](reports/CODEGEN_COMPACTION_AND_PACKING_2026-10-18.md).
