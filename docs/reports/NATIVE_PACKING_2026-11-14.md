# Native executable packing evaluation (2026-11-14)

The new built-in packer uses a deterministic LZ4 block for generated x64
`.text`, with a short startup loader embedded in both compilers. It requires
no external packer, library, installer, or runtime file. Packing is opt-in.
Unpacked builds use the existing code generator.

## Correctness

On Windows 11 x64 and Ubuntu under WSL, `tests/check_native_packing.py`
compiled the OOP plus standard-library fixture for both targets with:

- Python compiler, Windows self-hosted compiler, Linux self-hosted compiler
- monolithic and `.mlo` object-pipeline modes

All six packed images per target were byte-identical. Each unpacked exactly
to the corresponding original image, ran with the expected output, and
rejected a corrupted footer without publishing output. A corrupted compressed
payload exited with code 127 on both targets. The prerelease Windows and Linux
self-host compiler builds were byte-identical to their Python bootstrap
counterparts (SHA-256 `73934F6978B9BAFBA9B68FBC233816AD699486E659284835C7935AF8FDCDA3FF`
and `4DCA77248EE35CFC6FAE38DEE6E21A60EA4123ED7E6A1C0BB5C97750DF166049`).
The full native regression suite passed (173.7 s); the Python suite passed
with 229/229 tests. Packed Windows and Linux
compiler images compiled the fixture to bytes identical to their unpacked
counterparts. GCC plus `objcopy` in WSL reproduced both embedded loader byte
arrays exactly from `mlc/pack_stubs/loader.S`; these tools are only needed to
regenerate the checked-in bytes, not to compile or run MiniLang programs.

## Compiler-image size and pack time

| Target | Original | Packed | Reduction | Python pack | Native pack |
| --- | ---: | ---: | ---: | ---: | ---: |
| Windows PE | 64,317,440 B | 14,389,296 B | 77.63% | 14.7 s | 0.58 s |
| Linux ELF | 64,336,224 B | 14,412,938 B | 77.60% | 15.1 s | 0.59 s |

The Python and native packers emitted the same SHA-256 for the large compiler
image on each target. Times include the standalone packer process and exact
restoration verification; one run per host/target. Python's pure Python LZ4
encoder is the main compile-time cost at this image size.

## Startup cost

Alternating A/B `--version` runs after five warmups per image, 30 samples per
image. The median includes process creation and program exit. This is a
large-compiler worst-case workload, not an application benchmark.

| Target | Unpacked median | Packed median | Packed p90 |
| --- | ---: | ---: | ---: |
| Windows x64 | 8.72 ms | 81.31 ms | 84.13 ms |
| Linux x64 (WSL) | 5.28 ms | 118.10 ms | 125.16 ms |

The loader touches and decompresses approximately 64 MB of code at startup.
Runtime performance after startup and live heap size are not improved by
packing. Keep it optional for applications where startup latency matters.

## Reproduce

```powershell
python tests/check_native_packing.py `
  --python-compiler ../MiniLangCompilerPy/mlc_win64.py `
  --windows-compiler build/native-packer/final-native-windows.exe `
  --linux-compiler build/native-packer/final-native-linux `
  --output build/native-packer/parity-full.json
```

The script uses the local `wsl -d Ubuntu` installation to run ELF files.
Compiler images in this performance report were built before the 1.3.7 version
stamp and are not release artifacts; the 1.3.7 release hashes are in its
[version matrix](release-1.3.7-version-matrix.json). The existing UPX method remains available
explicitly; UPX was not installed for a comparative measurement in this run.
