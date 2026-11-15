# MinUX x64 target

`--target minux-x64` produces native MinUX ELF64 programs from either compiler
on Windows, Linux or MinUX. Direct compilation, MLO and built-in packing are
supported. Available starting with release 1.3.9; rebuild older compilers before using
this target.

## Compile and deploy

Run the host-side commands below from the `MiniLangCompilerPy` checkout;
the native compiler and its sources are in the sibling `MiniLangCompilerML`.

```powershell
python mlc_win64.py tests/minux_services.ml build/services --target minux-x64 -I . --pack
../MiniLangCompilerML/build/mlc_win64_minux_extensions.exe tests/minux_services.ml build/services-native --target minux-x64 -I . --pack
```

Copy the ELF to MinUX, set its execute bit and run it normally. The base system
supplies `/lib/ld-minux.so` and `/lib/libc.so.1`. Core runtime, filesystem, time,
process and threading require no additional library.

Predefined values: `TARGET_OS="minux"`, `TARGET_ARCH="x64"`, `TARGET_ABI="sysv"`,
`TARGET_FORMAT="elf"`, `POINTER_SIZE=8`. Manifests accept `target="minux-x64"`;
target identity participates in incremental caches.

## Implemented services

| Area | Native implementation |
| --- | --- |
| Runtime | UTF-8 arguments/I/O, managed values, cooperative GC, shared heap, native threads and per-thread GS contexts |
| Memory | Reserve/commit/decommit/recommit and reservation rollback; a 4 GiB reservation does not commit 4 GiB physically |
| FFI | Eager imports and shared SysV integer/FP/stack/out-parameter marshalling |
| Base libraries | `std.fs`, `std.path`, `std.platform`, `std.process`, `std.time`, `std.threading` |
| Advanced files | Positional I/O, durable writes, flush/truncate, directory-entry sync and shared/exclusive whole-file locks |
| Math and snapshots | MinUX libc math entry points and unmanaged shared-value allocation/copy/ownership |
| Terminal | Echo-safe secret input, mode restoration, bounded input, overflow draining and wiping |
| Network | IPv4 TCP/UDP clients/listeners, ranged I/O, ownership and finite native timeouts |
| TLS | Mbed TLS 3.6.5 client/server, TLS 1.2/1.3, PEM credentials, CA/hostname validation and SHA-256 certificate pinning |
| Crypto | SHA-256/384, HMAC, PBKDF2, HKDF, AES-256-GCM, X25519, ECDSA-P256 verification and secure random |
| GUI | MiniGui bridge to the native desktop snapshot/command protocol |
| Media | PCM WAV/raw BGR AVI with worker playback, events, seek/pause/rate/loop and native audio/video output |
| Compiler | Executes inside MinUX, translates programs and rebuilds itself |

Adapters use MinUX's 96-byte `stat`, 88-byte `dirent`, 24-byte mutex and 8-byte
condition layouts. Timed events poll against monotonic deadlines because native
condition clocks are realtime. Counting semaphores yield to the scheduler.

## Native libraries

Build on Linux/WSL using the existing MinUX SDK/toolchain:

```sh
python3 tools/build_minux_native.py --minux-root ../../MinUX
```

The build uses MinUX GCC 12.5 and the toolchain's verified Mbed TLS 3.6.5 source.
It creates a private PIC/pthread build, downloads nothing and leaves the MinUX
checkout/toolchain source unchanged. Host GCC/G++, Make and Binutils are needed.
Override `--toolchain`, `--mbedtls-source` or `--dependency-build` for another
cache location. `--core-only` omits GUI/media; otherwise the sibling MiniGui
checkout is used, or can be selected through `--minigui-root`.

Outputs under `build/minux-native/`:

- `libminilang_minux.so`: platform, TLS and crypto adapters.
- `libminigui_minux.so`: native desktop bridge.
- `libminilang_video.so`: media backend.
- `runtime-manifest.json`: sizes, SHA-256 hashes and native import audit.
- Mbed TLS license and the toolchain CA bundle, when available.

Install libraries into `/lib` and a trusted bundle into
`/etc/ssl/certs/ca-certificates.crt`, or set `ClientOptions.caFile` explicitly.
Preserve the Mbed TLS license when redistributing it. The build hides archive
internals and rejects unresolved symbols, text relocations and oversized images.
Ordinary MiniLang cross-compilation requires no assembler or MinUX SDK.

## Required MinUX kernel changes

The associated [MinUX prerequisite commit](https://github.com/n1k0m0/MinUX/commit/3675df7)
is needed for large managed compiler workloads
and durable file operations:

- VM commitment obeys the existing process memory budget instead of a separate
  fixed 256 MiB ceiling. Range validation, resource/physical limits and allocation
  rollback remain active.
- Added syscall 73 performs atomic nonblocking whole-file lock transitions.
  Ownership follows VFS open descriptions through dup/fork and releases on final
  close/process exit. Filesystem/inode identity covers hard links. Waiting occurs
  in the adapter outside the kernel/VFS operation lock.
- Native directory descriptors are accepted by VFS `syncDescriptor`, allowing
  `std.io.file.syncDirectory()` to reach Ext2's directory durability fence.
  Windows directory access checks remain in force.

Rebuild the MinUX kernel before using these features. Existing syscall numbers
and public structure layouts are preserved. Tests stage a private kernel into
a copied disk; the original boot image is preserved. The other adapters also
run on the preceding native MinUX image.

The public standard library selects MinUX native imports. `std.math` binds
`sqrt`, `exp` and `log` from `libc.so.1`. The legacy unmanaged snapshot codec
`std.concurrent.shared_value` uses its `malloc`, `free` and `memmove` exports.
`std.io.file.syncDirectory` validates the directory through `opendir`, calls
`fsync(dirfd(...))` and closes the stream on success and failure. It reports
errors for missing paths and regular files instead of claiming a successful
durability fence. MinUX does not use Linux's `O_DIRECTORY` flag.

## Native compiler and packing

```powershell
python mlc_win64.py ../MiniLangCompilerML/mlc_win64.ml build/mlc_minux --target minux-x64 -I ../MiniLangCompilerML --pack
```

Install `libminilang_minux.so` alongside MinUX libc before running the compiler;
the compiler itself imports the advanced file services. Inside MinUX, supply
the standard-library source root:

```sh
/home/user/compiler /home/user/hello.ml /home/user/hello --target minux-x64 -I /home/user/ml --pack
/home/user/compiler /home/user/ml/mlc_win64.ml /home/user/compiler-stage2 --target minux-x64 -I /home/user/ml --no-object-pipeline --pack
```

The packing stub preserves argc/argv/envp and uses native protection/exit
requests. Unpacking restores the exact original image. The compiler packs to
about 14.5 MB from about 64.7 MB. Final CLI output and packed images are checked
against the 16 MiB loader file limit. Large intermediate ELF construction and
explicit unpacking remain possible. Legacy UPX is rejected for MinUX.

## Platform limits

- Loader: 16 MiB per image, 16 objects per process, 256 KiB native stacks. Direct
  dependency counts are checked; transitive dependencies remain loader-bound.
  Image base is 4 GiB; the managed heap occupies a separate arena.
- VM requests retain the 1 GiB per-request limit and resource/physical limits.
  `--gc-concurrent` remains Windows-only.
- Imports require exact MinUX basenames. Linux libc names, DLLs, paths and
  same-name imports from different libraries are rejected. Binding is eager and
  global; library-local dlopen/dlsym is not emulated.
- MinUX libc has process-global errno. Positional I/O serializes seek/transfer/
  restore among adapter calls. Other native clients must not concurrently change
  the position of the same open description.
- Networking is IPv4 over the native interface; the native stack has no
  localhost/127.0.0.1 loopback interface. Unsupported reuse/keepalive/Nagle
  options report errors.
  Native socket defaults are finite; longer positive timeouts are supported.
  Zero is rejected instead of falsely claiming to disable native timeouts.
- `process.executablePath()` retains argv[0], which can be relative.
- Native filesystem leaf names are limited to 63 bytes (`NAME_MAX`).
- GUI requires desktop command/snapshot pipes. Stdout carries frames; log to
  stderr. One independent window is supported per process. Native labels,
  buttons, text boxes, checks, lists, trees, dropdowns, panels, status/progress
  controls, images and supported menu/toolbar records map to the SDK protocol.
  Messages use overlays; path/color pickers use validated text entry. WebView,
  tray, rich/code editors, canvas and extra independent windows require further
  OS facilities; unsupported constructors report errors. Native bounds and
  UI-thread affinity apply.
- WAV accepts local integer PCM (8/16/24/32-bit, 1–8 channels), converted to
  unsigned 8-bit mono at 4–44.1 kHz with basic resampling. AVI accepts one raw
  24/32-bit BGR video stream up to 4096×2160. Compressed/multiplexed AVI,
  MP3/MIDI and network media report unsupported-format errors. Inputs are bounded
  to 256 MiB; one player owns the audio device.

## Verification

```powershell
python -m unittest discover -s tests -p "test_*.py"
python tools/generate_minux_runtime.py --check
python tools/generate_pack_loaders.py --check
python tests/check_minux_target.py --native ../MiniLangCompilerML/build/mlc_win64_minux_extensions.exe --extensions --pack --output build/minux-extension-parity-final
```

Linux/WSL guest checks require QEMU, e2fsprogs and OpenSSH:

```sh
python3 tests/check_minux_network.py --minux-root ../../MinUX --native-libraries build/minux-native
python3 tests/check_minux_extensions.py --minux-root ../../MinUX --kernel /path/to/updated/MinUX_kernel.bin
python3 tests/run_minux_guest.py --minux-root ../../MinUX --kernel /path/to/updated/MinUX_kernel.bin --native-libraries build/minux-native --selfhost build/mlc_minux --selfbuild --work build/minux-selfbuild --timeout 2400
python3 tests/run_minux_guest.py --minux-root ../../MinUX --kernel /path/to/updated/MinUX_kernel.bin --native-libraries build/minux-native --selfhost build/mlc_minux --fixed-point --selfbuild-pipeline mlo --work build/minux-fixed-point --timeout 3600
```

Only copied disks are modified; listeners bind to loopback. A C supervisor checks
actual child exit status, and kernel/user faults fail the run. Coverage includes
file/lock lifetime, hard links, PTY echo restoration/overflow wiping, audio
hardware completion, malformed media, GUI events/dialogs and generated BMP
frames. TLS uses independent host peers, certificate rejection, bulk records and
native server interop. Compiler checks include direct/MLO program builds and
optional complete self-rebuild followed by running the resulting compiler/output.
`--fixed-point` rebuilds stage3 with stage2 using the same source paths and
options, compares every byte of both packed executables, and then compiles and
runs a program with stage3. `--selfbuild-pipeline` selects `direct` (default)
or `mlo` for both complete compiler builds. Self-builds use a copied 1 GiB image
by default; other guest tests use 256 MiB. Override with `--image-size-mib`.
The guest supervisor also tests equal and unequal comparison inputs. SSH sends
the shell's exit command only after the supervisor reports completion; live
transcripts and the copied disk are retained for failure diagnosis. The
supervisor polls and reaps the exact child before accepting its exit status.
For large self-builds, a WSL-native work directory (for example under `/tmp`)
avoids the overhead of flushing an emulated disk through a Windows drive mount.

Additional stdlib verification: all 48 public packages compile together for MinUX;
`minux_stdlib.ml` runs native math accuracy checks, unmanaged snapshot round
trips/overlapping copies and real directory sync after create/rename/unlink,
including invalid paths and repeated opens to catch descriptor leaks. Its
assertions fail the guest process exit status. The three compiler paths produce
identical packed binaries and all three execute successfully in MinUX.
The existing `stdlib_unit_tests.ml` also passes 321 assertions in MinUX. Its
localhost network round trips are explicitly marked `[SKIP]` on this platform;
`check_minux_network.py` verifies real TCP/UDP and TLS traffic with host peers
instead. Test fixture filenames respect MinUX `NAME_MAX`; Windows/Linux retain
their existing socket-reuse coverage. Use `--kernel` on the network runner to
verify the same private kernel as the other guest suites.

Run the portable stdlib unit suite in the guest with:

```sh
python3 mlc_win64.py tests/stdlib_unit_tests.ml build/minux-stdlib-units --target minux-x64 -I . --pack
python3 tests/run_minux_guest.py --minux-root ../../MinUX --kernel /path/to/updated/MinUX_kernel.bin --native-libraries build/minux-native --expected-exit 0 --work build/minux-stdlib-units-guest --timeout 480 build/minux-stdlib-units
```

Implementation verified before the release-version bump on 2026-11-15: Python regression 230 passed; native regression 146 harness
tests and all outer steps passed; unit/contract suite passed with one optional
NASM skip. Eleven packed fixtures agree byte-for-byte across Python/direct/MLO.
Complete MLO self-builds of stage2 and stage3 passed in QEMU. Both packed
compilers are byte-identical at 14,491,872 bytes; the independently built Python
bootstrap also matches. SHA-256:
`4a65a2622801f544153a6e1695120a3a0e5907d425c19ca82322374a50323252`.
Stage3 compiled a packed MLO program that ran with the expected exit status 37.
The actual guest-built compilers and complete transcripts are retained under
`build/minux-stdlib-fixedpoint/`; the checked evidence manifest is
`build/minux-stdlib-summary.json`. Native GUI protocol and video-frame checks
passed; visual desktop review was not performed. Current regression evidence is
in `build/minux-stdlib-*` and
`MiniLangCompilerML/build/minux-stdlib-native-regression.log`.

The clean prerequisite revision also builds a complete kernel independently
of unrelated OS development. Six host suites pass with ASan/UBSan, including
2,008,765 virtual-memory checks and 9,020,529 descriptor checks. Test images
using that kernel must install its matching driver modules; the guest runner's
`--modules /path/to/obj/modules` option stages them into the copied image.

## Maintenance

`mlc/minux_runtime.S` is authoritative; regenerate both compiler blobs with
`tools/generate_minux_runtime.py`. The executable pointer has separate storage
because argument construction clears its transient globals. Shared SysV
marshalling lives in `mlc/sysv_runtime`. Regenerate pack stubs from
`mlc/pack_stubs/loader.S` with `tools/generate_pack_loaders.py`.
