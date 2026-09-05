# Binary compiler packages

Release 1.2.6 provides Windows x64 ZIP and Linux x64 tar.gz packages. Each
contains an executable compiler (`mlc.exe` or `mlc`), the matching `std/` library,
a hello example, license, release notes and a BUILD_INFO.json manifest. Every
download has a SHA-256 sidecar. No separate Python installation is needed to run
either compiler distribution.

Extract the whole package before use. From its directory, on Windows:

```powershell
./mlc.exe --version
./mlc.exe examples/hello.ml hello.exe --target windows-x64 -I .
./hello.exe
```

On Linux:

```sh
./mlc --version
./mlc examples/hello.ml hello --target linux-x64 -I .
./hello
```

The Linux tar archive preserves the executable bit. These builds were tested on
Ubuntu 24.04 x86-64 (glibc 2.39) and Windows 11 x64. Older Linux distributions
and musl-based systems are not covered. Keep `-I /path/to/extracted/package`
when building from another directory so standard-library imports resolve.
Windows remains the compiler's default output target; select `--target linux-x64`
explicitly when producing Linux applications. Either host compiler can emit
either target, but the resulting program runs on its selected target OS.

The manifest identifies the 1.2.6 compiler-source revision and executable hash.
Compiler sources are unchanged by this binary-packaging update. Source archives
remain available alongside the binary assets generated for this release.

The reference compiler is distributed as a PyInstaller executable with its
Python runtime embedded. The runtime extracts to a temporary directory
when launched. It does not launch a system Python interpreter.

## Building binary releases

On each destination host, create a Python virtual environment and install
`scripts/requirements-binary.txt`. Run `python scripts/build_binary.py` with that
environment's Python. This builds `build/binary/windows-x64/mlc.exe` or
`build/binary/linux-x64/mlc`. PyInstaller freezing must run on the destination OS.

Package the result with `python scripts/package_binary.py --binary <executable>
--platform windows-x64` (or `linux-x64`). Add `--third-party <license-directory>`
for the Python, PyInstaller and bundled dependency licenses/notices from that
build environment. Archives and checksum sidecars are written to `build/releases`.
The compiler-source version tag must be available locally for the manifest.
