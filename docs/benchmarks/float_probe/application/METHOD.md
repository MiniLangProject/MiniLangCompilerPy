# Real application comparison

The two application workloads use the normal native MiniLang compiler and the
standalone formatter already shipped in MiniLangCompilerML. They complement the
numeric microbenchmarks with actual compiler and developer-tool work. Neither
workload is claimed to represent a game or database server.

Both variants use one clean, frozen MiniLangCompilerML checkout, including the
same standard library. The Phase 8 reference checkout is
`c92a678308d408c4f566f007c8ab16fcb5298ca2`. The input repository must be clean when
the runner starts and finishes; its commit and standard-library Git tree are
recorded. The runner fingerprints both native compilers, itself, the program
source, the formatting input and every output. It rechecks immutable inputs
after the experiment.

## Workloads

1. **Compile the formatter:** each uninstrumented native compiler compiles the
   unchanged `tools/mlfmt.ml` to a Linux x64 executable, using
   `--no-object-pipeline --no-incremental`. This is a complete real compilation,
   including imports, parsing, code generation and writing the executable. The
   generated executable must be byte-stable across all runs of each variant.
   Different compiler versions are allowed to generate different executables.
2. **Format compiler source:** each produced formatter reads a frozen copy of
   the real `mlc/codegen/codegen_stmt.ml`, formats it with `--indent 2
   --max-blank 2`, and writes to a separate output path. The repository source
   is never formatted in place. Every output must be nonempty and have exactly
   the same SHA-256 as the reference warmup output.

The source files at the reference revision are:

| File | Bytes | Lines | SHA-256 |
| --- | ---: | ---: | --- |
| `tools/mlfmt.ml` | 38,103 | 1,485 | `201293c0c2205a1a18e607a03632e0056b5aca11d3d26a70cf464e79cc4470d2` |
| `mlc/codegen/codegen_stmt.ml` | 488,825 | 12,155 | `6537e54af862fb6a3549957971ba0fa5f2ce8f86cc878a0af4943454fdfc87b5` |

## Timing and correctness

The preset experiment uses **seven paired measured rounds**, plus one separate
warmup process per workload and variant: 28 measured processes and four warmup
processes. All rows are retained. Within each pair, before/after order
alternates by round; the order is offset between workloads. The workload order
also alternates. For seven rounds the two relative pair orders occur four and
three times. A timeout, nonzero exit, missing output or hash mismatch aborts the
experiment; partial reports remain marked incomplete.

The runner pins itself and inherited child processes to one requested CPU.
`perf_counter_ns` measures complete process wall time, including startup and
cached filesystem I/O. Linux `wait4` additionally provides process user/system
CPU time and peak resident set in KiB. Peak RSS is not cumulative allocation
volume, managed-heap size or reserved address space. The monolithic compiler
mode avoids separate object-emitter processes.

Warmups are recorded but excluded from summaries. Reports retain individual
paired ratios, their median and full min/max, faster-pair counts, wall/CPU/RSS
medians and inclusive-quartile relative IQR. No unsuccessful or slow run is
silently removed or repeated. The measured times cannot be directly compared
to the numeric microbenchmarks' internal time per kernel call.

An unchanged formatter image is a useful real-application control. A numeric
optimization is not assumed to benefit string-heavy formatting or compilation;
any measured application change must be assessed against run-to-run variation.
These shared-host observations do not establish performance on controlled
hardware or on other application domains.

## Run

Choose a new output directory and use fixed before/after native executables:

```bash
python compare_applications.py \
  --before /absolute/path/before-compiler \
  --after /absolute/path/after-compiler \
  --repository /absolute/path/frozen-MiniLangCompilerML \
  --work /absolute/path/application-run \
  --rounds 7 --cpu 2 --timeout 300
```

`applications.json` contains provenance, warmups, raw measured rows and the
summary. `build/formatter-before` and `build/formatter-after` are the exact
programs used for the formatting workload. `build/formatted-output.ml` retains
the verified final formatted file. Each process has a separate log.

The private `preparation/` directory records one exploratory baseline build and
formatting run used to check workload feasibility. Its observations are not
pooled into the final comparison.
