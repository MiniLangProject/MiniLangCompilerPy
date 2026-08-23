<!--
Copyright 2026 Nils Kopal

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0
-->

# Native primitive benchmarks

Compile and run `native_primitives.ml` with the compiler revision being
measured. Redirect each run to a revision-specific text file and compare the
same machine, power plan, compiler options, and idle-system conditions.

```powershell
.\build\mlc_win64.exe .\benchmarks\native_primitives.ml .\build\native_primitives_bench.exe -I .
.\build\native_primitives_bench.exe | Tee-Object .\build\native_primitives_bench.txt
```

The benchmark covers a 64 MiB CRC-32C workload, found and missing byte scans,
short and long substring scans, AES-256-GCM at three message sizes, SHA-256,
and SHA-384. CRC and search are measured with forced scalar dispatch and with
all detected CPU features. Each result reports elapsed milliseconds,
throughput in MiB/s, live-heap change, and committed-heap change.

These are diagnostic measurements, not fixed pass/fail performance tests.
Record at least five runs per revision and compare medians. A change is
actionable only when it repeats outside ordinary run-to-run noise.
