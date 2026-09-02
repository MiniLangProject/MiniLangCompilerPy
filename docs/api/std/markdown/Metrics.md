# Metrics

[Home](README.md)

Static metrics are calculated from target-specific preprocessed MiniLang files inside the configured source roots. External imported modules, generated documentation, and excluded paths are not measured.

## Project summary

| Metric | Value |
| --- | ---: |
| Blank lines | 2552 |
| Clone groups | 163 |
| Cognitive complexity | 2631 (maximum per function: 43) |
| Comment lines | 3812 |
| Cyclomatic complexity | 3172 (average: 3.51, maximum: 26) |
| Documentation coverage | 100% (1684 of 1684 documentation items) |
| Duplicated lines | 1016 (10.73%) |
| Files | 46 |
| Functions | 904 |
| Maintainability index | 8.66 / 100 |
| Physical lines | 15828 |
| Source lines | 9467 |
| Statements | 6677 |

## Documentation coverage

Coverage is split by documentation contract so strong API summaries cannot hide undocumented parameters or data members.

| Category | Documented | Total | Coverage |
| --- | ---: | ---: | ---: |
| API declarations | 679 | 679 | 100% |
| Constants | 115 | 115 | 100% |
| Enum variants | 22 | 22 | 100% |
| Fields | 147 | 147 | 100% |
| Globals | 1 | 1 | 100% |
| Overall | 1684 | 1684 | 100% |
| Parameters | 720 | 720 | 100% |

## Halstead metrics

| Distinct operators | Distinct operands | Total operators | Total operands | Vocabulary | Length | Volume | Difficulty | Effort | Estimated defects |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 56 | 2785 | 38272 | 25929 | 2841 | 64201 | 736525.63 | 260.69 | 192002313.96 | 245.51 |

## Files

| File | SLOC | Functions | Cyclomatic total / avg / max | Cognitive total / max | Duplication | Halstead volume | MI |
| --- | ---: | ---: | --- | --- | --- | ---: | ---: |
| [`std/_linux_fs.ml`](File-std-linux-fs-ml-2121665983.md) | 238 | 23 | 103 / 4.48 / 10 | 94 / 13 | 9 (3.78%) | 15510.53 | 4.96 |
| [`std/array.ml`](File-std-array-ml-1258125823.md) | 260 | 18 | 79 / 4.39 / 11 | 67 / 10 | 27 (10.38%) | 7293.05 | 9.65 |
| [`std/assert.ml`](File-std-assert-ml-1772521196.md) | 92 | 8 | 17 / 2.13 / 3 | 9 / 2 | 0 (0%) | 1751.75 | 32.16 |
| [`std/bytes.ml`](File-std-bytes-ml-1351945333.md) | 501 | 38 | 153 / 4.03 / 13 | 124 / 16 | 215 (42.91%) | 16996.47 | 0 |
| [`std/checksum/crc32.ml`](File-std-checksum-crc32-ml-1964480723.md) | 23 | 5 | 12 / 2.4 / 3 | 7 / 2 | 0 (0%) | 974.56 | 47.75 |
| [`std/checksum/crc32c.ml`](File-std-checksum-crc32c-ml-144026660.md) | 23 | 5 | 12 / 2.4 / 3 | 7 / 2 | 0 (0%) | 974.56 | 47.75 |
| [`std/concurrent/cancellation.ml`](File-std-concurrent-cancellation-ml-1392694543.md) | 86 | 19 | 31 / 1.63 / 4 | 12 / 3 | 0 (0%) | 2987.09 | 29.3 |
| [`std/concurrent/channel.ml`](File-std-concurrent-channel-ml-2137315633.md) | 158 | 25 | 64 / 2.56 / 9 | 43 / 10 | 0 (0%) | 7671.79 | 16.23 |
| [`std/concurrent/shared_value.ml`](File-std-concurrent-shared-value-ml-2112657235.md) | 133 | 15 | 49 / 3.27 / 9 | 37 / 11 | 15 (11.28%) | 6847.36 | 20.22 |
| [`std/concurrent/task.ml`](File-std-concurrent-task-ml-139288457.md) | 114 | 18 | 48 / 2.67 / 10 | 38 / 15 | 0 (0%) | 5271.83 | 22.61 |
| [`std/concurrent/thread_pool.ml`](File-std-concurrent-thread-pool-ml-72857761.md) | 373 | 43 | 117 / 2.72 / 9 | 89 / 11 | 40 (10.72%) | 16551.36 | 0 |
| [`std/console.ml`](File-std-console-ml-1875579671.md) | 101 | 9 | 44 / 4.89 / 24 | 36 / 24 | 0 (0%) | 7093.64 | 23.4 |
| [`std/core.ml`](File-std-core-ml-750389783.md) | 82 | 16 | 28 / 1.75 / 4 | 12 / 3 | 29 (35.37%) | 1907.85 | 31.52 |
| [`std/cpu.ml`](File-std-cpu-ml-1561418518.md) | 17 | 3 | 3 / 1 / 1 | 0 / 0 | 0 (0%) | 320 | 55.21 |
| [`std/crypto.ml`](File-std-crypto-ml-1263151193.md) | 98 | 16 | 59 / 3.69 / 10 | 43 / 9 | 0 (0%) | 6101.03 | 22.12 |
| [`std/crypto/_cng.ml`](File-std-crypto-cng-ml-1099901917.md) | 302 | 15 | 72 / 4.8 / 13 | 60 / 14 | 46 (15.23%) | 20707.21 | 6 |
| [`std/crypto/_openssl.ml`](File-std-crypto-openssl-ml-882852629.md) | 174 | 11 | 64 / 5.82 / 21 | 69 / 32 | 0 (0%) | 14986.94 | 13.28 |
| [`std/crypto/aes_gcm.ml`](File-std-crypto-aes-gcm-ml-264581731.md) | 48 | 6 | 26 / 4.33 / 10 | 20 / 9 | 0 (0%) | 2739.36 | 35.76 |
| [`std/ds/concurrent_hashmap.ml`](File-std-ds-concurrent-hashmap-ml-1798836270.md) | 307 | 25 | 90 / 3.6 / 11 | 77 / 17 | 88 (28.66%) | 13050.58 | 4.82 |
| [`std/ds/concurrent_list.ml`](File-std-ds-concurrent-list-ml-291130726.md) | 242 | 25 | 82 / 3.28 / 7 | 57 / 6 | 45 (18.6%) | 9342.33 | 9.17 |
| [`std/ds/hashmap.ml`](File-std-ds-hashmap-ml-1269372918.md) | 235 | 21 | 66 / 3.14 / 12 | 60 / 22 | 29 (12.34%) | 8345.82 | 11.94 |
| [`std/ds/list.ml`](File-std-ds-list-ml-2070188142.md) | 202 | 22 | 59 / 2.68 / 7 | 38 / 6 | 48 (23.76%) | 6259.19 | 15.19 |
| [`std/ds/queue.ml`](File-std-ds-queue-ml-1555253413.md) | 98 | 12 | 24 / 2 / 4 | 13 / 3 | 22 (22.45%) | 3057.31 | 28.93 |
| [`std/ds/set.ml`](File-std-ds-set-ml-1393232564.md) | 32 | 9 | 9 / 1 / 1 | 0 / 0 | 0 (0%) | 786.93 | 45.68 |
| [`std/ds/stack.ml`](File-std-ds-stack-ml-117945432.md) | 215 | 19 | 51 / 2.68 / 11 | 32 / 10 | 28 (13.02%) | 6679.05 | 15.48 |
| [`std/encoding/base64.ml`](File-std-encoding-base64-ml-1044483879.md) | 195 | 7 | 53 / 7.57 / 26 | 67 / 43 | 9 (4.62%) | 7756.64 | 15.68 |
| [`std/encoding/hex.ml`](File-std-encoding-hex-ml-900742095.md) | 40 | 7 | 11 / 1.57 / 3 | 4 / 2 | 0 (0%) | 965.22 | 42.67 |
| [`std/fmt.ml`](File-std-fmt-ml-2123112301.md) | 88 | 6 | 35 / 5.83 / 11 | 37 / 18 | 21 (23.86%) | 3174.13 | 28.36 |
| [`std/fs.ml`](File-std-fs-ml-1285967051.md) | 514 | 23 | 122 / 5.3 / 13 | 118 / 18 | 32 (6.23%) | 23239.31 | 0 |
| [`std/io/file.ml`](File-std-io-file-ml-2074692665.md) | 304 | 37 | 145 / 3.92 / 11 | 116 / 13 | 9 (2.96%) | 22678.51 | 0 |
| [`std/math.ml`](File-std-math-ml-790065500.md) | 419 | 45 | 112 / 2.49 / 9 | 75 / 10 | 29 (6.92%) | 16696.31 | 0 |
| [`std/net.ml`](File-std-net-ml-1989130045.md) | 428 | 35 | 117 / 3.34 / 9 | 84 / 8 | 12 (2.8%) | 23299.98 | 0 |
| [`std/path.ml`](File-std-path-ml-701536411.md) | 80 | 9 | 49 / 5.44 / 13 | 47 / 12 | 0 (0%) | 4532.65 | 26.29 |
| [`std/platform.ml`](File-std-platform-ml-201801091.md) | 25 | 8 | 8 / 1 / 1 | 0 / 0 | 0 (0%) | 315.78 | 50.93 |
| [`std/process.ml`](File-std-process-ml-507069519.md) | 42 | 6 | 19 / 3.17 / 7 | 13 / 6 | 0 (0%) | 2210.57 | 38.62 |
| [`std/random.ml`](File-std-random-ml-66683891.md) | 84 | 10 | 22 / 2.2 / 4 | 13 / 4 | 0 (0%) | 2755.34 | 30.98 |
| [`std/result.ml`](File-std-result-ml-986518417.md) | 88 | 17 | 26 / 1.53 / 2 | 9 / 1 | 0 (0%) | 1976.31 | 31.01 |
| [`std/sort.ml`](File-std-sort-ml-1000391650.md) | 167 | 11 | 43 / 3.91 / 11 | 53 / 25 | 8 (4.79%) | 5176.37 | 19.72 |
| [`std/string.ml`](File-std-string-ml-1276545685.md) | 394 | 33 | 121 / 3.67 / 20 | 109 / 27 | 107 (27.16%) | 13558.13 | 0 |
| [`std/string_builder.ml`](File-std-string-builder-ml-412876577.md) | 122 | 11 | 33 / 3 / 10 | 22 / 9 | 21 (17.21%) | 3285.3 | 25.43 |
| [`std/threading.ml`](File-std-threading-ml-508437988.md) | 176 | 41 | 80 / 1.95 / 8 | 39 / 7 | 39 (22.16%) | 7850.03 | 12.98 |
| [`std/time.ml`](File-std-time-ml-975894601.md) | 619 | 53 | 203 / 3.83 / 17 | 159 / 19 | 0 (0%) | 32686.86 | 0 |
| [`std/tls.ml`](File-std-tls-ml-2076630303.md) | 134 | 18 | 69 / 3.83 / 14 | 54 / 13 | 0 (0%) | 7572.72 | 17.16 |
| [`std/tls/_openssl.ml`](File-std-tls-openssl-ml-961424543.md) | 221 | 15 | 85 / 5.67 / 18 | 76 / 19 | 0 (0%) | 18823.06 | 7.5 |
| [`std/tls/_schannel.ml`](File-std-tls-schannel-ml-805501109.md) | 1135 | 80 | 439 / 5.49 / 24 | 480 / 39 | 88 (7.75%) | 103976.25 | 0 |
| [`std/uuid.ml`](File-std-uuid-ml-1903850359.md) | 38 | 6 | 18 / 3 / 9 | 12 / 8 | 0 (0%) | 2700.98 | 39.09 |

## Functions

| Function | Location | LOC | Statements | Cyclomatic | Cognitive | Max nesting | Halstead volume | MI |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| [`std.array.all`](File-std-array-ml-1258125823.md#function-function-std-array-all-function-all-a-pred-std-array-ml-1158565640) | `std/array.ml:264` | 15 | 9 | 5 | 5 | 2 | 325.48 | 56.08 |
| [`std.array.any`](File-std-array-ml-1258125823.md#function-function-std-array-any-function-any-a-pred-std-array-ml-130273110) | `std/array.ml:244` | 15 | 9 | 5 | 5 | 2 | 317.29 | 56.16 |
| [`std.array.append`](File-std-array-ml-1258125823.md#function-function-std-array-append-function-append-a-value-std-array-ml-1844937612) | `std/array.ml:341` | 14 | 9 | 4 | 4 | 2 | 340.06 | 56.73 |
| [`std.array.concat`](File-std-array-ml-1258125823.md#function-function-std-array-concat-function-concat-a-b-std-array-ml-2041570823) | `std/array.ml:360` | 18 | 12 | 5 | 4 | 1 | 471.22 | 53.23 |
| [`std.array.contains`](File-std-array-ml-1258125823.md#function-function-std-array-contains-function-contains-a-value-std-array-ml-1539166352) | `std/array.ml:155` | 6 | 3 | 2 | 1 | 1 | 158.12 | 67.36 |
| [`std.array.copy`](File-std-array-ml-1258125823.md#function-function-std-array-copy-function-copy-a-std-array-ml-1680176529) | `std/array.ml:37` | 14 | 9 | 4 | 3 | 1 | 291.43 | 57.2 |
| [`std.array.filter`](File-std-array-ml-1258125823.md#function-function-std-array-filter-function-filter-a-pred-std-array-ml-27472074) | `std/array.ml:190` | 28 | 19 | 8 | 8 | 2 | 646.24 | 47.68 |
| [`std.array.first`](File-std-array-ml-1258125823.md#function-function-std-array-first-function-first-a-std-array-ml-2054141141) | `std/array.ml:315` | 9 | 5 | 3 | 2 | 1 | 138.97 | 63.78 |
| [`std.array.indexOf`](File-std-array-ml-1258125823.md#function-function-std-array-indexof-function-indexof-a-value-start-std-array-ml-148871920) | `std/array.ml:104` | 22 | 14 | 7 | 7 | 2 | 440.92 | 51.26 |
| [`std.array.isArray`](File-std-array-ml-1258125823.md#function-function-std-array-isarray-function-isarray-x-std-array-ml-605013932) | `std/array.ml:31` | 3 | 1 | 1 | 0 | 0 | 46.51 | 77.78 |
| [`std.array.isEmpty`](File-std-array-ml-1258125823.md#function-function-std-array-isempty-function-isempty-a-std-array-ml-946252559) | `std/array.ml:306` | 6 | 3 | 2 | 1 | 1 | 104 | 68.63 |
| [`std.array.joinStrings`](File-std-array-ml-1258125823.md#function-function-std-array-joinstrings-function-joinstrings-a-sep-std-array-ml-426039153) | `std/array.ml:284` | 9 | 5 | 3 | 2 | 1 | 152 | 63.5 |
| [`std.array.last`](File-std-array-ml-1258125823.md#function-function-std-array-last-function-last-a-std-array-ml-1230645617) | `std/array.ml:327` | 10 | 6 | 3 | 2 | 1 | 171.3 | 62.14 |
| [`std.array.lastIndexOf`](File-std-array-ml-1258125823.md#function-function-std-array-lastindexof-function-lastindexof-a-value-std-array-ml-787503178) | `std/array.ml:132` | 17 | 11 | 5 | 5 | 2 | 318.58 | 54.96 |
| [`std.array.length`](File-std-array-ml-1258125823.md#function-function-std-array-length-function-length-a-std-array-ml-1052681365) | `std/array.ml:297` | 6 | 3 | 2 | 1 | 1 | 85.11 | 69.24 |
| [`std.array.map`](File-std-array-ml-1258125823.md#function-function-std-array-map-function-map-a-fn-std-array-ml-1628791657) | `std/array.ml:167` | 17 | 11 | 5 | 4 | 1 | 378.92 | 54.43 |
| [`std.array.reduce`](File-std-array-ml-1258125823.md#function-function-std-array-reduce-function-reduce-arr-f-init-std-array-ml-1955820997) | `std/array.ml:226` | 13 | 8 | 4 | 3 | 1 | 304.31 | 57.77 |
| [`std.array.slice`](File-std-array-ml-1258125823.md#function-function-std-array-slice-function-slice-a-offset-length-std-array-ml-1271445914) | `std/array.ml:58` | 36 | 24 | 11 | 10 | 1 | 707.16 | 44.62 |
| [`std.assert.assertApprox`](File-std-assert-ml-1772521196.md#function-function-std-assert-assertapprox-function-assertapprox-actual-expected-eps-label-std-assert-ml-916027518) | `std/assert.ml:130` | 18 | 14 | 3 | 2 | 1 | 293.25 | 54.94 |
| [`std.assert.assertEq`](File-std-assert-ml-1772521196.md#function-function-std-assert-asserteq-function-asserteq-actual-expected-label-std-assert-ml-808850792) | `std/assert.ml:59` | 12 | 9 | 2 | 1 | 1 | 166.91 | 60.63 |
| [`std.assert.assertFalse`](File-std-assert-ml-1772521196.md#function-function-std-assert-assertfalse-function-assertfalse-cond-label-std-assert-ml-1917626464) | `std/assert.ml:44` | 9 | 6 | 2 | 1 | 1 | 123.19 | 64.28 |
| [`std.assert.assertGt`](File-std-assert-ml-1772521196.md#function-function-std-assert-assertgt-function-assertgt-a-b-label-std-assert-ml-51991933) | `std/assert.ml:93` | 12 | 9 | 2 | 1 | 1 | 166.91 | 60.63 |
| [`std.assert.assertLt`](File-std-assert-ml-1772521196.md#function-function-std-assert-assertlt-function-assertlt-a-b-label-std-assert-ml-756131789) | `std/assert.ml:111` | 12 | 9 | 2 | 1 | 1 | 166.91 | 60.63 |
| [`std.assert.assertNe`](File-std-assert-ml-1772521196.md#function-function-std-assert-assertne-function-assertne-actual-expected-label-std-assert-ml-221639904) | `std/assert.ml:77` | 10 | 7 | 2 | 1 | 1 | 146.95 | 62.74 |
| [`std.assert.assertNotVoid`](File-std-assert-ml-1772521196.md#function-function-std-assert-assertnotvoid-function-assertnotvoid-x-label-std-assert-ml-1841061316) | `std/assert.ml:154` | 9 | 6 | 2 | 1 | 1 | 144.95 | 63.78 |
| [`std.assert.assertTrue`](File-std-assert-ml-1772521196.md#function-function-std-assert-asserttrue-function-asserttrue-cond-label-std-assert-ml-1187416750) | `std/assert.ml:30` | 9 | 6 | 2 | 1 | 1 | 116.76 | 64.44 |
| [`std.bytes.alloc`](File-std-bytes-ml-1351945333.md#function-function-std-bytes-alloc-function-alloc-size-std-bytes-ml-1457681591) | `std/bytes.ml:38` | 9 | 5 | 3 | 2 | 1 | 121.11 | 64.19 |
| [`std.bytes.allocFill`](File-std-bytes-ml-1351945333.md#function-function-std-bytes-allocfill-function-allocfill-size-fill-std-bytes-ml-871437864) | `std/bytes.ml:51` | 12 | 7 | 4 | 3 | 1 | 188.02 | 60 |
| [`std.bytes.compare`](File-std-bytes-ml-1351945333.md#function-function-std-bytes-compare-function-compare-a-b-std-bytes-ml-1567382625) | `std/bytes.ml:329` | 9 | 5 | 3 | 2 | 1 | 148.46 | 63.58 |
| [`std.bytes.concat`](File-std-bytes-ml-1351945333.md#function-function-std-bytes-concat-function-concat-a-b-std-bytes-ml-1927135267) | `std/bytes.ml:133` | 9 | 5 | 3 | 2 | 1 | 136.74 | 63.83 |
| [`std.bytes.copy`](File-std-bytes-ml-1351945333.md#function-function-std-bytes-copy-function-copy-b-std-bytes-ml-1693844616) | `std/bytes.ml:66` | 6 | 3 | 2 | 1 | 1 | 120 | 68.2 |
| [`std.bytes.ctEquals`](File-std-bytes-ml-1351945333.md#function-function-std-bytes-ctequals-function-ctequals-a-b-std-bytes-ml-959200415) | `std/bytes.ml:159` | 29 | 20 | 8 | 12 | 3 | 656.58 | 47.3 |
| [`std.bytes.decodeUtf16Z`](File-std-bytes-ml-1351945333.md#function-function-std-bytes-decodeutf16z-function-decodeutf16z-b-std-bytes-ml-1507867896) | `std/bytes.ml:394` | 3 | 1 | 1 | 0 | 0 | 36 | 78.56 |
| [`std.bytes.decodeUtf8`](File-std-bytes-ml-1351945333.md#function-function-std-bytes-decodeutf8-function-decodeutf8-b-std-bytes-ml-1587911928) | `std/bytes.ml:367` | 3 | 1 | 1 | 0 | 0 | 36 | 78.56 |
| [`std.bytes.decodeUtf8OrError`](File-std-bytes-ml-1351945333.md#function-function-std-bytes-decodeutf8orerror-function-decodeutf8orerror-b-std-bytes-ml-396718180) | `std/bytes.ml:373` | 10 | 6 | 3 | 2 | 1 | 194.49 | 61.76 |
| [`std.bytes.decodeUtf8Z`](File-std-bytes-ml-1351945333.md#function-function-std-bytes-decodeutf8z-function-decodeutf8z-b-std-bytes-ml-913051038) | `std/bytes.ml:387` | 3 | 1 | 1 | 0 | 0 | 36 | 78.56 |
| [`std.bytes.endsWith`](File-std-bytes-ml-1351945333.md#function-function-std-bytes-endswith-function-endswith-b-suffix-std-bytes-ml-1215280649) | `std/bytes.ml:234` | 9 | 5 | 3 | 2 | 1 | 160 | 63.35 |
| [`std.bytes.equals`](File-std-bytes-ml-1351945333.md#function-function-std-bytes-equals-function-equals-a-b-std-bytes-ml-1472927903) | `std/bytes.ml:146` | 9 | 5 | 3 | 2 | 1 | 148 | 63.58 |
| [`std.bytes.fill`](File-std-bytes-ml-1351945333.md#function-function-std-bytes-fill-function-fill-b-value-std-bytes-ml-1020966655) | `std/bytes.ml:202` | 13 | 8 | 4 | 3 | 1 | 241.58 | 58.48 |
| [`std.bytes.fromHex`](File-std-bytes-ml-1351945333.md#function-function-std-bytes-fromhex-function-fromhex-s-std-bytes-ml-510091409) | `std/bytes.ml:347` | 3 | 1 | 1 | 0 | 0 | 46.51 | 77.78 |
| [`std.bytes.fromHexOrError`](File-std-bytes-ml-1351945333.md#function-function-std-bytes-fromhexorerror-function-fromhexorerror-s-std-bytes-ml-2035014311) | `std/bytes.ml:353` | 10 | 6 | 3 | 2 | 1 | 209.59 | 61.53 |
| [`std.bytes.indexOf`](File-std-bytes-ml-1351945333.md#function-function-std-bytes-indexof-function-indexof-hay-needle-start-std-bytes-ml-154105993) | `std/bytes.ml:300` | 12 | 7 | 4 | 3 | 1 | 216.64 | 59.57 |
| [`std.bytes.lastIndexOf`](File-std-bytes-ml-1351945333.md#function-function-std-bytes-lastindexof-function-lastindexof-hay-needle-std-bytes-ml-26887577) | `std/bytes.ml:316` | 9 | 5 | 3 | 2 | 1 | 148.46 | 63.58 |
| [`std.bytes.readU16BE`](File-std-bytes-ml-1351945333.md#function-function-std-bytes-readu16be-function-readu16be-b-off-std-bytes-ml-388570013) | `std/bytes.ml:542` | 15 | 10 | 4 | 3 | 1 | 368.02 | 55.84 |
| [`std.bytes.readU16LE`](File-std-bytes-ml-1351945333.md#function-function-std-bytes-readu16le-function-readu16le-b-off-std-bytes-ml-827175377) | `std/bytes.ml:523` | 15 | 10 | 4 | 3 | 1 | 368.02 | 55.84 |
| [`std.bytes.readU32BE`](File-std-bytes-ml-1351945333.md#function-function-std-bytes-readu32be-function-readu32be-b-off-std-bytes-ml-157086745) | `std/bytes.ml:638` | 17 | 12 | 4 | 3 | 1 | 553.18 | 53.42 |
| [`std.bytes.readU32LE`](File-std-bytes-ml-1351945333.md#function-function-std-bytes-readu32le-function-readu32le-b-off-std-bytes-ml-1814407613) | `std/bytes.ml:617` | 17 | 12 | 4 | 3 | 1 | 553.18 | 53.42 |
| [`std.bytes.readU8`](File-std-bytes-ml-1351945333.md#function-function-std-bytes-readu8-function-readu8-b-off-std-bytes-ml-1101136119) | `std/bytes.ml:454` | 13 | 8 | 4 | 3 | 1 | 253.32 | 58.33 |
| [`std.bytes.startsWith`](File-std-bytes-ml-1351945333.md#function-function-std-bytes-startswith-function-startswith-b-prefix-std-bytes-ml-913248740) | `std/bytes.ml:221` | 9 | 5 | 3 | 2 | 1 | 160 | 63.35 |
| [`std.bytes.sub`](File-std-bytes-ml-1351945333.md#function-function-std-bytes-sub-function-sub-b-offset-length-std-bytes-ml-46179299) | `std/bytes.ml:77` | 12 | 7 | 4 | 3 | 1 | 216.64 | 59.57 |
| [`std.bytes.subOrError`](File-std-bytes-ml-1351945333.md#function-function-std-bytes-suborerror-function-suborerror-b-offset-length-std-bytes-ml-710702291) | `std/bytes.ml:95` | 30 | 20 | 10 | 9 | 1 | 754.81 | 46.28 |
| [`std.bytes.toHex`](File-std-bytes-ml-1351945333.md#function-function-std-bytes-tohex-function-tohex-b-std-bytes-ml-835666772) | `std/bytes.ml:341` | 3 | 1 | 1 | 0 | 0 | 46.51 | 77.78 |
| [`std.bytes.writeU16BE`](File-std-bytes-ml-1351945333.md#function-function-std-bytes-writeu16be-function-writeu16be-b-off-value-std-bytes-ml-1415343010) | `std/bytes.ml:498` | 21 | 14 | 7 | 6 | 1 | 523.19 | 51.18 |
| [`std.bytes.writeU16LE`](File-std-bytes-ml-1351945333.md#function-function-std-bytes-writeu16le-function-writeu16le-b-off-value-std-bytes-ml-623641502) | `std/bytes.ml:472` | 21 | 14 | 7 | 6 | 1 | 523.19 | 51.18 |
| [`std.bytes.writeU32BE`](File-std-bytes-ml-1351945333.md#function-function-std-bytes-writeu32be-function-writeu32be-b-off-value-std-bytes-ml-560161774) | `std/bytes.ml:590` | 23 | 16 | 7 | 6 | 1 | 687.1 | 49.49 |
| [`std.bytes.writeU32LE`](File-std-bytes-ml-1351945333.md#function-function-std-bytes-writeu32le-function-writeu32le-b-off-value-std-bytes-ml-720189578) | `std/bytes.ml:562` | 23 | 16 | 7 | 6 | 1 | 687.1 | 49.49 |
| [`std.bytes.writeU8`](File-std-bytes-ml-1351945333.md#function-function-std-bytes-writeu8-function-writeu8-b-off-value-std-bytes-ml-1748622230) | `std/bytes.ml:430` | 20 | 13 | 7 | 6 | 1 | 435.97 | 52.2 |
| [`std.bytes.xor`](File-std-bytes-ml-1351945333.md#function-function-std-bytes-xor-function-xor-a-b-std-bytes-ml-2027129921) | `std/bytes.ml:659` | 19 | 13 | 5 | 4 | 1 | 418.24 | 53.08 |
| [`std.bytes.xorInPlace`](File-std-bytes-ml-1351945333.md#function-function-std-bytes-xorinplace-function-xorinplace-a-b-std-bytes-ml-1831427983) | `std/bytes.ml:684` | 18 | 12 | 5 | 4 | 1 | 380.74 | 53.88 |
| [`std.checksum.crc32.compute`](File-std-checksum-crc32-ml-1964480723.md#function-function-std-checksum-crc32-compute-function-compute-buffer-std-checksum-crc32-ml-1928954823) | `std/checksum/crc32.ml:28` | 4 | 3 | 2 | 1 | 1 | 128 | 71.84 |
| [`std.checksum.crc32.computeRange`](File-std-checksum-crc32-ml-1964480723.md#function-function-std-checksum-crc32-computerange-function-computerange-buffer-offset-length-std-checksum-crc32-ml-443299340) | `std/checksum/crc32.ml:37` | 4 | 3 | 2 | 1 | 1 | 134.89 | 71.68 |
| [`std.checksum.crc32.update`](File-std-checksum-crc32-ml-1964480723.md#function-function-std-checksum-crc32-update-function-update-previous-buffer-offset-length-std-checksum-crc32-ml-1170152687) | `std/checksum/crc32.ml:47` | 4 | 3 | 2 | 1 | 1 | 143.06 | 71.5 |
| [`std.checksum.crc32.verify`](File-std-checksum-crc32-ml-1964480723.md#function-function-std-checksum-crc32-verify-function-verify-buffer-expected-std-checksum-crc32-ml-1834539753) | `std/checksum/crc32.ml:55` | 5 | 4 | 3 | 2 | 1 | 164.23 | 68.84 |
| [`std.checksum.crc32.verifyRange`](File-std-checksum-crc32-ml-1964480723.md#function-function-std-checksum-crc32-verifyrange-function-verifyrange-buffer-offset-length-expected-std-checksum-crc32-ml-384566048) | `std/checksum/crc32.ml:66` | 5 | 4 | 3 | 2 | 1 | 205.13 | 68.16 |
| [`std.checksum.crc32c.compute`](File-std-checksum-crc32c-ml-144026660.md#function-function-std-checksum-crc32c-compute-function-compute-buffer-std-checksum-crc32c-ml-2124890769) | `std/checksum/crc32c.ml:28` | 4 | 3 | 2 | 1 | 1 | 128 | 71.84 |
| [`std.checksum.crc32c.computeRange`](File-std-checksum-crc32c-ml-144026660.md#function-function-std-checksum-crc32c-computerange-function-computerange-buffer-offset-length-std-checksum-crc32c-ml-1768014220) | `std/checksum/crc32c.ml:37` | 4 | 3 | 2 | 1 | 1 | 134.89 | 71.68 |
| [`std.checksum.crc32c.update`](File-std-checksum-crc32c-ml-144026660.md#function-function-std-checksum-crc32c-update-function-update-previous-buffer-offset-length-std-checksum-crc32c-ml-1039557397) | `std/checksum/crc32c.ml:47` | 4 | 3 | 2 | 1 | 1 | 143.06 | 71.5 |
| [`std.checksum.crc32c.verify`](File-std-checksum-crc32c-ml-144026660.md#function-function-std-checksum-crc32c-verify-function-verify-buffer-expected-std-checksum-crc32c-ml-766353659) | `std/checksum/crc32c.ml:55` | 5 | 4 | 3 | 2 | 1 | 164.23 | 68.84 |
| [`std.checksum.crc32c.verifyRange`](File-std-checksum-crc32c-ml-144026660.md#function-function-std-checksum-crc32c-verifyrange-function-verifyrange-buffer-offset-length-expected-std-checksum-crc32c-ml-434060604) | `std/checksum/crc32c.ml:66` | 5 | 4 | 3 | 2 | 1 | 205.13 | 68.16 |
| [`std.concurrent.cancellation.CancellationToken.check`](Type-std-concurrent-cancellation-cancellationtoken-2126484772.md#method-method-std-concurrent-cancellation-cancellationtoken-check-function-check-std-concurrent-cancellation-ml-163271096) | `std/concurrent/cancellation.ml:40` | 6 | 3 | 2 | 1 | 1 | 96 | 68.88 |
| [`std.concurrent.cancellation.CancellationToken.Check`](Type-std-concurrent-cancellation-cancellationtoken-2126484772.md#method-method-std-concurrent-cancellation-cancellationtoken-check-function-check-std-concurrent-cancellation-ml-459292792) | `std/concurrent/cancellation.ml:55` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.concurrent.cancellation.CancellationToken.isCancellationRequested`](Type-std-concurrent-cancellation-cancellationtoken-2126484772.md#method-method-std-concurrent-cancellation-cancellationtoken-iscancellationrequested-function-iscancellationrequested-std-concurrent-cancellation-ml-1369244462) | `std/concurrent/cancellation.ml:21` | 4 | 3 | 2 | 1 | 1 | 109.39 | 72.32 |
| [`std.concurrent.cancellation.CancellationToken.IsCancellationRequested`](Type-std-concurrent-cancellation-cancellationtoken-2126484772.md#method-method-std-concurrent-cancellation-cancellationtoken-iscancellationrequested-function-iscancellationrequested-std-concurrent-cancellation-ml-427321518) | `std/concurrent/cancellation.ml:48` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.concurrent.cancellation.CancellationToken.wait`](Type-std-concurrent-cancellation-cancellationtoken-2126484772.md#method-method-std-concurrent-cancellation-cancellationtoken-wait-function-wait-std-concurrent-cancellation-ml-173979236) | `std/concurrent/cancellation.ml:27` | 4 | 3 | 2 | 1 | 1 | 109.39 | 72.32 |
| [`std.concurrent.cancellation.CancellationToken.Wait`](Type-std-concurrent-cancellation-cancellationtoken-2126484772.md#method-method-std-concurrent-cancellation-cancellationtoken-wait-function-wait-std-concurrent-cancellation-ml-1185604580) | `std/concurrent/cancellation.ml:50` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.concurrent.cancellation.CancellationToken.waitFor`](Type-std-concurrent-cancellation-cancellationtoken-2126484772.md#method-method-std-concurrent-cancellation-cancellationtoken-waitfor-function-waitfor-milliseconds-std-concurrent-cancellation-ml-192213066) | `std/concurrent/cancellation.ml:34` | 4 | 3 | 2 | 1 | 1 | 120 | 72.04 |
| [`std.concurrent.cancellation.CancellationToken.WaitFor`](Type-std-concurrent-cancellation-cancellationtoken-2126484772.md#method-method-std-concurrent-cancellation-cancellationtoken-waitfor-function-waitfor-milliseconds-std-concurrent-cancellation-ml-944284170) | `std/concurrent/cancellation.ml:53` | 1 | 1 | 1 | 0 | 0 | 46.51 | 88.19 |
| [`std.concurrent.cancellation.CancellationTokenSource.Cancel`](Type-std-concurrent-cancellation-cancellationtokensource-1458442689.md#method-method-std-concurrent-cancellation-cancellationtokensource-cancel-function-cancel-std-concurrent-cancellation-ml-462585941) | `std/concurrent/cancellation.ml:137` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.concurrent.cancellation.CancellationTokenSource.cancel`](Type-std-concurrent-cancellation-cancellationtokensource-1458442689.md#method-method-std-concurrent-cancellation-cancellationtokensource-cancel-function-cancel-std-concurrent-cancellation-ml-1744828821) | `std/concurrent/cancellation.ml:85` | 11 | 9 | 4 | 3 | 1 | 284.98 | 59.56 |
| [`std.concurrent.cancellation.CancellationTokenSource.close`](Type-std-concurrent-cancellation-cancellationtokensource-1458442689.md#method-method-std-concurrent-cancellation-cancellationtokensource-close-function-close-std-concurrent-cancellation-ml-2069306449) | `std/concurrent/cancellation.ml:121` | 12 | 10 | 3 | 2 | 1 | 312.16 | 58.59 |
| [`std.concurrent.cancellation.CancellationTokenSource.Dispose`](Type-std-concurrent-cancellation-cancellationtokensource-1458442689.md#method-method-std-concurrent-cancellation-cancellationtokensource-dispose-function-dispose-std-concurrent-cancellation-ml-1933081907) | `std/concurrent/cancellation.ml:141` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.concurrent.cancellation.CancellationTokenSource.isCancellationRequested`](Type-std-concurrent-cancellation-cancellationtokensource-1458442689.md#method-method-std-concurrent-cancellation-cancellationtokensource-iscancellationrequested-function-iscancellationrequested-std-concurrent-cancellation-ml-1684155959) | `std/concurrent/cancellation.ml:100` | 6 | 5 | 2 | 1 | 1 | 141.78 | 67.69 |
| [`std.concurrent.cancellation.CancellationTokenSource.IsCancellationRequested`](Type-std-concurrent-cancellation-cancellationtokensource-1458442689.md#method-method-std-concurrent-cancellation-cancellationtokensource-iscancellationrequested-function-iscancellationrequested-std-concurrent-cancellation-ml-1851143927) | `std/concurrent/cancellation.ml:139` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.concurrent.cancellation.CancellationTokenSource.new`](Type-std-concurrent-cancellation-cancellationtokensource-1458442689.md#static_method-static-method-std-concurrent-cancellation-cancellationtokensource-new-static-function-new-std-concurrent-cancellation-ml-177292884) | `std/concurrent/cancellation.ml:70` | 8 | 1 | 1 | 0 | 0 | 128.93 | 65.39 |
| [`std.concurrent.cancellation.CancellationTokenSource.Token`](Type-std-concurrent-cancellation-cancellationtokensource-1458442689.md#method-method-std-concurrent-cancellation-cancellationtokensource-token-function-token-std-concurrent-cancellation-ml-1903566395) | `std/concurrent/cancellation.ml:135` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.concurrent.cancellation.CancellationTokenSource.token`](Type-std-concurrent-cancellation-cancellationtokensource-1458442689.md#method-method-std-concurrent-cancellation-cancellationtokensource-token-function-token-std-concurrent-cancellation-ml-198279739) | `std/concurrent/cancellation.ml:80` | 3 | 1 | 1 | 0 | 0 | 33 | 78.82 |
| [`std.concurrent.cancellation.CancellationTokenSource.wait`](Type-std-concurrent-cancellation-cancellationtokensource-1458442689.md#method-method-std-concurrent-cancellation-cancellationtokensource-wait-function-wait-std-concurrent-cancellation-ml-1133919633) | `std/concurrent/cancellation.ml:108` | 4 | 3 | 2 | 1 | 1 | 85.11 | 73.08 |
| [`std.concurrent.cancellation.CancellationTokenSource.waitFor`](Type-std-concurrent-cancellation-cancellationtokensource-1458442689.md#method-method-std-concurrent-cancellation-cancellationtokensource-waitfor-function-waitfor-milliseconds-std-concurrent-cancellation-ml-427995255) | `std/concurrent/cancellation.ml:115` | 4 | 3 | 2 | 1 | 1 | 95.18 | 72.74 |
| [`std.concurrent.channel.BoundedQueue.countValue`](Type-std-concurrent-channel-boundedqueue-1937801506.md#method-method-std-concurrent-channel-boundedqueue-countvalue-function-countvalue-std-concurrent-channel-ml-503180078) | `std/concurrent/channel.ml:111` | 6 | 5 | 2 | 1 | 1 | 141.78 | 67.69 |
| [`std.concurrent.channel.BoundedQueue.dispose`](Type-std-concurrent-channel-boundedqueue-1937801506.md#method-method-std-concurrent-channel-boundedqueue-dispose-function-dispose-std-concurrent-channel-ml-1470048932) | `std/concurrent/channel.ml:133` | 9 | 8 | 4 | 3 | 1 | 387.64 | 60.52 |
| [`std.concurrent.channel.BoundedQueue.isSealed`](Type-std-concurrent-channel-boundedqueue-1937801506.md#method-method-std-concurrent-channel-boundedqueue-issealed-function-issealed-std-concurrent-channel-ml-1579367774) | `std/concurrent/channel.ml:119` | 3 | 1 | 1 | 0 | 0 | 46.51 | 77.78 |
| [`std.concurrent.channel.BoundedQueue.new`](Type-std-concurrent-channel-boundedqueue-1937801506.md#static_method-static-method-std-concurrent-channel-boundedqueue-new-static-function-new-capacity-std-concurrent-channel-ml-1067955915) | `std/concurrent/channel.ml:52` | 15 | 1 | 1 | 0 | 0 | 322.84 | 56.64 |
| [`std.concurrent.channel.BoundedQueue.seal`](Type-std-concurrent-channel-boundedqueue-1937801506.md#method-method-std-concurrent-channel-boundedqueue-seal-function-seal-std-concurrent-channel-ml-1060330214) | `std/concurrent/channel.ml:124` | 7 | 8 | 4 | 3 | 1 | 284.98 | 63.84 |
| [`std.concurrent.channel.BoundedQueue.tryPut`](Type-std-concurrent-channel-boundedqueue-1937801506.md#method-method-std-concurrent-channel-boundedqueue-tryput-function-tryput-value-std-concurrent-channel-ml-1780235547) | `std/concurrent/channel.ml:70` | 21 | 20 | 7 | 6 | 1 | 940.8 | 49.4 |
| [`std.concurrent.channel.BoundedQueue.tryTake`](Type-std-concurrent-channel-boundedqueue-1937801506.md#method-method-std-concurrent-channel-boundedqueue-trytake-function-trytake-std-concurrent-channel-ml-1966288618) | `std/concurrent/channel.ml:93` | 15 | 18 | 5 | 4 | 1 | 834.42 | 53.22 |
| [`std.concurrent.channel.Channel.close`](Type-std-concurrent-channel-channel-21011237.md#method-method-std-concurrent-channel-channel-close-function-close-std-concurrent-channel-ml-113930469) | `std/concurrent/channel.ml:209` | 4 | 3 | 2 | 1 | 1 | 87.57 | 73 |
| [`std.concurrent.channel.Channel.Count`](Type-std-concurrent-channel-channel-21011237.md#method-method-std-concurrent-channel-channel-count-function-count-std-concurrent-channel-ml-1978801295) | `std/concurrent/channel.ml:240` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.concurrent.channel.Channel.countValue`](Type-std-concurrent-channel-channel-21011237.md#method-method-std-concurrent-channel-channel-countvalue-function-countvalue-std-concurrent-channel-ml-423376045) | `std/concurrent/channel.ml:204` | 4 | 3 | 2 | 1 | 1 | 85.11 | 73.08 |
| [`std.concurrent.channel.Channel.dispose`](Type-std-concurrent-channel-channel-21011237.md#method-method-std-concurrent-channel-channel-dispose-function-dispose-std-concurrent-channel-ml-738798171) | `std/concurrent/channel.ml:215` | 6 | 6 | 3 | 2 | 1 | 144 | 67.51 |
| [`std.concurrent.channel.Channel.Dispose`](Type-std-concurrent-channel-channel-21011237.md#method-method-std-concurrent-channel-channel-dispose-function-dispose-std-concurrent-channel-ml-894779547) | `std/concurrent/channel.ml:242` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.concurrent.channel.Channel.new`](Type-std-concurrent-channel-channel-21011237.md#static_method-static-method-std-concurrent-channel-channel-new-static-function-new-capacity-std-concurrent-channel-ml-477572384) | `std/concurrent/channel.ml:153` | 6 | 3 | 3 | 2 | 1 | 187.98 | 66.7 |
| [`std.concurrent.channel.Channel.receive`](Type-std-concurrent-channel-channel-21011237.md#method-method-std-concurrent-channel-channel-receive-function-receive-std-concurrent-channel-ml-1619698643) | `std/concurrent/channel.ml:200` | 1 | 1 | 1 | 0 | 0 | 48.43 | 88.07 |
| [`std.concurrent.channel.Channel.Receive`](Type-std-concurrent-channel-channel-21011237.md#method-method-std-concurrent-channel-channel-receive-function-receive-std-concurrent-channel-ml-234908883) | `std/concurrent/channel.ml:233` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.concurrent.channel.Channel.receiveFor`](Type-std-concurrent-channel-channel-21011237.md#method-method-std-concurrent-channel-channel-receivefor-function-receivefor-milliseconds-std-concurrent-channel-ml-983386375) | `std/concurrent/channel.ml:185` | 13 | 14 | 9 | 10 | 2 | 557.41 | 55.26 |
| [`std.concurrent.channel.Channel.ReceiveFor`](Type-std-concurrent-channel-channel-21011237.md#method-method-std-concurrent-channel-channel-receivefor-function-receivefor-milliseconds-std-concurrent-channel-ml-141724103) | `std/concurrent/channel.ml:236` | 1 | 1 | 1 | 0 | 0 | 46.51 | 88.19 |
| [`std.concurrent.channel.Channel.send`](Type-std-concurrent-channel-channel-21011237.md#method-method-std-concurrent-channel-channel-send-function-send-value-std-concurrent-channel-ml-1435514270) | `std/concurrent/channel.ml:178` | 1 | 1 | 1 | 0 | 0 | 62.91 | 87.27 |
| [`std.concurrent.channel.Channel.Send`](Type-std-concurrent-channel-channel-21011237.md#method-method-std-concurrent-channel-channel-send-function-send-value-std-concurrent-channel-ml-867878686) | `std/concurrent/channel.ml:224` | 1 | 1 | 1 | 0 | 0 | 46.51 | 88.19 |
| [`std.concurrent.channel.Channel.sendFor`](Type-std-concurrent-channel-channel-21011237.md#method-method-std-concurrent-channel-channel-sendfor-function-sendfor-value-milliseconds-std-concurrent-channel-ml-388594722) | `std/concurrent/channel.ml:163` | 12 | 13 | 9 | 10 | 2 | 461.64 | 56.59 |
| [`std.concurrent.channel.Channel.SendFor`](Type-std-concurrent-channel-channel-21011237.md#method-method-std-concurrent-channel-channel-sendfor-function-sendfor-value-milliseconds-std-concurrent-channel-ml-564623202) | `std/concurrent/channel.ml:228` | 1 | 1 | 1 | 0 | 0 | 64.53 | 87.19 |
| [`std.concurrent.channel.Channel.tryReceive`](Type-std-concurrent-channel-channel-21011237.md#method-method-std-concurrent-channel-channel-tryreceive-function-tryreceive-std-concurrent-channel-ml-2005260969) | `std/concurrent/channel.ml:202` | 1 | 1 | 1 | 0 | 0 | 43.19 | 88.41 |
| [`std.concurrent.channel.Channel.TryReceive`](Type-std-concurrent-channel-channel-21011237.md#method-method-std-concurrent-channel-channel-tryreceive-function-tryreceive-std-concurrent-channel-ml-1599168617) | `std/concurrent/channel.ml:238` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.concurrent.channel.Channel.trySend`](Type-std-concurrent-channel-channel-21011237.md#method-method-std-concurrent-channel-channel-trysend-function-trysend-value-std-concurrent-channel-ml-416491496) | `std/concurrent/channel.ml:181` | 1 | 1 | 1 | 0 | 0 | 57.36 | 87.55 |
| [`std.concurrent.channel.Channel.TrySend`](Type-std-concurrent-channel-channel-21011237.md#method-method-std-concurrent-channel-channel-trysend-function-trysend-value-std-concurrent-channel-ml-121058408) | `std/concurrent/channel.ml:231` | 1 | 1 | 1 | 0 | 0 | 46.51 | 88.19 |
| [`std.concurrent.shared_value.allocate`](File-std-concurrent-shared-value-ml-2112657235.md#function-function-std-concurrent-shared-value-allocate-function-allocate-size-std-concurrent-shared-value-ml-634200546) | `std/concurrent/shared_value.ml:60` | 4 | 3 | 3 | 2 | 1 | 146.95 | 71.29 |
| [`std.concurrent.shared_value.clearRecordAt`](File-std-concurrent-shared-value-ml-2112657235.md#function-function-std-concurrent-shared-value-clearrecordat-function-clearrecordat-address-std-concurrent-shared-value-ml-353588477) | `std/concurrent/shared_value.ml:198` | 4 | 2 | 1 | 0 | 0 | 85.11 | 73.22 |
| [`std.concurrent.shared_value.destroyAt`](File-std-concurrent-shared-value-ml-2112657235.md#function-function-std-concurrent-shared-value-destroyat-function-destroyat-address-std-concurrent-shared-value-ml-875610501) | `std/concurrent/shared_value.ml:231` | 8 | 5 | 4 | 3 | 1 | 229.25 | 63.24 |
| [`std.concurrent.shared_value.encode`](File-std-concurrent-shared-value-ml-2112657235.md#function-function-std-concurrent-shared-value-encode-function-encode-value-std-concurrent-shared-value-ml-914447698) | `std/concurrent/shared_value.ml:142` | 25 | 24 | 9 | 11 | 2 | 942.93 | 47.47 |
| [`std.concurrent.shared_value.free`](File-std-concurrent-shared-value-ml-2112657235.md#function-function-std-concurrent-shared-value-free-function-free-address-std-concurrent-shared-value-ml-384067739) | `std/concurrent/shared_value.ml:71` | 4 | 3 | 3 | 2 | 1 | 135.93 | 71.53 |
| [`std.concurrent.shared_value.isShareable`](File-std-concurrent-shared-value-ml-2112657235.md#function-function-std-concurrent-shared-value-isshareable-function-isshareable-value-std-concurrent-shared-value-ml-1922324316) | `std/concurrent/shared_value.ml:135` | 4 | 2 | 1 | 0 | 0 | 134.89 | 71.82 |
| [`std.concurrent.shared_value.move`](File-std-concurrent-shared-value-ml-2112657235.md#function-function-std-concurrent-shared-value-move-function-move-destination-source-count-std-concurrent-shared-value-ml-334062803) | `std/concurrent/shared_value.ml:85` | 5 | 4 | 2 | 1 | 1 | 120 | 69.93 |
| [`std.concurrent.shared_value.readAt`](File-std-concurrent-shared-value-ml-2112657235.md#function-function-std-concurrent-shared-value-readat-function-readat-address-std-concurrent-shared-value-ml-1679073383) | `std/concurrent/shared_value.ml:213` | 14 | 18 | 8 | 7 | 1 | 569.35 | 54.63 |
| [`std.concurrent.shared_value.readI64At`](File-std-concurrent-shared-value-ml-2112657235.md#function-function-std-concurrent-shared-value-readi64at-function-readi64at-address-std-concurrent-shared-value-ml-591429923) | `std/concurrent/shared_value.ml:127` | 5 | 3 | 1 | 0 | 0 | 132 | 69.77 |
| [`std.concurrent.shared_value.releaseEncoded`](File-std-concurrent-shared-value-ml-2112657235.md#function-function-std-concurrent-shared-value-releaseencoded-function-releaseencoded-encoded-std-concurrent-shared-value-ml-645091353) | `std/concurrent/shared_value.ml:172` | 8 | 6 | 6 | 5 | 1 | 304.23 | 62.11 |
| [`std.concurrent.shared_value.writeEncodedAt`](File-std-concurrent-shared-value-ml-2112657235.md#function-function-std-concurrent-shared-value-writeencodedat-function-writeencodedat-address-encoded-std-concurrent-shared-value-ml-1480224945) | `std/concurrent/shared_value.ml:184` | 11 | 8 | 4 | 3 | 1 | 435.99 | 58.26 |
| [`std.concurrent.shared_value.writeI64At`](File-std-concurrent-shared-value-ml-2112657235.md#function-function-std-concurrent-shared-value-writei64at-function-writei64at-address-value-std-concurrent-shared-value-ml-1649928982) | `std/concurrent/shared_value.ml:119` | 5 | 3 | 1 | 0 | 0 | 128.93 | 69.84 |
| [`std.concurrent.task.Future.Cancel`](Type-std-concurrent-task-future-1621495977.md#method-method-std-concurrent-task-future-cancel-function-cancel-std-concurrent-task-ml-1703225909) | `std/concurrent/task.ml:107` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.concurrent.task.Future.cancel`](Type-std-concurrent-task-future-1621495977.md#method-method-std-concurrent-task-future-cancel-function-cancel-std-concurrent-task-ml-175448501) | `std/concurrent/task.ml:77` | 9 | 8 | 4 | 3 | 1 | 241.58 | 61.96 |
| [`std.concurrent.task.Future.close`](Type-std-concurrent-task-future-1621495977.md#method-method-std-concurrent-task-future-close-function-close-std-concurrent-task-ml-615943313) | `std/concurrent/task.ml:88` | 10 | 9 | 6 | 5 | 1 | 343.13 | 59.63 |
| [`std.concurrent.task.Future.Dispose`](Type-std-concurrent-task-future-1621495977.md#method-method-std-concurrent-task-future-dispose-function-dispose-std-concurrent-task-ml-667536055) | `std/concurrent/task.ml:109` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.concurrent.task.Future.IsDone`](Type-std-concurrent-task-future-1621495977.md#method-method-std-concurrent-task-future-isdone-function-isdone-std-concurrent-task-ml-1810562205) | `std/concurrent/task.ml:105` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.concurrent.task.Future.isDone`](Type-std-concurrent-task-future-1621495977.md#method-method-std-concurrent-task-future-isdone-function-isdone-std-concurrent-task-ml-1624872349) | `std/concurrent/task.ml:64` | 4 | 3 | 2 | 1 | 1 | 87.57 | 73 |
| [`std.concurrent.task.Future.result`](Type-std-concurrent-task-future-1621495977.md#method-method-std-concurrent-task-future-result-function-result-std-concurrent-task-ml-716603753) | `std/concurrent/task.ml:70` | 5 | 5 | 3 | 2 | 1 | 203.13 | 68.19 |
| [`std.concurrent.task.Future.status`](Type-std-concurrent-task-future-1621495977.md#method-method-std-concurrent-task-future-status-function-status-std-concurrent-task-ml-1165235189) | `std/concurrent/task.ml:58` | 4 | 3 | 2 | 1 | 1 | 87.57 | 73 |
| [`std.concurrent.task.Future.Wait`](Type-std-concurrent-task-future-1621495977.md#method-method-std-concurrent-task-future-wait-function-wait-std-concurrent-task-ml-850498977) | `std/concurrent/task.ml:100` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.concurrent.task.Future.wait`](Type-std-concurrent-task-future-1621495977.md#method-method-std-concurrent-task-future-wait-function-wait-std-concurrent-task-ml-1188844321) | `std/concurrent/task.ml:45` | 4 | 3 | 2 | 1 | 1 | 87.57 | 73 |
| [`std.concurrent.task.Future.WaitFor`](Type-std-concurrent-task-future-1621495977.md#method-method-std-concurrent-task-future-waitfor-function-waitfor-milliseconds-std-concurrent-task-ml-1086060791) | `std/concurrent/task.ml:103` | 1 | 1 | 1 | 0 | 0 | 46.51 | 88.19 |
| [`std.concurrent.task.Future.waitFor`](Type-std-concurrent-task-future-1621495977.md#method-method-std-concurrent-task-future-waitfor-function-waitfor-milliseconds-std-concurrent-task-ml-1176137015) | `std/concurrent/task.ml:52` | 4 | 3 | 2 | 1 | 1 | 97.67 | 72.67 |
| [`std.concurrent.task.run`](File-std-concurrent-task-ml-139288457.md#function-function-std-concurrent-task-run-function-run-pool-callback-data-std-concurrent-task-ml-576679120) | `std/concurrent/task.ml:116` | 5 | 4 | 2 | 1 | 1 | 218.26 | 68.11 |
| [`std.concurrent.task.runCancellable`](File-std-concurrent-task-ml-139288457.md#function-function-std-concurrent-task-runcancellable-function-runcancellable-pool-callback-data-std-concurrent-task-ml-86407698) | `std/concurrent/task.ml:126` | 10 | 7 | 2 | 1 | 1 | 378.33 | 59.87 |
| [`std.concurrent.task.whenAll`](File-std-concurrent-task-ml-139288457.md#function-function-std-concurrent-task-whenall-function-whenall-futures-std-concurrent-task-ml-504238549) | `std/concurrent/task.ml:139` | 13 | 13 | 5 | 6 | 2 | 520.95 | 56 |
| [`std.concurrent.task.whenAny`](File-std-concurrent-task-ml-139288457.md#function-function-std-concurrent-task-whenany-function-whenany-futures-std-concurrent-task-ml-1373291439) | `std/concurrent/task.ml:177` | 3 | 1 | 1 | 0 | 0 | 51.89 | 77.45 |
| [`std.concurrent.task.whenAnyFor`](File-std-concurrent-task-ml-139288457.md#function-function-std-concurrent-task-whenanyfor-function-whenanyfor-futures-milliseconds-std-concurrent-task-ml-1029684509) | `std/concurrent/task.ml:156` | 18 | 19 | 10 | 15 | 3 | 722.57 | 51.25 |
| [`std.concurrent.thread_pool.ThreadPool.AwaitTermination`](Type-std-concurrent-thread-pool-threadpool-1892282200.md#method-method-std-concurrent-thread-pool-threadpool-awaittermination-function-awaittermination-std-concurrent-thread-pool-ml-6637564) | `std/concurrent/thread_pool.ml:506` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.concurrent.thread_pool.ThreadPool.AwaitTerminationFor`](Type-std-concurrent-thread-pool-threadpool-1892282200.md#method-method-std-concurrent-thread-pool-threadpool-awaitterminationfor-function-awaitterminationfor-milliseconds-std-concurrent-thread-pool-ml-1960742116) | `std/concurrent/thread_pool.ml:509` | 1 | 1 | 1 | 0 | 0 | 46.51 | 88.19 |
| [`std.concurrent.thread_pool.ThreadPool.close`](Type-std-concurrent-thread-pool-threadpool-1892282200.md#method-method-std-concurrent-thread-pool-threadpool-close-function-close-std-concurrent-thread-pool-ml-1182797580) | `std/concurrent/thread_pool.ml:474` | 16 | 17 | 6 | 6 | 2 | 600.13 | 53.47 |
| [`std.concurrent.thread_pool.ThreadPool.Dispose`](Type-std-concurrent-thread-pool-threadpool-1892282200.md#method-method-std-concurrent-thread-pool-threadpool-dispose-function-dispose-std-concurrent-thread-pool-ml-1118298946) | `std/concurrent/thread_pool.ml:511` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.concurrent.thread_pool.ThreadPool.isShutdown`](Type-std-concurrent-thread-pool-threadpool-1892282200.md#method-method-std-concurrent-thread-pool-threadpool-isshutdown-function-isshutdown-std-concurrent-thread-pool-ml-811388460) | `std/concurrent/thread_pool.ml:396` | 6 | 5 | 2 | 1 | 1 | 145.95 | 67.6 |
| [`std.concurrent.thread_pool.ThreadPool.IsShutdown`](Type-std-concurrent-thread-pool-threadpool-1892282200.md#method-method-std-concurrent-thread-pool-threadpool-isshutdown-function-isshutdown-std-concurrent-thread-pool-ml-1713408876) | `std/concurrent/thread_pool.ml:500` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.concurrent.thread_pool.ThreadPool.join`](Type-std-concurrent-thread-pool-threadpool-1892282200.md#method-method-std-concurrent-thread-pool-threadpool-join-function-join-std-concurrent-thread-pool-ml-1493137732) | `std/concurrent/thread_pool.ml:444` | 12 | 12 | 5 | 5 | 2 | 402.36 | 57.55 |
| [`std.concurrent.thread_pool.ThreadPool.joinFor`](Type-std-concurrent-thread-pool-threadpool-1892282200.md#method-method-std-concurrent-thread-pool-threadpool-joinfor-function-joinfor-milliseconds-std-concurrent-thread-pool-ml-663703616) | `std/concurrent/thread_pool.ml:459` | 13 | 14 | 8 | 8 | 2 | 541.78 | 55.48 |
| [`std.concurrent.thread_pool.ThreadPool.new`](Type-std-concurrent-thread-pool-threadpool-1892282200.md#static_method-static-method-std-concurrent-thread-pool-threadpool-new-static-function-new-workercount-std-concurrent-thread-pool-ml-1759983018) | `std/concurrent/thread_pool.ml:294` | 3 | 1 | 1 | 0 | 0 | 62.91 | 76.86 |
| [`std.concurrent.thread_pool.ThreadPool.pendingCount`](Type-std-concurrent-thread-pool-threadpool-1892282200.md#method-method-std-concurrent-thread-pool-threadpool-pendingcount-function-pendingcount-std-concurrent-thread-pool-ml-78633876) | `std/concurrent/thread_pool.ml:383` | 6 | 5 | 2 | 1 | 1 | 141.78 | 67.69 |
| [`std.concurrent.thread_pool.ThreadPool.PendingCount`](Type-std-concurrent-thread-pool-threadpool-1892282200.md#method-method-std-concurrent-thread-pool-threadpool-pendingcount-function-pendingcount-std-concurrent-thread-pool-ml-1884661524) | `std/concurrent/thread_pool.ml:496` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.concurrent.thread_pool.ThreadPool.shutdown`](Type-std-concurrent-thread-pool-threadpool-1892282200.md#method-method-std-concurrent-thread-pool-threadpool-shutdown-function-shutdown-std-concurrent-thread-pool-ml-586367372) | `std/concurrent/thread_pool.ml:404` | 12 | 10 | 4 | 3 | 1 | 347.83 | 58.13 |
| [`std.concurrent.thread_pool.ThreadPool.Shutdown`](Type-std-concurrent-thread-pool-threadpool-1892282200.md#method-method-std-concurrent-thread-pool-threadpool-shutdown-function-shutdown-std-concurrent-thread-pool-ml-648357004) | `std/concurrent/thread_pool.ml:502` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.concurrent.thread_pool.ThreadPool.ShutdownNow`](Type-std-concurrent-thread-pool-threadpool-1892282200.md#method-method-std-concurrent-thread-pool-threadpool-shutdownnow-function-shutdownnow-std-concurrent-thread-pool-ml-1083023640) | `std/concurrent/thread_pool.ml:504` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.concurrent.thread_pool.ThreadPool.stop`](Type-std-concurrent-thread-pool-threadpool-1892282200.md#method-method-std-concurrent-thread-pool-threadpool-stop-function-stop-std-concurrent-thread-pool-ml-1402724008) | `std/concurrent/thread_pool.ml:418` | 24 | 22 | 6 | 6 | 2 | 856.15 | 48.55 |
| [`std.concurrent.thread_pool.ThreadPool.submit`](Type-std-concurrent-thread-pool-threadpool-1892282200.md#method-method-std-concurrent-thread-pool-threadpool-submit-function-submit-callback-data-std-concurrent-thread-pool-ml-704351741) | `std/concurrent/thread_pool.ml:350` | 31 | 26 | 8 | 7 | 1 | 1013.76 | 45.34 |
| [`std.concurrent.thread_pool.ThreadPool.Submit`](Type-std-concurrent-thread-pool-threadpool-1892282200.md#method-method-std-concurrent-thread-pool-threadpool-submit-function-submit-callback-data-std-concurrent-thread-pool-ml-1887013117) | `std/concurrent/thread_pool.ml:494` | 1 | 1 | 1 | 0 | 0 | 64.53 | 87.19 |
| [`std.concurrent.thread_pool.ThreadPool.withQueueCapacity`](Type-std-concurrent-thread-pool-threadpool-1892282200.md#static_method-static-method-std-concurrent-thread-pool-threadpool-withqueuecapacity-static-function-withqueuecapacity-workercount-queuecapacity-std-concurrent-thread-pool-ml-10704545) | `std/concurrent/thread_pool.ml:301` | 43 | 23 | 9 | 11 | 3 | 1381.86 | 41.17 |
| [`std.concurrent.thread_pool.ThreadPool.workerCount`](Type-std-concurrent-thread-pool-threadpool-1892282200.md#method-method-std-concurrent-thread-pool-threadpool-workercount-function-workercount-std-concurrent-thread-pool-ml-724788614) | `std/concurrent/thread_pool.ml:391` | 3 | 1 | 1 | 0 | 0 | 43.19 | 78.01 |
| [`std.concurrent.thread_pool.ThreadPool.WorkerCount`](Type-std-concurrent-thread-pool-threadpool-1892282200.md#method-method-std-concurrent-thread-pool-threadpool-workercount-function-workercount-std-concurrent-thread-pool-ml-609593798) | `std/concurrent/thread_pool.ml:498` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.concurrent.thread_pool.ThreadPoolJob.cancel`](Type-std-concurrent-thread-pool-threadpooljob-859238811.md#method-method-std-concurrent-thread-pool-threadpooljob-cancel-function-cancel-std-concurrent-thread-pool-ml-1078125767) | `std/concurrent/thread_pool.ml:105` | 13 | 11 | 4 | 3 | 1 | 350.94 | 57.34 |
| [`std.concurrent.thread_pool.ThreadPoolJob.Cancel`](Type-std-concurrent-thread-pool-threadpooljob-859238811.md#method-method-std-concurrent-thread-pool-threadpooljob-cancel-function-cancel-std-concurrent-thread-pool-ml-1381498503) | `std/concurrent/thread_pool.ml:181` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.concurrent.thread_pool.ThreadPoolJob.close`](Type-std-concurrent-thread-pool-threadpooljob-859238811.md#method-method-std-concurrent-thread-pool-threadpooljob-close-function-close-std-concurrent-thread-pool-ml-957207643) | `std/concurrent/thread_pool.ml:160` | 16 | 14 | 4 | 3 | 1 | 539.75 | 54.06 |
| [`std.concurrent.thread_pool.ThreadPoolJob.Dispose`](Type-std-concurrent-thread-pool-threadpooljob-859238811.md#method-method-std-concurrent-thread-pool-threadpooljob-dispose-function-dispose-std-concurrent-thread-pool-ml-689250869) | `std/concurrent/thread_pool.ml:196` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.concurrent.thread_pool.ThreadPoolJob.getResult`](Type-std-concurrent-thread-pool-threadpooljob-859238811.md#method-method-std-concurrent-thread-pool-threadpooljob-getresult-function-getresult-std-concurrent-thread-pool-ml-1087002137) | `std/concurrent/thread_pool.ml:141` | 6 | 5 | 2 | 1 | 1 | 134.89 | 67.84 |
| [`std.concurrent.thread_pool.ThreadPoolJob.GetResult`](Type-std-concurrent-thread-pool-threadpooljob-859238811.md#method-method-std-concurrent-thread-pool-threadpooljob-getresult-function-getresult-std-concurrent-thread-pool-ml-1209365721) | `std/concurrent/thread_pool.ml:190` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.concurrent.thread_pool.ThreadPoolJob.getStatus`](Type-std-concurrent-thread-pool-threadpooljob-859238811.md#method-method-std-concurrent-thread-pool-threadpooljob-getstatus-function-getstatus-std-concurrent-thread-pool-ml-223169015) | `std/concurrent/thread_pool.ml:133` | 6 | 5 | 2 | 1 | 1 | 141.78 | 67.69 |
| [`std.concurrent.thread_pool.ThreadPoolJob.GetStatus`](Type-std-concurrent-thread-pool-threadpooljob-859238811.md#method-method-std-concurrent-thread-pool-threadpooljob-getstatus-function-getstatus-std-concurrent-thread-pool-ml-1285725111) | `std/concurrent/thread_pool.ml:188` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.concurrent.thread_pool.ThreadPoolJob.isCancelled`](Type-std-concurrent-thread-pool-threadpooljob-859238811.md#method-method-std-concurrent-thread-pool-threadpooljob-iscancelled-function-iscancelled-std-concurrent-thread-pool-ml-502201925) | `std/concurrent/thread_pool.ml:155` | 3 | 1 | 1 | 0 | 0 | 48.43 | 77.66 |
| [`std.concurrent.thread_pool.ThreadPoolJob.IsCancelled`](Type-std-concurrent-thread-pool-threadpooljob-859238811.md#method-method-std-concurrent-thread-pool-threadpooljob-iscancelled-function-iscancelled-std-concurrent-thread-pool-ml-1595104197) | `std/concurrent/thread_pool.ml:194` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.concurrent.thread_pool.ThreadPoolJob.isDone`](Type-std-concurrent-thread-pool-threadpooljob-859238811.md#method-method-std-concurrent-thread-pool-threadpooljob-isdone-function-isdone-std-concurrent-thread-pool-ml-1101974527) | `std/concurrent/thread_pool.ml:149` | 4 | 2 | 1 | 0 | 0 | 100 | 72.73 |
| [`std.concurrent.thread_pool.ThreadPoolJob.IsDone`](Type-std-concurrent-thread-pool-threadpooljob-859238811.md#method-method-std-concurrent-thread-pool-threadpooljob-isdone-function-isdone-std-concurrent-thread-pool-ml-666330559) | `std/concurrent/thread_pool.ml:192` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.concurrent.thread_pool.ThreadPoolJob.new`](Type-std-concurrent-thread-pool-threadpooljob-859238811.md#static_method-static-method-std-concurrent-thread-pool-threadpooljob-new-static-function-new-callback-data-std-concurrent-thread-pool-ml-1751013359) | `std/concurrent/thread_pool.ml:53` | 13 | 3 | 1 | 0 | 0 | 214.05 | 59.25 |
| [`std.concurrent.thread_pool.ThreadPoolJob.wait`](Type-std-concurrent-thread-pool-threadpooljob-859238811.md#method-method-std-concurrent-thread-pool-threadpooljob-wait-function-wait-std-concurrent-thread-pool-ml-60910587) | `std/concurrent/thread_pool.ml:120` | 4 | 3 | 2 | 1 | 1 | 85.11 | 73.08 |
| [`std.concurrent.thread_pool.ThreadPoolJob.Wait`](Type-std-concurrent-thread-pool-threadpooljob-859238811.md#method-method-std-concurrent-thread-pool-threadpooljob-wait-function-wait-std-concurrent-thread-pool-ml-1518778939) | `std/concurrent/thread_pool.ml:183` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.concurrent.thread_pool.ThreadPoolJob.waitFor`](Type-std-concurrent-thread-pool-threadpooljob-859238811.md#method-method-std-concurrent-thread-pool-threadpooljob-waitfor-function-waitfor-milliseconds-std-concurrent-thread-pool-ml-378084097) | `std/concurrent/thread_pool.ml:127` | 4 | 3 | 2 | 1 | 1 | 95.18 | 72.74 |
| [`std.concurrent.thread_pool.ThreadPoolJob.WaitFor`](Type-std-concurrent-thread-pool-threadpooljob-859238811.md#method-method-std-concurrent-thread-pool-threadpooljob-waitfor-function-waitfor-milliseconds-std-concurrent-thread-pool-ml-1383667777) | `std/concurrent/thread_pool.ml:186` | 1 | 1 | 1 | 0 | 0 | 46.51 | 88.19 |
| [`std.console.disableQuickEdit`](File-std-console-ml-1875579671.md#function-function-std-console-disablequickedit-function-disablequickedit-std-console-ml-1305818672) | `std/console.ml:109` | 10 | 11 | 6 | 5 | 1 | 442.8 | 58.85 |
| [`std.console.isInteractive`](File-std-console-ml-1875579671.md#function-function-std-console-isinteractive-function-isinteractive-std-console-ml-470243024) | `std/console.ml:97` | 6 | 5 | 3 | 2 | 1 | 185.47 | 66.74 |
| [`std.console.readPassword`](File-std-console-ml-1875579671.md#function-function-std-console-readpassword-function-readpassword-prompt-std-console-ml-1668045086) | `std/console.ml:181` | 3 | 1 | 1 | 0 | 0 | 46.51 | 77.78 |
| [`std.console.readSecret`](File-std-console-ml-1875579671.md#function-function-std-console-readsecret-function-readsecret-prompt-maximumbytes-std-console-ml-989090479) | `std/console.ml:125` | 42 | 50 | 24 | 24 | 2 | 2884.23 | 37.14 |
| [`std.console.readSecretConfirmed`](File-std-console-ml-1875579671.md#function-function-std-console-readsecretconfirmed-function-readsecretconfirmed-prompt-confirmationprompt-maximumbytes-std-console-ml-500058034) | `std/console.ml:189` | 10 | 13 | 4 | 3 | 1 | 404.24 | 59.4 |
| [`std.console.wipe`](File-std-console-ml-1875579671.md#function-function-std-console-wipe-function-wipe-buffer-std-console-ml-1632003642) | `std/console.ml:53` | 5 | 5 | 3 | 2 | 1 | 186.91 | 68.44 |
| [`std.core.abs`](File-std-core-ml-750389783.md#function-function-std-core-abs-function-abs-x-std-core-ml-390262774) | `std/core.ml:125` | 6 | 3 | 2 | 1 | 1 | 68.11 | 69.92 |
| [`std.core.clamp`](File-std-core-ml-750389783.md#function-function-std-core-clamp-function-clamp-x-lo-hi-std-core-ml-150268134) | `std/core.ml:113` | 9 | 5 | 3 | 2 | 1 | 118.03 | 64.27 |
| [`std.core.coalesce`](File-std-core-ml-750389783.md#function-function-std-core-coalesce-function-coalesce-x-fallback-std-core-ml-1995835884) | `std/core.ml:82` | 6 | 3 | 2 | 1 | 1 | 87.57 | 69.16 |
| [`std.core.isArray`](File-std-core-ml-750389783.md#function-function-std-core-isarray-function-isarray-x-std-core-ml-378530128) | `std/core.ml:69` | 3 | 1 | 1 | 0 | 0 | 46.51 | 77.78 |
| [`std.core.isBool`](File-std-core-ml-750389783.md#function-function-std-core-isbool-function-isbool-x-std-core-ml-877919882) | `std/core.ml:57` | 3 | 1 | 1 | 0 | 0 | 46.51 | 77.78 |
| [`std.core.isFloat`](File-std-core-ml-750389783.md#function-function-std-core-isfloat-function-isfloat-x-std-core-ml-313162674) | `std/core.ml:44` | 3 | 1 | 1 | 0 | 0 | 46.51 | 77.78 |
| [`std.core.isFunction`](File-std-core-ml-750389783.md#function-function-std-core-isfunction-function-isfunction-x-std-core-ml-1168317218) | `std/core.ml:75` | 3 | 1 | 1 | 0 | 0 | 46.51 | 77.78 |
| [`std.core.isInt`](File-std-core-ml-750389783.md#function-function-std-core-isint-function-isint-x-std-core-ml-935704364) | `std/core.ml:38` | 3 | 1 | 1 | 0 | 0 | 46.51 | 77.78 |
| [`std.core.isNumber`](File-std-core-ml-750389783.md#function-function-std-core-isnumber-function-isnumber-x-std-core-ml-1560296318) | `std/core.ml:50` | 4 | 2 | 1 | 0 | 0 | 79.95 | 73.41 |
| [`std.core.isString`](File-std-core-ml-750389783.md#function-function-std-core-isstring-function-isstring-x-std-core-ml-2010892826) | `std/core.ml:63` | 3 | 1 | 1 | 0 | 0 | 46.51 | 77.78 |
| [`std.core.isVoid`](File-std-core-ml-750389783.md#function-function-std-core-isvoid-function-isvoid-x-std-core-ml-1825949782) | `std/core.ml:32` | 3 | 1 | 1 | 0 | 0 | 46.51 | 77.78 |
| [`std.core.max`](File-std-core-ml-750389783.md#function-function-std-core-max-function-max-a-b-std-core-ml-735947893) | `std/core.ml:102` | 6 | 3 | 2 | 1 | 1 | 71.7 | 69.76 |
| [`std.core.min`](File-std-core-ml-750389783.md#function-function-std-core-min-function-min-a-b-std-core-ml-1618154621) | `std/core.ml:92` | 6 | 3 | 2 | 1 | 1 | 71.7 | 69.76 |
| [`std.core.safeLen`](File-std-core-ml-750389783.md#function-function-std-core-safelen-function-safelen-x-fallback-std-core-ml-2007178136) | `std/core.ml:147` | 7 | 4 | 4 | 3 | 1 | 159.91 | 65.6 |
| [`std.core.safeToNumber`](File-std-core-ml-750389783.md#function-function-std-core-safetonumber-function-safetonumber-x-fallback-std-core-ml-527887072) | `std/core.ml:158` | 7 | 4 | 2 | 1 | 1 | 118.54 | 66.77 |
| [`std.core.sign`](File-std-core-ml-750389783.md#function-function-std-core-sign-function-sign-x-std-core-ml-1151146318) | `std/core.ml:134` | 9 | 5 | 3 | 2 | 1 | 106.61 | 64.58 |
| [`std.cpu.activeFeatures`](File-std-cpu-ml-1561418518.md#function-function-std-cpu-activefeatures-function-activefeatures-std-cpu-ml-774821314) | `std/cpu.ml:42` | 3 | 1 | 1 | 0 | 0 | 28.07 | 79.32 |
| [`std.cpu.features`](File-std-cpu-ml-1561418518.md#function-function-std-cpu-features-function-features-std-cpu-ml-440708594) | `std/cpu.ml:37` | 3 | 1 | 1 | 0 | 0 | 28.07 | 79.32 |
| [`std.cpu.setDispatchMaskForTesting`](File-std-cpu-ml-1561418518.md#function-function-std-cpu-setdispatchmaskfortesting-function-setdispatchmaskfortesting-mask-std-cpu-ml-816780596) | `std/cpu.ml:48` | 3 | 1 | 1 | 0 | 0 | 36 | 78.56 |
| [`std.crypto.aes_gcm.decrypt`](File-std-crypto-aes-gcm-ml-264581731.md#function-function-std-crypto-aes-gcm-decrypt-function-decrypt-key-nonce-ciphertext-tag-aad-std-crypto-aes-gcm-ml-485061609) | `std/crypto/aes_gcm.ml:107` | 4 | 3 | 3 | 2 | 1 | 248.8 | 69.69 |
| [`std.crypto.aes_gcm.encrypt`](File-std-crypto-aes-gcm-ml-264581731.md#function-function-std-crypto-aes-gcm-encrypt-function-encrypt-key-nonce-plaintext-aad-taglength-std-crypto-aes-gcm-ml-125820132) | `std/crypto/aes_gcm.ml:94` | 6 | 5 | 2 | 1 | 1 | 329.03 | 65.13 |
| [`std.crypto.aes_gcm.open`](File-std-crypto-aes-gcm-ml-264581731.md#function-function-std-crypto-aes-gcm-open-function-open-key-nonce-sealed-aad-taglength-std-crypto-aes-gcm-ml-1220352403) | `std/crypto/aes_gcm.ml:77` | 10 | 6 | 5 | 4 | 1 | 468.05 | 58.82 |
| [`std.crypto.aes_gcm.seal`](File-std-crypto-aes-gcm-ml-264581731.md#function-function-std-crypto-aes-gcm-seal-function-seal-key-nonce-plaintext-aad-taglength-std-crypto-aes-gcm-ml-1614549846) | `std/crypto/aes_gcm.ml:59` | 11 | 8 | 5 | 4 | 1 | 531.36 | 57.53 |
| [`std.crypto.constantTimeEquals`](File-std-crypto-ml-1263151193.md#function-function-std-crypto-constanttimeequals-function-constanttimeequals-a-b-std-crypto-ml-1925949949) | `std/crypto.ml:148` | 4 | 3 | 3 | 2 | 1 | 143.06 | 71.37 |
| [`std.crypto.hkdfSha256`](File-std-crypto-ml-1263151193.md#function-function-std-crypto-hkdfsha256-function-hkdfsha256-inputkeymaterial-salt-info-length-std-crypto-ml-1740727018) | `std/crypto.ml:94` | 3 | 1 | 1 | 0 | 0 | 106.61 | 75.26 |
| [`std.crypto.hkdfSha384`](File-std-crypto-ml-1263151193.md#function-function-std-crypto-hkdfsha384-function-hkdfsha384-inputkeymaterial-salt-info-length-std-crypto-ml-1751700406) | `std/crypto.ml:103` | 3 | 1 | 1 | 0 | 0 | 106.61 | 75.26 |
| [`std.crypto.hmacSha256`](File-std-crypto-ml-1263151193.md#function-function-std-crypto-hmacsha256-function-hmacsha256-key-input-std-crypto-ml-689688099) | `std/crypto.ml:56` | 6 | 6 | 4 | 3 | 1 | 302.86 | 65.11 |
| [`std.crypto.hmacSha384`](File-std-crypto-ml-1263151193.md#function-function-std-crypto-hmacsha384-function-hmacsha384-key-input-std-crypto-ml-1206696471) | `std/crypto.ml:66` | 6 | 6 | 4 | 3 | 1 | 302.86 | 65.11 |
| [`std.crypto.pbkdf2Sha256`](File-std-crypto-ml-1263151193.md#function-function-std-crypto-pbkdf2sha256-function-pbkdf2sha256-password-salt-iterations-length-std-crypto-ml-1283186663) | `std/crypto.ml:123` | 3 | 1 | 1 | 0 | 0 | 96.21 | 75.57 |
| [`std.crypto.pbkdf2Sha384`](File-std-crypto-ml-1263151193.md#function-function-std-crypto-pbkdf2sha384-function-pbkdf2sha384-password-salt-iterations-length-std-crypto-ml-2002863367) | `std/crypto.ml:132` | 3 | 1 | 1 | 0 | 0 | 96.21 | 75.57 |
| [`std.crypto.secureRandom`](File-std-crypto-ml-1263151193.md#function-function-std-crypto-securerandom-function-securerandom-length-std-crypto-ml-287450256) | `std/crypto.ml:138` | 6 | 6 | 5 | 4 | 1 | 269.21 | 65.34 |
| [`std.crypto.secureZero`](File-std-crypto-ml-1263151193.md#function-function-std-crypto-securezero-function-securezero-buffer-std-crypto-ml-1706379390) | `std/crypto.ml:155` | 5 | 5 | 3 | 2 | 1 | 186.91 | 68.44 |
| [`std.crypto.sha256`](File-std-crypto-ml-1263151193.md#function-function-std-crypto-sha256-function-sha256-input-std-crypto-ml-2117608982) | `std/crypto.ml:37` | 6 | 6 | 3 | 2 | 1 | 256.76 | 65.75 |
| [`std.crypto.sha384`](File-std-crypto-ml-1263151193.md#function-function-std-crypto-sha384-function-sha384-input-std-crypto-ml-534054486) | `std/crypto.ml:46` | 6 | 6 | 3 | 2 | 1 | 256.76 | 65.75 |
| [`std.crypto.x25519`](File-std-crypto-ml-1263151193.md#function-function-std-crypto-x25519-function-x25519-privatekey-peerpublickey-std-crypto-ml-1569573420) | `std/crypto.ml:173` | 14 | 14 | 7 | 6 | 1 | 590.19 | 54.65 |
| [`std.crypto.x25519PublicKey`](File-std-crypto-ml-1263151193.md#function-function-std-crypto-x25519publickey-function-x25519publickey-privatekey-std-crypto-ml-664480438) | `std/crypto.ml:163` | 6 | 6 | 4 | 3 | 1 | 271.03 | 65.45 |
| [`std.ds.concurrent_hashmap.ThreadSafeHashMap.clear`](Type-std-ds-concurrent-hashmap-threadsafehashmap-551487914.md#method-method-std-ds-concurrent-hashmap-threadsafehashmap-clear-function-clear-std-ds-concurrent-hashmap-ml-1301294917) | `std/ds/concurrent_hashmap.ml:308` | 13 | 11 | 3 | 2 | 1 | 371.51 | 57.3 |
| [`std.ds.concurrent_hashmap.ThreadSafeHashMap.close`](Type-std-ds-concurrent-hashmap-threadsafehashmap-551487914.md#method-method-std-ds-concurrent-hashmap-threadsafehashmap-close-function-close-std-ds-concurrent-hashmap-ml-869858615) | `std/ds/concurrent_hashmap.ml:386` | 12 | 11 | 3 | 2 | 1 | 347.11 | 58.27 |
| [`std.ds.concurrent_hashmap.ThreadSafeHashMap.count`](Type-std-ds-concurrent-hashmap-threadsafehashmap-551487914.md#method-method-std-ds-concurrent-hashmap-threadsafehashmap-count-function-count-std-ds-concurrent-hashmap-ml-2095071105) | `std/ds/concurrent_hashmap.ml:147` | 7 | 7 | 3 | 2 | 1 | 191.16 | 65.19 |
| [`std.ds.concurrent_hashmap.ThreadSafeHashMap.delete`](Type-std-ds-concurrent-hashmap-threadsafehashmap-551487914.md#method-method-std-ds-concurrent-hashmap-threadsafehashmap-delete-function-delete-key-std-ds-concurrent-hashmap-ml-886823762) | `std/ds/concurrent_hashmap.ml:303` | 3 | 1 | 1 | 0 | 0 | 46.51 | 77.78 |
| [`std.ds.concurrent_hashmap.ThreadSafeHashMap.entriesArray`](Type-std-ds-concurrent-hashmap-threadsafehashmap-551487914.md#method-method-std-ds-concurrent-hashmap-threadsafehashmap-entriesarray-function-entriesarray-std-ds-concurrent-hashmap-ml-1527597983) | `std/ds/concurrent_hashmap.ml:365` | 19 | 15 | 5 | 5 | 2 | 574.48 | 52.11 |
| [`std.ds.concurrent_hashmap.ThreadSafeHashMap.get`](Type-std-ds-concurrent-hashmap-threadsafehashmap-551487914.md#method-method-std-ds-concurrent-hashmap-threadsafehashmap-get-function-get-key-std-ds-concurrent-hashmap-ml-113965598) | `std/ds/concurrent_hashmap.ml:211` | 15 | 12 | 5 | 4 | 1 | 465 | 54.99 |
| [`std.ds.concurrent_hashmap.ThreadSafeHashMap.getOr`](Type-std-ds-concurrent-hashmap-threadsafehashmap-551487914.md#method-method-std-ds-concurrent-hashmap-threadsafehashmap-getor-function-getor-key-fallback-std-ds-concurrent-hashmap-ml-1939592210) | `std/ds/concurrent_hashmap.ml:230` | 15 | 12 | 5 | 4 | 1 | 494.35 | 54.81 |
| [`std.ds.concurrent_hashmap.ThreadSafeHashMap.has`](Type-std-ds-concurrent-hashmap-threadsafehashmap-551487914.md#method-method-std-ds-concurrent-hashmap-threadsafehashmap-has-function-has-key-std-ds-concurrent-hashmap-ml-169138350) | `std/ds/concurrent_hashmap.ml:199` | 9 | 7 | 4 | 3 | 1 | 331.71 | 61 |
| [`std.ds.concurrent_hashmap.ThreadSafeHashMap.increment`](Type-std-ds-concurrent-hashmap-threadsafehashmap-551487914.md#method-method-std-ds-concurrent-hashmap-threadsafehashmap-increment-function-increment-key-delta-std-ds-concurrent-hashmap-ml-1786891598) | `std/ds/concurrent_hashmap.ml:249` | 30 | 26 | 8 | 8 | 2 | 1222.01 | 45.09 |
| [`std.ds.concurrent_hashmap.ThreadSafeHashMap.isClosed`](Type-std-ds-concurrent-hashmap-threadsafehashmap-551487914.md#method-method-std-ds-concurrent-hashmap-threadsafehashmap-isclosed-function-isclosed-std-ds-concurrent-hashmap-ml-1082109163) | `std/ds/concurrent_hashmap.ml:166` | 3 | 1 | 1 | 0 | 0 | 31.7 | 78.95 |
| [`std.ds.concurrent_hashmap.ThreadSafeHashMap.isEmpty`](Type-std-ds-concurrent-hashmap-threadsafehashmap-551487914.md#method-method-std-ds-concurrent-hashmap-threadsafehashmap-isempty-function-isempty-std-ds-concurrent-hashmap-ml-1917850989) | `std/ds/concurrent_hashmap.ml:161` | 3 | 1 | 1 | 0 | 0 | 48.43 | 77.66 |
| [`std.ds.concurrent_hashmap.ThreadSafeHashMap.keysArray`](Type-std-ds-concurrent-hashmap-threadsafehashmap-551487914.md#method-method-std-ds-concurrent-hashmap-threadsafehashmap-keysarray-function-keysarray-std-ds-concurrent-hashmap-ml-664401893) | `std/ds/concurrent_hashmap.ml:323` | 19 | 15 | 5 | 5 | 2 | 510 | 52.47 |
| [`std.ds.concurrent_hashmap.ThreadSafeHashMap.len`](Type-std-ds-concurrent-hashmap-threadsafehashmap-551487914.md#method-method-std-ds-concurrent-hashmap-threadsafehashmap-len-function-len-std-ds-concurrent-hashmap-ml-1950357417) | `std/ds/concurrent_hashmap.ml:156` | 3 | 1 | 1 | 0 | 0 | 38.04 | 78.39 |
| [`std.ds.concurrent_hashmap.ThreadSafeHashMap.new`](Type-std-ds-concurrent-hashmap-threadsafehashmap-551487914.md#static_method-static-method-std-ds-concurrent-hashmap-threadsafehashmap-new-static-function-new-std-ds-concurrent-hashmap-ml-2047700696) | `std/ds/concurrent_hashmap.ml:108` | 3 | 1 | 1 | 0 | 0 | 48.43 | 77.66 |
| [`std.ds.concurrent_hashmap.ThreadSafeHashMap.remove`](Type-std-ds-concurrent-hashmap-threadsafehashmap-551487914.md#method-method-std-ds-concurrent-hashmap-threadsafehashmap-remove-function-remove-key-std-ds-concurrent-hashmap-ml-1236541502) | `std/ds/concurrent_hashmap.ml:282` | 18 | 15 | 5 | 4 | 1 | 625.56 | 52.37 |
| [`std.ds.concurrent_hashmap.ThreadSafeHashMap.set`](Type-std-ds-concurrent-hashmap-threadsafehashmap-551487914.md#method-method-std-ds-concurrent-hashmap-threadsafehashmap-set-function-set-key-value-std-ds-concurrent-hashmap-ml-2134634419) | `std/ds/concurrent_hashmap.ml:173` | 23 | 18 | 7 | 6 | 1 | 889.91 | 48.7 |
| [`std.ds.concurrent_hashmap.ThreadSafeHashMap.valuesArray`](Type-std-ds-concurrent-hashmap-threadsafehashmap-551487914.md#method-method-std-ds-concurrent-hashmap-threadsafehashmap-valuesarray-function-valuesarray-std-ds-concurrent-hashmap-ml-1895275761) | `std/ds/concurrent_hashmap.ml:344` | 19 | 15 | 5 | 5 | 2 | 510 | 52.47 |
| [`std.ds.concurrent_hashmap.ThreadSafeHashMap.withCapacity`](Type-std-ds-concurrent-hashmap-threadsafehashmap-551487914.md#static_method-static-method-std-ds-concurrent-hashmap-threadsafehashmap-withcapacity-static-function-withcapacity-minimumbuckets-std-ds-concurrent-hashmap-ml-1092752747) | `std/ds/concurrent_hashmap.ml:114` | 8 | 5 | 3 | 2 | 1 | 346.79 | 62.11 |
| [`std.ds.concurrent_list.ThreadSafeList.add`](Type-std-ds-concurrent-list-threadsafelist-78742376.md#method-method-std-ds-concurrent-list-threadsafelist-add-function-add-value-std-ds-concurrent-list-ml-1193809212) | `std/ds/concurrent_list.ml:129` | 12 | 10 | 3 | 2 | 1 | 352.53 | 58.22 |
| [`std.ds.concurrent_list.ThreadSafeList.addAll`](Type-std-ds-concurrent-list-threadsafelist-78742376.md#method-method-std-ds-concurrent-list-threadsafelist-addall-function-addall-values-std-ds-concurrent-list-ml-1924274557) | `std/ds/concurrent_list.ml:150` | 17 | 15 | 5 | 4 | 1 | 559.62 | 53.25 |
| [`std.ds.concurrent_list.ThreadSafeList.clear`](Type-std-ds-concurrent-list-threadsafelist-78742376.md#method-method-std-ds-concurrent-list-threadsafelist-clear-function-clear-std-ds-concurrent-list-ml-2030947113) | `std/ds/concurrent_list.ml:281` | 15 | 12 | 4 | 3 | 1 | 355.74 | 55.94 |
| [`std.ds.concurrent_list.ThreadSafeList.close`](Type-std-ds-concurrent-list-threadsafelist-78742376.md#method-method-std-ds-concurrent-list-threadsafelist-close-function-close-std-ds-concurrent-list-ml-1917022135) | `std/ds/concurrent_list.ml:315` | 10 | 9 | 3 | 2 | 1 | 283.28 | 60.61 |
| [`std.ds.concurrent_list.ThreadSafeList.count`](Type-std-ds-concurrent-list-threadsafelist-78742376.md#method-method-std-ds-concurrent-list-threadsafelist-count-function-count-std-ds-concurrent-list-ml-174601541) | `std/ds/concurrent_list.ml:102` | 3 | 1 | 1 | 0 | 0 | 38.04 | 78.39 |
| [`std.ds.concurrent_list.ThreadSafeList.first`](Type-std-ds-concurrent-list-threadsafelist-78742376.md#method-method-std-ds-concurrent-list-threadsafelist-first-function-first-std-ds-concurrent-list-ml-1203419835) | `std/ds/concurrent_list.ml:198` | 3 | 1 | 1 | 0 | 0 | 43.19 | 78.01 |
| [`std.ds.concurrent_list.ThreadSafeList.fromArray`](Type-std-ds-concurrent-list-threadsafelist-78742376.md#static_method-static-method-std-ds-concurrent-list-threadsafelist-fromarray-static-function-fromarray-values-std-ds-concurrent-list-ml-1166086536) | `std/ds/concurrent_list.ml:63` | 12 | 8 | 3 | 2 | 1 | 320 | 58.51 |
| [`std.ds.concurrent_list.ThreadSafeList.get`](Type-std-ds-concurrent-list-threadsafelist-78742376.md#method-method-std-ds-concurrent-list-threadsafelist-get-function-get-index-std-ds-concurrent-list-ml-1342810797) | `std/ds/concurrent_list.ml:170` | 11 | 10 | 6 | 5 | 1 | 354.63 | 58.62 |
| [`std.ds.concurrent_list.ThreadSafeList.insert`](Type-std-ds-concurrent-list-threadsafelist-78742376.md#method-method-std-ds-concurrent-list-threadsafelist-insert-function-insert-index-value-std-ds-concurrent-list-ml-1673287280) | `std/ds/concurrent_list.ml:217` | 18 | 16 | 7 | 6 | 1 | 671.73 | 51.88 |
| [`std.ds.concurrent_list.ThreadSafeList.isClosed`](Type-std-ds-concurrent-list-threadsafelist-78742376.md#method-method-std-ds-concurrent-list-threadsafelist-isclosed-function-isclosed-std-ds-concurrent-list-ml-1449244539) | `std/ds/concurrent_list.ml:112` | 3 | 1 | 1 | 0 | 0 | 31.7 | 78.95 |
| [`std.ds.concurrent_list.ThreadSafeList.isEmpty`](Type-std-ds-concurrent-list-threadsafelist-78742376.md#method-method-std-ds-concurrent-list-threadsafelist-isempty-function-isempty-std-ds-concurrent-list-ml-964418993) | `std/ds/concurrent_list.ml:107` | 3 | 1 | 1 | 0 | 0 | 48.43 | 77.66 |
| [`std.ds.concurrent_list.ThreadSafeList.last`](Type-std-ds-concurrent-list-threadsafelist-78742376.md#method-method-std-ds-concurrent-list-threadsafelist-last-function-last-std-ds-concurrent-list-ml-1508902143) | `std/ds/concurrent_list.ml:203` | 10 | 8 | 4 | 3 | 1 | 286.73 | 60.44 |
| [`std.ds.concurrent_list.ThreadSafeList.len`](Type-std-ds-concurrent-list-threadsafelist-78742376.md#method-method-std-ds-concurrent-list-threadsafelist-len-function-len-std-ds-concurrent-list-ml-2066822621) | `std/ds/concurrent_list.ml:93` | 7 | 7 | 3 | 2 | 1 | 191.16 | 65.19 |
| [`std.ds.concurrent_list.ThreadSafeList.new`](Type-std-ds-concurrent-list-threadsafelist-78742376.md#static_method-static-method-std-ds-concurrent-list-threadsafelist-new-static-function-new-std-ds-concurrent-list-ml-1011596306) | `std/ds/concurrent_list.ml:46` | 3 | 1 | 1 | 0 | 0 | 48.43 | 77.66 |
| [`std.ds.concurrent_list.ThreadSafeList.pop`](Type-std-ds-concurrent-list-threadsafelist-78742376.md#method-method-std-ds-concurrent-list-threadsafelist-pop-function-pop-std-ds-concurrent-list-ml-632107569) | `std/ds/concurrent_list.ml:258` | 13 | 11 | 4 | 3 | 1 | 366.13 | 57.21 |
| [`std.ds.concurrent_list.ThreadSafeList.popOr`](Type-std-ds-concurrent-list-threadsafelist-78742376.md#method-method-std-ds-concurrent-list-threadsafelist-popor-function-popor-fallback-std-ds-concurrent-list-ml-960393249) | `std/ds/concurrent_list.ml:274` | 5 | 4 | 2 | 1 | 1 | 114.45 | 70.07 |
| [`std.ds.concurrent_list.ThreadSafeList.push`](Type-std-ds-concurrent-list-threadsafelist-78742376.md#method-method-std-ds-concurrent-list-threadsafelist-push-function-push-value-std-ds-concurrent-list-ml-57487206) | `std/ds/concurrent_list.ml:144` | 3 | 1 | 1 | 0 | 0 | 46.51 | 77.78 |
| [`std.ds.concurrent_list.ThreadSafeList.removeAt`](Type-std-ds-concurrent-list-threadsafelist-78742376.md#method-method-std-ds-concurrent-list-threadsafelist-removeat-function-removeat-index-std-ds-concurrent-list-ml-149304045) | `std/ds/concurrent_list.ml:238` | 18 | 16 | 7 | 6 | 1 | 635.93 | 52.05 |
| [`std.ds.concurrent_list.ThreadSafeList.reserve`](Type-std-ds-concurrent-list-threadsafelist-78742376.md#method-method-std-ds-concurrent-list-threadsafelist-reserve-function-reserve-minimumcapacity-std-ds-concurrent-list-ml-1098250973) | `std/ds/concurrent_list.ml:118` | 8 | 9 | 5 | 4 | 1 | 305.53 | 62.23 |
| [`std.ds.concurrent_list.ThreadSafeList.set`](Type-std-ds-concurrent-list-threadsafelist-78742376.md#method-method-std-ds-concurrent-list-threadsafelist-set-function-set-index-value-std-ds-concurrent-list-ml-564599672) | `std/ds/concurrent_list.ml:185` | 11 | 10 | 6 | 5 | 1 | 390 | 58.33 |
| [`std.ds.concurrent_list.ThreadSafeList.toArray`](Type-std-ds-concurrent-list-threadsafelist-78742376.md#method-method-std-ds-concurrent-list-threadsafelist-toarray-function-toarray-std-ds-concurrent-list-ml-1032101379) | `std/ds/concurrent_list.ml:298` | 15 | 12 | 4 | 3 | 1 | 394.2 | 55.63 |
| [`std.ds.concurrent_list.ThreadSafeList.withCapacity`](Type-std-ds-concurrent-list-threadsafelist-78742376.md#static_method-static-method-std-ds-concurrent-list-threadsafelist-withcapacity-static-function-withcapacity-minimumcapacity-std-ds-concurrent-list-ml-2053089166) | `std/ds/concurrent_list.ml:52` | 8 | 5 | 3 | 2 | 1 | 297.25 | 62.58 |
| [`std.ds.hashmap.HashMap.clear`](Type-std-ds-hashmap-hashmap-1326830721.md#method-method-std-ds-hashmap-hashmap-clear-function-clear-std-ds-hashmap-ml-1700032960) | `std/ds/hashmap.ml:186` | 6 | 4 | 1 | 0 | 0 | 188 | 66.97 |
| [`std.ds.hashmap.HashMap.count`](Type-std-ds-hashmap-hashmap-1326830721.md#method-method-std-ds-hashmap-hashmap-count-function-count-std-ds-hashmap-ml-806853896) | `std/ds/hashmap.ml:176` | 3 | 1 | 1 | 0 | 0 | 31.7 | 78.95 |
| [`std.ds.hashmap.HashMap.delete`](Type-std-ds-hashmap-hashmap-1326830721.md#method-method-std-ds-hashmap-hashmap-delete-function-delete-key-std-ds-hashmap-ml-1951284107) | `std/ds/hashmap.ml:310` | 3 | 1 | 1 | 0 | 0 | 46.51 | 77.78 |
| [`std.ds.hashmap.HashMap.entriesArray`](Type-std-ds-hashmap-hashmap-1326830721.md#method-method-std-ds-hashmap-hashmap-entriesarray-function-entriesarray-std-ds-hashmap-ml-1475560178) | `std/ds/hashmap.ml:341` | 11 | 7 | 3 | 3 | 2 | 351.75 | 59.05 |
| [`std.ds.hashmap.HashMap.get`](Type-std-ds-hashmap-hashmap-1326830721.md#method-method-std-ds-hashmap-hashmap-get-function-get-key-std-ds-hashmap-ml-1962985435) | `std/ds/hashmap.ml:266` | 11 | 7 | 5 | 4 | 1 | 317.07 | 59.1 |
| [`std.ds.hashmap.HashMap.getOr`](Type-std-ds-hashmap-hashmap-1326830721.md#method-method-std-ds-hashmap-hashmap-getor-function-getor-key-fallback-std-ds-hashmap-ml-923925195) | `std/ds/hashmap.ml:281` | 7 | 4 | 2 | 1 | 1 | 131.69 | 66.45 |
| [`std.ds.hashmap.HashMap.has`](Type-std-ds-hashmap-hashmap-1326830721.md#method-method-std-ds-hashmap-hashmap-has-function-has-key-std-ds-hashmap-ml-1870741851) | `std/ds/hashmap.ml:255` | 8 | 5 | 4 | 3 | 1 | 259.6 | 62.86 |
| [`std.ds.hashmap.HashMap.isEmpty`](Type-std-ds-hashmap-hashmap-1326830721.md#method-method-std-ds-hashmap-hashmap-isempty-function-isempty-std-ds-hashmap-ml-364699036) | `std/ds/hashmap.ml:181` | 3 | 1 | 1 | 0 | 0 | 41.51 | 78.13 |
| [`std.ds.hashmap.HashMap.keysArray`](Type-std-ds-hashmap-hashmap-1326830721.md#method-method-std-ds-hashmap-hashmap-keysarray-function-keysarray-std-ds-hashmap-ml-1663031904) | `std/ds/hashmap.ml:315` | 11 | 7 | 3 | 3 | 2 | 293.25 | 59.6 |
| [`std.ds.hashmap.HashMap.new`](Type-std-ds-hashmap-hashmap-1326830721.md#static_method-static-method-std-ds-hashmap-hashmap-new-static-function-new-std-ds-hashmap-ml-111281271) | `std/ds/hashmap.ml:161` | 3 | 1 | 1 | 0 | 0 | 48.43 | 77.66 |
| [`std.ds.hashmap.HashMap.remove`](Type-std-ds-hashmap-hashmap-1326830721.md#method-method-std-ds-hashmap-hashmap-remove-function-remove-key-std-ds-hashmap-ml-1942441951) | `std/ds/hashmap.ml:291` | 15 | 11 | 5 | 4 | 1 | 485.97 | 54.86 |
| [`std.ds.hashmap.HashMap.set`](Type-std-ds-hashmap-hashmap-1326830721.md#method-method-std-ds-hashmap-hashmap-set-function-set-key-value-std-ds-hashmap-ml-1174901958) | `std/ds/hashmap.ml:229` | 20 | 14 | 7 | 6 | 1 | 671.25 | 50.88 |
| [`std.ds.hashmap.HashMap.valuesArray`](Type-std-ds-hashmap-hashmap-1326830721.md#method-method-std-ds-hashmap-hashmap-valuesarray-function-valuesarray-std-ds-hashmap-ml-1708150460) | `std/ds/hashmap.ml:328` | 11 | 7 | 3 | 3 | 2 | 293.25 | 59.6 |
| [`std.ds.hashmap.HashMap.withCapacity`](Type-std-ds-hashmap-hashmap-1326830721.md#static_method-static-method-std-ds-hashmap-hashmap-withcapacity-static-function-withcapacity-mincap-std-ds-hashmap-ml-1784250823) | `std/ds/hashmap.ml:167` | 7 | 5 | 1 | 0 | 0 | 212.67 | 65.13 |
| [`std.ds.list.List.add`](Type-std-ds-list-list-472810057.md#method-method-std-ds-list-list-add-function-add-value-std-ds-list-ml-436826465) | `std/ds/list.ml:141` | 7 | 4 | 2 | 1 | 1 | 206.44 | 65.09 |
| [`std.ds.list.List.addAll`](Type-std-ds-list-list-472810057.md#method-method-std-ds-list-list-addall-function-addall-values-std-ds-list-ml-274680188) | `std/ds/list.ml:157` | 16 | 11 | 4 | 3 | 1 | 378.92 | 55.14 |
| [`std.ds.list.List.clear`](Type-std-ds-list-list-472810057.md#method-method-std-ds-list-list-clear-function-clear-std-ds-list-ml-956239204) | `std/ds/list.ml:106` | 8 | 4 | 3 | 3 | 2 | 184.48 | 64.03 |
| [`std.ds.list.List.first`](Type-std-ds-list-list-472810057.md#method-method-std-ds-list-list-first-function-first-std-ds-list-ml-2140847354) | `std/ds/list.ml:201` | 6 | 3 | 2 | 1 | 1 | 92 | 69.01 |
| [`std.ds.list.List.fromArray`](Type-std-ds-list-list-472810057.md#static_method-static-method-std-ds-list-list-fromarray-static-function-fromarray-values-std-ds-list-ml-902518015) | `std/ds/list.ml:82` | 12 | 8 | 3 | 2 | 1 | 313.82 | 58.57 |
| [`std.ds.list.List.get`](Type-std-ds-list-list-472810057.md#method-method-std-ds-list-list-get-function-get-index-std-ds-list-ml-1268966370) | `std/ds/list.ml:176` | 9 | 5 | 4 | 3 | 1 | 173.92 | 62.96 |
| [`std.ds.list.List.insert`](Type-std-ds-list-list-472810057.md#method-method-std-ds-list-list-insert-function-insert-index-value-std-ds-list-ml-1400622307) | `std/ds/list.ml:241` | 23 | 16 | 7 | 6 | 1 | 645.97 | 49.68 |
| [`std.ds.list.List.isEmpty`](Type-std-ds-list-list-472810057.md#method-method-std-ds-list-list-isempty-function-isempty-std-ds-list-ml-958491744) | `std/ds/list.ml:101` | 3 | 1 | 1 | 0 | 0 | 41.51 | 78.13 |
| [`std.ds.list.List.last`](Type-std-ds-list-list-472810057.md#method-method-std-ds-list-list-last-function-last-std-ds-list-ml-614101394) | `std/ds/list.ml:209` | 6 | 3 | 2 | 1 | 1 | 112.59 | 68.39 |
| [`std.ds.list.List.len`](Type-std-ds-list-list-472810057.md#method-method-std-ds-list-list-len-function-len-std-ds-list-ml-1370223244) | `std/ds/list.ml:96` | 3 | 1 | 1 | 0 | 0 | 31.7 | 78.95 |
| [`std.ds.list.List.new`](Type-std-ds-list-list-472810057.md#static_method-static-method-std-ds-list-list-new-static-function-new-std-ds-list-ml-1698003813) | `std/ds/list.ml:68` | 3 | 1 | 1 | 0 | 0 | 48.43 | 77.66 |
| [`std.ds.list.List.pop`](Type-std-ds-list-list-472810057.md#method-method-std-ds-list-list-pop-function-pop-std-ds-list-ml-183093544) | `std/ds/list.ml:217` | 10 | 7 | 2 | 1 | 1 | 202.05 | 61.77 |
| [`std.ds.list.List.popOr`](Type-std-ds-list-list-472810057.md#method-method-std-ds-list-list-popor-function-popor-fallbackvalue-std-ds-list-ml-1510696565) | `std/ds/list.ml:230` | 7 | 4 | 2 | 1 | 1 | 114.45 | 66.88 |
| [`std.ds.list.List.push`](Type-std-ds-list-list-472810057.md#method-method-std-ds-list-list-push-function-push-value-std-ds-list-ml-1846460339) | `std/ds/list.ml:151` | 3 | 1 | 1 | 0 | 0 | 41.21 | 78.15 |
| [`std.ds.list.List.removeAt`](Type-std-ds-list-list-472810057.md#method-method-std-ds-list-list-removeat-function-removeat-index-std-ds-list-ml-140564318) | `std/ds/list.ml:267` | 17 | 12 | 5 | 4 | 1 | 466.37 | 53.8 |
| [`std.ds.list.List.reserve`](Type-std-ds-list-list-472810057.md#method-method-std-ds-list-list-reserve-function-reserve-mincap-std-ds-list-ml-1425645590) | `std/ds/list.ml:117` | 9 | 5 | 3 | 2 | 1 | 138.97 | 63.78 |
| [`std.ds.list.List.set`](Type-std-ds-list-list-472810057.md#method-method-std-ds-list-list-set-function-set-index-value-std-ds-list-ml-1817091431) | `std/ds/list.ml:189` | 10 | 6 | 4 | 3 | 1 | 218.72 | 61.26 |
| [`std.ds.list.List.toArray`](Type-std-ds-list-list-472810057.md#method-method-std-ds-list-list-toarray-function-toarray-std-ds-list-ml-679354234) | `std/ds/list.ml:286` | 8 | 5 | 2 | 1 | 1 | 182.66 | 64.19 |
| [`std.ds.list.List.withCapacity`](Type-std-ds-list-list-472810057.md#static_method-static-method-std-ds-list-list-withcapacity-static-function-withcapacity-mincap-std-ds-list-ml-1912842597) | `std/ds/list.ml:74` | 5 | 3 | 1 | 0 | 0 | 124 | 69.96 |
| [`std.ds.queue.Queue.clear`](Type-std-ds-queue-queue-1012616181.md#method-method-std-ds-queue-queue-clear-function-clear-std-ds-queue-ml-519280311) | `std/ds/queue.ml:94` | 5 | 3 | 1 | 0 | 0 | 75.28 | 71.48 |
| [`std.ds.queue.Queue.dequeue`](Type-std-ds-queue-queue-1012616181.md#method-method-std-ds-queue-queue-dequeue-function-dequeue-std-ds-queue-ml-517233613) | `std/ds/queue.ml:140` | 10 | 7 | 2 | 1 | 1 | 302.61 | 60.55 |
| [`std.ds.queue.Queue.enqueue`](Type-std-ds-queue-queue-1012616181.md#method-method-std-ds-queue-queue-enqueue-function-enqueue-v-std-ds-queue-ml-1746933747) | `std/ds/queue.ml:121` | 8 | 5 | 2 | 1 | 1 | 302.61 | 62.66 |
| [`std.ds.queue.Queue.isEmpty`](Type-std-ds-queue-queue-1012616181.md#method-method-std-ds-queue-queue-isempty-function-isempty-std-ds-queue-ml-350459979) | `std/ds/queue.ml:89` | 3 | 1 | 1 | 0 | 0 | 41.51 | 78.13 |
| [`std.ds.queue.Queue.len`](Type-std-ds-queue-queue-1012616181.md#method-method-std-ds-queue-queue-len-function-len-std-ds-queue-ml-62408447) | `std/ds/queue.ml:84` | 3 | 1 | 1 | 0 | 0 | 31.7 | 78.95 |
| [`std.ds.queue.Queue.new`](Type-std-ds-queue-queue-1012616181.md#static_method-static-method-std-ds-queue-queue-new-static-function-new-std-ds-queue-ml-2141908760) | `std/ds/queue.ml:71` | 3 | 1 | 1 | 0 | 0 | 48.43 | 77.66 |
| [`std.ds.queue.Queue.peek`](Type-std-ds-queue-queue-1012616181.md#method-method-std-ds-queue-queue-peek-function-peek-std-ds-queue-ml-1238278161) | `std/ds/queue.ml:132` | 6 | 3 | 2 | 1 | 1 | 102.19 | 68.69 |
| [`std.ds.queue.Queue.toArray`](Type-std-ds-queue-queue-1012616181.md#method-method-std-ds-queue-queue-toarray-function-toarray-std-ds-queue-ml-260125405) | `std/ds/queue.ml:155` | 11 | 7 | 3 | 2 | 1 | 325.48 | 59.29 |
| [`std.ds.queue.Queue.withCapacity`](Type-std-ds-queue-queue-1012616181.md#static_method-static-method-std-ds-queue-queue-withcapacity-static-function-withcapacity-mincap-std-ds-queue-ml-438691928) | `std/ds/queue.ml:77` | 5 | 3 | 1 | 0 | 0 | 140 | 69.59 |
| [`std.ds.set.HashSet.add`](Type-std-ds-set-hashset-1613617709.md#method-method-std-ds-set-hashset-add-function-add-key-std-ds-set-ml-1838512067) | `std/ds/set.ml:50` | 3 | 1 | 1 | 0 | 0 | 66.61 | 76.69 |
| [`std.ds.set.HashSet.clear`](Type-std-ds-set-hashset-1613617709.md#method-method-std-ds-set-hashset-clear-function-clear-std-ds-set-ml-1453333662) | `std/ds/set.ml:44` | 3 | 1 | 1 | 0 | 0 | 39 | 78.32 |
| [`std.ds.set.HashSet.delete`](Type-std-ds-set-hashset-1613617709.md#method-method-std-ds-set-hashset-delete-function-delete-key-std-ds-set-ml-1333440797) | `std/ds/set.ml:68` | 3 | 1 | 1 | 0 | 0 | 46.51 | 77.78 |
| [`std.ds.set.HashSet.has`](Type-std-ds-set-hashset-1613617709.md#method-method-std-ds-set-hashset-has-function-has-key-std-ds-set-ml-902445005) | `std/ds/set.ml:56` | 3 | 1 | 1 | 0 | 0 | 53.15 | 77.38 |
| [`std.ds.set.HashSet.isEmpty`](Type-std-ds-set-hashset-1613617709.md#method-method-std-ds-set-hashset-isempty-function-isempty-std-ds-set-ml-840145106) | `std/ds/set.ml:39` | 3 | 1 | 1 | 0 | 0 | 44.38 | 77.92 |
| [`std.ds.set.HashSet.keysArray`](Type-std-ds-set-hashset-1613617709.md#method-method-std-ds-set-hashset-keysarray-function-keysarray-std-ds-set-ml-1999664542) | `std/ds/set.ml:73` | 3 | 1 | 1 | 0 | 0 | 44.38 | 77.92 |
| [`std.ds.set.HashSet.len`](Type-std-ds-set-hashset-1613617709.md#method-method-std-ds-set-hashset-len-function-len-std-ds-set-ml-1244644214) | `std/ds/set.ml:34` | 3 | 1 | 1 | 0 | 0 | 46.51 | 77.78 |
| [`std.ds.set.HashSet.new`](Type-std-ds-set-hashset-1613617709.md#static_method-static-method-std-ds-set-hashset-new-static-function-new-std-ds-set-ml-1006408109) | `std/ds/set.ml:29` | 3 | 1 | 1 | 0 | 0 | 62.27 | 76.89 |
| [`std.ds.set.HashSet.remove`](Type-std-ds-set-hashset-1613617709.md#method-method-std-ds-set-hashset-remove-function-remove-key-std-ds-set-ml-1015320057) | `std/ds/set.ml:62` | 3 | 1 | 1 | 0 | 0 | 53.15 | 77.38 |
| [`std.ds.stack.Stack.clear`](Type-std-ds-stack-stack-2051682853.md#method-method-std-ds-stack-stack-clear-function-clear-std-ds-stack-ml-244409422) | `std/ds/stack.ml:179` | 7 | 5 | 1 | 0 | 0 | 174.17 | 65.74 |
| [`std.ds.stack.Stack.fromArray`](Type-std-ds-stack-stack-2051682853.md#static_method-static-method-std-ds-stack-stack-fromarray-static-function-fromarray-values-std-ds-stack-ml-1532778091) | `std/ds/stack.ml:130` | 3 | 1 | 1 | 0 | 0 | 83.76 | 75.99 |
| [`std.ds.stack.Stack.isEmpty`](Type-std-ds-stack-stack-2051682853.md#method-method-std-ds-stack-stack-isempty-function-isempty-std-ds-stack-ml-879125514) | `std/ds/stack.ml:173` | 4 | 2 | 1 | 0 | 0 | 80 | 73.41 |
| [`std.ds.stack.Stack.len`](Type-std-ds-stack-stack-2051682853.md#method-method-std-ds-stack-stack-len-function-len-std-ds-stack-ml-1431646790) | `std/ds/stack.ml:167` | 4 | 2 | 1 | 0 | 0 | 68.53 | 73.88 |
| [`std.ds.stack.Stack.new`](Type-std-ds-stack-stack-2051682853.md#static_method-static-method-std-ds-stack-stack-new-static-function-new-std-ds-stack-ml-1244206485) | `std/ds/stack.ml:124` | 3 | 1 | 1 | 0 | 0 | 79.95 | 76.13 |
| [`std.ds.stack.Stack.peek`](Type-std-ds-stack-stack-2051682853.md#method-method-std-ds-stack-stack-peek-function-peek-std-ds-stack-ml-520126940) | `std/ds/stack.ml:236` | 9 | 6 | 2 | 1 | 1 | 175.69 | 63.2 |
| [`std.ds.stack.Stack.peekOr`](Type-std-ds-stack-stack-2051682853.md#method-method-std-ds-stack-stack-peekor-function-peekor-fallbackvalue-std-ds-stack-ml-938237637) | `std/ds/stack.ml:248` | 7 | 4 | 2 | 1 | 1 | 114.45 | 66.88 |
| [`std.ds.stack.Stack.pop`](Type-std-ds-stack-stack-2051682853.md#method-method-std-ds-stack-stack-pop-function-pop-std-ds-stack-ml-337641410) | `std/ds/stack.ml:257` | 15 | 12 | 2 | 1 | 1 | 316.36 | 56.57 |
| [`std.ds.stack.Stack.popOr`](Type-std-ds-stack-stack-2051682853.md#method-method-std-ds-stack-stack-popor-function-popor-fallbackvalue-std-ds-stack-ml-1004619701) | `std/ds/stack.ml:276` | 7 | 4 | 2 | 1 | 1 | 114.45 | 66.88 |
| [`std.ds.stack.Stack.push`](Type-std-ds-stack-stack-2051682853.md#method-method-std-ds-stack-stack-push-function-push-value-std-ds-stack-ml-1856663047) | `std/ds/stack.ml:189` | 14 | 11 | 2 | 1 | 1 | 366.8 | 56.77 |
| [`std.ds.stack.Stack.pushAll`](Type-std-ds-stack-stack-2051682853.md#method-method-std-ds-stack-stack-pushall-function-pushall-values-std-ds-stack-ml-2011042572) | `std/ds/stack.ml:207` | 24 | 18 | 5 | 4 | 1 | 646.24 | 49.54 |
| [`std.ds.stack.Stack.toArray`](Type-std-ds-stack-stack-2051682853.md#method-method-std-ds-stack-stack-toarray-function-toarray-std-ds-stack-ml-1503124416) | `std/ds/stack.ml:285` | 13 | 9 | 3 | 2 | 1 | 296.13 | 57.99 |
| [`std.encoding.base64.fromBase64`](File-std-encoding-base64-ml-1044483879.md#function-function-std-encoding-base64-frombase64-function-frombase64-text-std-encoding-base64-ml-1409232600) | `std/encoding/base64.ml:158` | 90 | 69 | 26 | 43 | 3 | 3202.01 | 29.33 |
| [`std.encoding.base64.toBase64`](File-std-encoding-base64-ml-1044483879.md#function-function-std-encoding-base64-tobase64-function-tobase64-b-std-encoding-base64-ml-696343249) | `std/encoding/base64.ml:101` | 46 | 38 | 7 | 8 | 2 | 1815.18 | 39.97 |
| [`std.encoding.hex.decode`](File-std-encoding-hex-ml-900742095.md#function-function-std-encoding-hex-decode-function-decode-s-std-encoding-hex-ml-994210004) | `std/encoding/hex.ml:58` | 3 | 1 | 1 | 0 | 0 | 36 | 78.56 |
| [`std.encoding.hex.decodeOr`](File-std-encoding-hex-ml-900742095.md#function-function-std-encoding-hex-decodeor-function-decodeor-s-fallbackbytes-std-encoding-hex-ml-1574510785) | `std/encoding/hex.ml:72` | 7 | 4 | 2 | 1 | 1 | 118.54 | 66.77 |
| [`std.encoding.hex.decodeOrError`](File-std-encoding-hex-ml-900742095.md#function-function-std-encoding-hex-decodeorerror-function-decodeorerror-s-std-encoding-hex-ml-1933310858) | `std/encoding/hex.ml:83` | 10 | 6 | 3 | 2 | 1 | 194.49 | 61.76 |
| [`std.encoding.hex.encode`](File-std-encoding-hex-ml-900742095.md#function-function-std-encoding-hex-encode-function-encode-b-std-encoding-hex-ml-1999249601) | `std/encoding/hex.ml:42` | 3 | 1 | 1 | 0 | 0 | 36 | 78.56 |
| [`std.encoding.hex.encodeUpper`](File-std-encoding-hex-ml-900742095.md#function-function-std-encoding-hex-encodeupper-function-encodeupper-b-std-encoding-hex-ml-1884024969) | `std/encoding/hex.ml:48` | 7 | 4 | 2 | 1 | 1 | 129.27 | 66.51 |
| [`std.encoding.hex.isValid`](File-std-encoding-hex-ml-900742095.md#function-function-std-encoding-hex-isvalid-function-isvalid-s-std-encoding-hex-ml-1745609812) | `std/encoding/hex.ml:64` | 4 | 2 | 1 | 0 | 0 | 74.01 | 73.64 |
| [`std.fmt.center`](File-std-fmt-ml-2123112301.md#function-function-std-fmt-center-function-center-s-width-ch-std-fmt-ml-887357416) | `std/fmt.ml:66` | 12 | 8 | 6 | 5 | 1 | 465.69 | 56.97 |
| [`std.fmt.line`](File-std-fmt-ml-2123112301.md#function-function-std-fmt-line-function-line-ch-width-std-fmt-ml-1807299147) | `std/fmt.ml:130` | 12 | 7 | 5 | 4 | 1 | 256.76 | 58.91 |
| [`std.fmt.padLeft`](File-std-fmt-ml-2123112301.md#function-function-std-fmt-padleft-function-padleft-s-width-ch-std-fmt-ml-1234037328) | `std/fmt.ml:36` | 10 | 6 | 6 | 5 | 1 | 324.33 | 59.8 |
| [`std.fmt.padRight`](File-std-fmt-ml-2123112301.md#function-function-std-fmt-padright-function-padright-s-width-ch-std-fmt-ml-842685836) | `std/fmt.ml:51` | 10 | 6 | 6 | 5 | 1 | 324.33 | 59.8 |
| [`std.fmt.quote`](File-std-fmt-ml-2123112301.md#function-function-std-fmt-quote-function-quote-s-std-fmt-ml-1511859179) | `std/fmt.ml:84` | 39 | 27 | 11 | 18 | 3 | 1099.18 | 42.52 |
| [`std.fmt.repeat`](File-std-fmt-ml-2123112301.md#function-function-std-fmt-repeat-function-repeat-ch-count-std-fmt-ml-28025468) | `std/fmt.ml:28` | 3 | 1 | 1 | 0 | 0 | 53.15 | 77.38 |
| [`std.fs.appendAllBytes`](File-std-fs-ml-1285967051.md#function-function-std-fs-appendallbytes-function-appendallbytes-path-data-std-fs-ml-372563649) | `std/fs.ml:782` | 13 | 8 | 5 | 4 | 1 | 356.62 | 57.16 |
| [`std.fs.appendAllText`](File-std-fs-ml-1285967051.md#function-function-std-fs-appendalltext-function-appendalltext-path-text-std-fs-ml-1086283032) | `std/fs.ml:802` | 13 | 8 | 5 | 4 | 1 | 352.53 | 57.19 |
| [`std.fs.copyFile`](File-std-fs-ml-1285967051.md#function-function-std-fs-copyfile-function-copyfile-sourcepath-destpath-overwrite-std-fs-ml-1522240000) | `std/fs.ml:710` | 16 | 10 | 6 | 5 | 1 | 418.24 | 54.57 |
| [`std.fs.delete`](File-std-fs-ml-1285967051.md#function-function-std-fs-delete-function-delete-path-std-fs-ml-1227233521) | `std/fs.ml:440` | 21 | 14 | 6 | 7 | 2 | 426.06 | 51.94 |
| [`std.fs.exists`](File-std-fs-ml-1285967051.md#function-function-std-fs-exists-function-exists-path-std-fs-ml-72849833) | `std/fs.ml:281` | 7 | 4 | 2 | 1 | 1 | 118.94 | 66.76 |
| [`std.fs.fileSize`](File-std-fs-ml-1285967051.md#function-function-std-fs-filesize-function-filesize-path-std-fs-ml-274199189) | `std/fs.ml:759` | 16 | 11 | 4 | 3 | 1 | 620.12 | 53.64 |
| [`std.fs.isDir`](File-std-fs-ml-1285967051.md#function-function-std-fs-isdir-function-isdir-path-std-fs-ml-1982632259) | `std/fs.ml:291` | 10 | 6 | 3 | 2 | 1 | 241.48 | 61.1 |
| [`std.fs.isFile`](File-std-fs-ml-1285967051.md#function-function-std-fs-isfile-function-isfile-path-std-fs-ml-137584197) | `std/fs.ml:304` | 6 | 3 | 2 | 1 | 1 | 96.21 | 68.87 |
| [`std.fs.joinPath`](File-std-fs-ml-1285967051.md#function-function-std-fs-joinpath-function-joinpath-base-name-std-fs-ml-1871291558) | `std/fs.ml:314` | 12 | 7 | 6 | 5 | 1 | 303.08 | 58.28 |
| [`std.fs.listDir`](File-std-fs-ml-1285967051.md#function-function-std-fs-listdir-function-listdir-path-std-fs-ml-1461247751) | `std/fs.ml:393` | 39 | 27 | 12 | 18 | 4 | 1298.01 | 41.88 |
| [`std.fs.moveFile`](File-std-fs-ml-1285967051.md#function-function-std-fs-movefile-function-movefile-sourcepath-destpath-overwrite-std-fs-ml-190963024) | `std/fs.ml:733` | 21 | 13 | 9 | 9 | 2 | 535.05 | 50.84 |
| [`std.fs.readAllBytes`](File-std-fs-ml-1285967051.md#function-function-std-fs-readallbytes-function-readallbytes-path-std-fs-ml-290559245) | `std/fs.ml:519` | 56 | 37 | 11 | 13 | 2 | 2155.78 | 37.04 |
| [`std.fs.readAllLines`](File-std-fs-ml-1285967051.md#function-function-std-fs-readalllines-function-readalllines-path-std-fs-ml-1313468293) | `std/fs.ml:821` | 19 | 13 | 6 | 6 | 2 | 587.77 | 51.91 |
| [`std.fs.readAllText`](File-std-fs-ml-1285967051.md#function-function-std-fs-readalltext-function-readalltext-path-std-fs-ml-1923171005) | `std/fs.ml:621` | 64 | 43 | 13 | 15 | 2 | 2403.52 | 35.18 |
| [`std.fs.writeAllBytes`](File-std-fs-ml-1285967051.md#function-function-std-fs-writeallbytes-function-writeallbytes-path-data-std-fs-ml-354087299) | `std/fs.ml:495` | 17 | 12 | 5 | 4 | 1 | 557.19 | 53.26 |
| [`std.fs.writeAllText`](File-std-fs-ml-1285967051.md#function-function-std-fs-writealltext-function-writealltext-path-text-std-fs-ml-856051952) | `std/fs.ml:597` | 17 | 12 | 5 | 4 | 1 | 553.48 | 53.28 |
| [`std.io.file.append`](File-std-io-file-ml-2074692665.md#function-function-std-io-file-append-function-append-file-source-sourceoffset-count-std-io-file-ml-1717912519) | `std/io/file.ml:424` | 7 | 7 | 3 | 2 | 1 | 259.15 | 64.26 |
| [`std.io.file.atomicMove`](File-std-io-file-ml-2074692665.md#function-function-std-io-file-atomicmove-function-atomicmove-source-destination-replaceexisting-std-io-file-ml-17044359) | `std/io/file.ml:639` | 9 | 12 | 10 | 9 | 1 | 660.68 | 58.09 |
| [`std.io.file.close`](File-std-io-file-ml-2074692665.md#function-function-std-io-file-close-function-close-file-std-io-file-ml-1917059369) | `std/io/file.ml:528` | 12 | 12 | 5 | 5 | 2 | 411.2 | 57.48 |
| [`std.io.file.create`](File-std-io-file-ml-2074692665.md#function-function-std-io-file-create-function-create-path-std-io-file-ml-118505396) | `std/io/file.ml:320` | 3 | 1 | 1 | 0 | 0 | 71.7 | 76.47 |
| [`std.io.file.createDirectory`](File-std-io-file-ml-2074692665.md#function-function-std-io-file-createdirectory-function-createdirectory-path-std-io-file-ml-1346524798) | `std/io/file.ml:547` | 6 | 7 | 5 | 4 | 1 | 302.86 | 64.98 |
| [`std.io.file.createDurable`](File-std-io-file-ml-2074692665.md#function-function-std-io-file-createdurable-function-createdurable-path-std-io-file-ml-1821741618) | `std/io/file.ml:332` | 3 | 1 | 1 | 0 | 0 | 69.19 | 76.57 |
| [`std.io.file.createNew`](File-std-io-file-ml-2074692665.md#function-function-std-io-file-createnew-function-createnew-path-std-io-file-ml-1821480312) | `std/io/file.ml:326` | 3 | 1 | 1 | 0 | 0 | 71.7 | 76.47 |
| [`std.io.file.createNewDurable`](File-std-io-file-ml-2074692665.md#function-function-std-io-file-createnewdurable-function-createnewdurable-path-std-io-file-ml-825041504) | `std/io/file.ml:338` | 3 | 1 | 1 | 0 | 0 | 69.19 | 76.57 |
| [`std.io.file.deletePath`](File-std-io-file-ml-2074692665.md#function-function-std-io-file-deletepath-function-deletepath-path-std-io-file-ml-291993508) | `std/io/file.ml:590` | 6 | 7 | 5 | 4 | 1 | 326.9 | 64.75 |
| [`std.io.file.directoryExists`](File-std-io-file-ml-2074692665.md#function-function-std-io-file-directoryexists-function-directoryexists-path-std-io-file-ml-1671780194) | `std/io/file.ml:584` | 3 | 1 | 1 | 0 | 0 | 46.51 | 77.78 |
| [`std.io.file.fileExists`](File-std-io-file-ml-2074692665.md#function-function-std-io-file-fileexists-function-fileexists-path-std-io-file-ml-1075595960) | `std/io/file.ml:578` | 3 | 1 | 1 | 0 | 0 | 46.51 | 77.78 |
| [`std.io.file.flush`](File-std-io-file-ml-2074692665.md#function-function-std-io-file-flush-function-flush-file-std-io-file-ml-1772033725) | `std/io/file.ml:464` | 7 | 8 | 4 | 3 | 1 | 252.17 | 64.21 |
| [`std.io.file.joinPath`](File-std-io-file-ml-2074692665.md#function-function-std-io-file-joinpath-function-joinpath-left-right-std-io-file-ml-648345826) | `std/io/file.ml:600` | 3 | 1 | 1 | 0 | 0 | 64.53 | 76.79 |
| [`std.io.file.lock`](File-std-io-file-ml-2074692665.md#function-function-std-io-file-lock-function-lock-file-mode-wait-std-io-file-ml-1414253107) | `std/io/file.ml:480` | 18 | 22 | 10 | 10 | 2 | 1037.48 | 50.15 |
| [`std.io.file.movePath`](File-std-io-file-ml-2074692665.md#function-function-std-io-file-movepath-function-movepath-source-destination-replaceexisting-std-io-file-ml-1359616939) | `std/io/file.ml:657` | 3 | 1 | 1 | 0 | 0 | 69.19 | 76.57 |
| [`std.io.file.openRead`](File-std-io-file-ml-2074692665.md#function-function-std-io-file-openread-function-openread-path-std-io-file-ml-808384584) | `std/io/file.ml:294` | 3 | 1 | 1 | 0 | 0 | 71.7 | 76.47 |
| [`std.io.file.openReadWrite`](File-std-io-file-ml-2074692665.md#function-function-std-io-file-openreadwrite-function-openreadwrite-path-createifmissing-std-io-file-ml-1630995317) | `std/io/file.ml:301` | 6 | 6 | 3 | 2 | 1 | 241.48 | 65.94 |
| [`std.io.file.openReadWriteDurable`](File-std-io-file-ml-2074692665.md#function-function-std-io-file-openreadwritedurable-function-openreadwritedurable-path-createifmissing-std-io-file-ml-1261778099) | `std/io/file.ml:311` | 6 | 6 | 3 | 2 | 1 | 238.42 | 65.98 |
| [`std.io.file.pathExists`](File-std-io-file-ml-2074692665.md#function-function-std-io-file-pathexists-function-pathexists-path-std-io-file-ml-2037795076) | `std/io/file.ml:572` | 3 | 1 | 1 | 0 | 0 | 46.51 | 77.78 |
| [`std.io.file.readAllBytes`](File-std-io-file-ml-2074692665.md#function-function-std-io-file-readallbytes-function-readallbytes-path-maximumbytes-std-io-file-ml-888056637) | `std/io/file.ml:607` | 16 | 22 | 9 | 9 | 2 | 871.16 | 51.94 |
| [`std.io.file.readAllText`](File-std-io-file-ml-2074692665.md#function-function-std-io-file-readalltext-function-readalltext-path-maximumbytes-std-io-file-ml-2121359345) | `std/io/file.ml:627` | 7 | 7 | 3 | 2 | 1 | 260.06 | 64.25 |
| [`std.io.file.readAt`](File-std-io-file-ml-2074692665.md#function-function-std-io-file-readat-function-readat-file-fileoffset-destination-destinationoffset-count-std-io-file-ml-1658255612) | `std/io/file.ml:348` | 16 | 22 | 10 | 9 | 1 | 1123.13 | 51.03 |
| [`std.io.file.readExactAt`](File-std-io-file-ml-2074692665.md#function-function-std-io-file-readexactat-function-readexactat-file-fileoffset-destination-destinationoffset-count-std-io-file-ml-560496664) | `std/io/file.ml:376` | 10 | 9 | 4 | 5 | 2 | 387.64 | 59.52 |
| [`std.io.file.removeDirectory`](File-std-io-file-ml-2074692665.md#function-function-std-io-file-removedirectory-function-removedirectory-path-std-io-file-ml-253072106) | `std/io/file.ml:560` | 5 | 5 | 4 | 3 | 1 | 227.55 | 67.71 |
| [`std.io.file.size`](File-std-io-file-ml-2074692665.md#function-function-std-io-file-size-function-size-file-std-io-file-ml-1605500929) | `std/io/file.ml:434` | 7 | 7 | 3 | 2 | 1 | 285.29 | 63.97 |
| [`std.io.file.syncDirectory`](File-std-io-file-ml-2074692665.md#function-function-std-io-file-syncdirectory-function-syncdirectory-path-std-io-file-ml-367043320) | `std/io/file.ml:663` | 4 | 3 | 3 | 2 | 1 | 156.08 | 71.11 |
| [`std.io.file.truncate`](File-std-io-file-ml-2074692665.md#function-function-std-io-file-truncate-function-truncate-file-newsize-std-io-file-ml-718471930) | `std/io/file.ml:450` | 7 | 8 | 7 | 6 | 1 | 456.51 | 62 |
| [`std.io.file.unlock`](File-std-io-file-ml-2074692665.md#function-function-std-io-file-unlock-function-unlock-file-std-io-file-ml-810506305) | `std/io/file.ml:512` | 9 | 10 | 4 | 3 | 1 | 377.83 | 60.6 |
| [`std.io.file.writeAt`](File-std-io-file-ml-2074692665.md#function-function-std-io-file-writeat-function-writeat-file-fileoffset-source-sourceoffset-count-std-io-file-ml-307314880) | `std/io/file.ml:393` | 20 | 25 | 11 | 13 | 2 | 1283.43 | 48.37 |
| [`std.math.abs`](File-std-math-ml-790065500.md#function-function-std-math-abs-function-abs-x-std-math-ml-573377840) | `std/math.ml:32` | 9 | 5 | 3 | 2 | 1 | 134.89 | 63.87 |
| [`std.math.acos`](File-std-math-ml-790065500.md#function-function-std-math-acos-function-acos-x-std-math-ml-1386598144) | `std/math.ml:592` | 4 | 2 | 1 | 0 | 0 | 195.4 | 70.69 |
| [`std.math.asin`](File-std-math-ml-790065500.md#function-function-std-math-asin-function-asin-x-std-math-ml-224541764) | `std/math.ml:585` | 4 | 2 | 1 | 0 | 0 | 195.4 | 70.69 |
| [`std.math.atan`](File-std-math-ml-790065500.md#function-function-std-math-atan-function-atan-x-std-math-ml-2132826072) | `std/math.ml:364` | 17 | 13 | 3 | 2 | 1 | 555 | 53.54 |
| [`std.math.atan2`](File-std-math-ml-790065500.md#function-function-std-math-atan2-function-atan2-y-x-std-math-ml-1842524175) | `std/math.ml:389` | 19 | 12 | 6 | 6 | 2 | 499.96 | 52.4 |
| [`std.math.ceil`](File-std-math-ml-790065500.md#function-function-std-math-ceil-function-ceil-x-std-math-ml-1435593484) | `std/math.ml:113` | 10 | 6 | 3 | 2 | 1 | 181.52 | 61.97 |
| [`std.math.clamp`](File-std-math-ml-790065500.md#function-function-std-math-clamp-function-clamp-x-lo-hi-std-math-ml-473254544) | `std/math.ml:61` | 9 | 5 | 3 | 2 | 1 | 118.03 | 64.27 |
| [`std.math.cos`](File-std-math-ml-790065500.md#function-function-std-math-cos-function-cos-x-std-math-ml-638965610) | `std/math.ml:322` | 19 | 15 | 3 | 2 | 1 | 593.88 | 52.28 |
| [`std.math.cosh`](File-std-math-ml-790065500.md#function-function-std-math-cosh-function-cosh-x-std-math-ml-981216312) | `std/math.ml:607` | 5 | 3 | 1 | 0 | 0 | 127.44 | 69.88 |
| [`std.math.degToRad`](File-std-math-ml-790065500.md#function-function-std-math-degtorad-function-degtorad-deg-std-math-ml-600428704) | `std/math.ml:161` | 3 | 1 | 1 | 0 | 0 | 79.95 | 76.13 |
| [`std.math.e`](File-std-math-ml-790065500.md#function-function-std-math-e-function-e-std-math-ml-1291905090) | `std/math.ml:421` | 3 | 1 | 1 | 0 | 0 | 22.46 | 80 |
| [`std.math.exp`](File-std-math-ml-790065500.md#function-function-std-math-exp-function-exp-x-std-math-ml-847392178) | `std/math.ml:449` | 12 | 10 | 1 | 0 | 0 | 559.62 | 57.08 |
| [`std.math.expm1`](File-std-math-ml-790065500.md#function-function-std-math-expm1-function-expm1-x-std-math-ml-671119542) | `std/math.ml:471` | 9 | 6 | 2 | 1 | 1 | 280.54 | 61.77 |
| [`std.math.floor`](File-std-math-ml-790065500.md#function-function-std-math-floor-function-floor-x-std-math-ml-1858376096) | `std/math.ml:93` | 13 | 8 | 4 | 3 | 1 | 220.89 | 58.75 |
| [`std.math.fract`](File-std-math-ml-790065500.md#function-function-std-math-fract-function-fract-x-std-math-ml-123616796) | `std/math.ml:623` | 3 | 1 | 1 | 0 | 0 | 64.53 | 76.79 |
| [`std.math.gcd`](File-std-math-ml-790065500.md#function-function-std-math-gcd-function-gcd-a-b-std-math-ml-520129697) | `std/math.ml:240` | 13 | 9 | 4 | 3 | 1 | 302.61 | 57.79 |
| [`std.math.hypot`](File-std-math-ml-790065500.md#function-function-std-math-hypot-function-hypot-x-y-std-math-ml-336937453) | `std/math.ml:416` | 3 | 1 | 1 | 0 | 0 | 109.39 | 75.18 |
| [`std.math.invSqrt`](File-std-math-ml-790065500.md#function-function-std-math-invsqrt-function-invsqrt-x-std-math-ml-1022224274) | `std/math.ml:575` | 7 | 4 | 2 | 1 | 1 | 127.44 | 66.55 |
| [`std.math.isIntValue`](File-std-math-ml-790065500.md#function-function-std-math-isintvalue-function-isintvalue-x-std-math-ml-23293032) | `std/math.ml:437` | 9 | 5 | 3 | 2 | 1 | 181.52 | 62.96 |
| [`std.math.isNumber`](File-std-math-ml-790065500.md#function-function-std-math-isnumber-function-isnumber-x-std-math-ml-2115637864) | `std/math.ml:25` | 4 | 2 | 1 | 0 | 0 | 79.95 | 73.41 |
| [`std.math.lcm`](File-std-math-ml-790065500.md#function-function-std-math-lcm-function-lcm-a-b-std-math-ml-2106405213) | `std/math.ml:259` | 14 | 9 | 6 | 5 | 1 | 361.37 | 56.28 |
| [`std.math.lerp`](File-std-math-ml-790065500.md#function-function-std-math-lerp-function-lerp-a-b-t-std-math-ml-1477438275) | `std/math.ml:631` | 3 | 1 | 1 | 0 | 0 | 85.11 | 75.94 |
| [`std.math.ln`](File-std-math-ml-790065500.md#function-function-std-math-ln-function-ln-x-std-math-ml-120611688) | `std/math.ml:484` | 24 | 19 | 4 | 3 | 1 | 723.27 | 49.33 |
| [`std.math.ln10`](File-std-math-ml-790065500.md#function-function-std-math-ln10-function-ln10-std-math-ml-177958864) | `std/math.ml:431` | 3 | 1 | 1 | 0 | 0 | 22.46 | 80 |
| [`std.math.ln1p`](File-std-math-ml-790065500.md#function-function-std-math-ln1p-function-ln1p-x-std-math-ml-858417300) | `std/math.ml:519` | 9 | 6 | 2 | 1 | 1 | 280.54 | 61.77 |
| [`std.math.ln2`](File-std-math-ml-790065500.md#function-function-std-math-ln2-function-ln2-std-math-ml-236134708) | `std/math.ml:426` | 3 | 1 | 1 | 0 | 0 | 22.46 | 80 |
| [`std.math.log10`](File-std-math-ml-790065500.md#function-function-std-math-log10-function-log10-x-std-math-ml-1652022478) | `std/math.ml:532` | 3 | 1 | 1 | 0 | 0 | 88.81 | 75.81 |
| [`std.math.log2`](File-std-math-ml-790065500.md#function-function-std-math-log2-function-log2-x-std-math-ml-559981656) | `std/math.ml:538` | 3 | 1 | 1 | 0 | 0 | 88.81 | 75.81 |
| [`std.math.max`](File-std-math-ml-790065500.md#function-function-std-math-max-function-max-a-b-std-math-ml-1771960409) | `std/math.ml:84` | 6 | 3 | 2 | 1 | 1 | 71.7 | 69.76 |
| [`std.math.min`](File-std-math-ml-790065500.md#function-function-std-math-min-function-min-a-b-std-math-ml-1964626413) | `std/math.ml:74` | 6 | 3 | 2 | 1 | 1 | 71.7 | 69.76 |
| [`std.math.pi`](File-std-math-ml-790065500.md#function-function-std-math-pi-function-pi-std-math-ml-108227704) | `std/math.ml:150` | 3 | 1 | 1 | 0 | 0 | 22.46 | 80 |
| [`std.math.pow`](File-std-math-ml-790065500.md#function-function-std-math-pow-function-pow-base-exponent-std-math-ml-903671006) | `std/math.ml:545` | 21 | 13 | 7 | 9 | 2 | 493.55 | 51.36 |
| [`std.math.powi`](File-std-math-ml-790065500.md#function-function-std-math-powi-function-powi-base-exp-std-math-ml-456187076) | `std/math.ml:200` | 31 | 21 | 9 | 10 | 2 | 687.6 | 46.39 |
| [`std.math.radToDeg`](File-std-math-ml-790065500.md#function-function-std-math-radtodeg-function-radtodeg-rad-std-math-ml-511407857) | `std/math.ml:167` | 3 | 1 | 1 | 0 | 0 | 79.95 | 76.13 |
| [`std.math.round`](File-std-math-ml-790065500.md#function-function-std-math-round-function-round-x-std-math-ml-891501820) | `std/math.ml:139` | 9 | 5 | 3 | 2 | 1 | 214.05 | 62.46 |
| [`std.math.sign`](File-std-math-ml-790065500.md#function-function-std-math-sign-function-sign-x-std-math-ml-1470077816) | `std/math.ml:44` | 12 | 7 | 4 | 3 | 1 | 178.41 | 60.16 |
| [`std.math.sin`](File-std-math-ml-790065500.md#function-function-std-math-sin-function-sin-x-std-math-ml-77784832) | `std/math.ml:293` | 20 | 16 | 3 | 2 | 1 | 624.5 | 51.64 |
| [`std.math.sinh`](File-std-math-ml-790065500.md#function-function-std-math-sinh-function-sinh-x-std-math-ml-1215837824) | `std/math.ml:599` | 5 | 3 | 1 | 0 | 0 | 127.44 | 69.88 |
| [`std.math.smoothstep`](File-std-math-ml-790065500.md#function-function-std-math-smoothstep-function-smoothstep-edge0-edge1-x-std-math-ml-541762641) | `std/math.ml:639` | 8 | 5 | 2 | 1 | 1 | 277.33 | 62.93 |
| [`std.math.sqrt`](File-std-math-ml-790065500.md#function-function-std-math-sqrt-function-sqrt-x-std-math-ml-760602576) | `std/math.ml:173` | 20 | 14 | 5 | 5 | 2 | 405 | 52.69 |
| [`std.math.tan`](File-std-math-ml-790065500.md#function-function-std-math-tan-function-tan-x-std-math-ml-1295707230) | `std/math.ml:350` | 10 | 6 | 3 | 3 | 2 | 255.41 | 60.93 |
| [`std.math.tanh`](File-std-math-ml-790065500.md#function-function-std-math-tanh-function-tanh-x-std-math-ml-933610836) | `std/math.ml:615` | 5 | 3 | 1 | 0 | 0 | 141.78 | 69.55 |
| [`std.math.tau`](File-std-math-ml-790065500.md#function-function-std-math-tau-function-tau-std-math-ml-722341156) | `std/math.ml:155` | 3 | 1 | 1 | 0 | 0 | 57.36 | 77.14 |
| [`std.math.trunc`](File-std-math-ml-790065500.md#function-function-std-math-trunc-function-trunc-x-std-math-ml-1042085096) | `std/math.ml:126` | 9 | 5 | 3 | 2 | 1 | 212.55 | 62.48 |
| [`std.net.cleanup`](File-std-net-ml-1989130045.md#function-function-std-net-cleanup-synchronized-function-cleanup-std-net-ml-1900488416) | `std/net.ml:264` | 11 | 7 | 3 | 2 | 1 | 145.95 | 61.73 |
| [`std.net.close`](File-std-net-ml-1989130045.md#function-function-std-net-close-function-close-sock-std-net-ml-2027943708) | `std/net.ml:742` | 7 | 4 | 2 | 1 | 1 | 114.45 | 66.88 |
| [`std.net.init`](File-std-net-ml-1989130045.md#function-function-std-net-init-synchronized-function-init-std-net-ml-1993957128) | `std/net.ml:239` | 13 | 9 | 3 | 2 | 1 | 221.65 | 58.87 |
| [`std.net.lastError`](File-std-net-ml-1989130045.md#function-function-std-net-lasterror-function-lasterror-std-net-ml-1066354328) | `std/net.ml:284` | 3 | 1 | 1 | 0 | 0 | 28.07 | 79.32 |
| [`std.net.setKeepAlive`](File-std-net-ml-1989130045.md#function-function-std-net-setkeepalive-function-setkeepalive-sock-enabled-std-net-ml-1531381615) | `std/net.ml:474` | 3 | 1 | 1 | 0 | 0 | 81.41 | 76.08 |
| [`std.net.setNoDelay`](File-std-net-ml-1989130045.md#function-function-std-net-setnodelay-function-setnodelay-sock-enabled-std-net-ml-976341439) | `std/net.ml:481` | 3 | 1 | 1 | 0 | 0 | 81.41 | 76.08 |
| [`std.net.setReceiveTimeout`](File-std-net-ml-1989130045.md#function-function-std-net-setreceivetimeout-function-setreceivetimeout-sock-milliseconds-std-net-ml-2114040622) | `std/net.ml:504` | 3 | 1 | 1 | 0 | 0 | 71.7 | 76.47 |
| [`std.net.setReuseAddress`](File-std-net-ml-1989130045.md#function-function-std-net-setreuseaddress-function-setreuseaddress-sock-enabled-std-net-ml-620588191) | `std/net.ml:429` | 7 | 5 | 3 | 3 | 2 | 248.8 | 64.39 |
| [`std.net.setSendTimeout`](File-std-net-ml-1989130045.md#function-function-std-net-setsendtimeout-function-setsendtimeout-sock-milliseconds-std-net-ml-739144534) | `std/net.ml:511` | 3 | 1 | 1 | 0 | 0 | 71.7 | 76.47 |
| [`std.net.tcpAccept`](File-std-net-ml-1989130045.md#function-function-std-net-tcpaccept-function-tcpaccept-serversocket-std-net-ml-1658993728) | `std/net.ml:621` | 10 | 6 | 3 | 2 | 1 | 233.83 | 61.2 |
| [`std.net.tcpAcceptPeer`](File-std-net-ml-1989130045.md#function-function-std-net-tcpacceptpeer-function-tcpacceptpeer-serversocket-std-net-ml-324030640) | `std/net.ml:637` | 18 | 14 | 3 | 2 | 1 | 572.02 | 52.91 |
| [`std.net.tcpConnect`](File-std-net-ml-1989130045.md#function-function-std-net-tcpconnect-function-tcpconnect-host-port-std-net-ml-1793379633) | `std/net.ml:522` | 24 | 17 | 6 | 5 | 1 | 735.91 | 49.01 |
| [`std.net.tcpListen`](File-std-net-ml-1989130045.md#function-function-std-net-tcplisten-function-tcplisten-port-backlog-std-net-ml-2129811236) | `std/net.ml:554` | 31 | 25 | 8 | 7 | 1 | 1038.47 | 45.27 |
| [`std.net.tcpListenAddress`](File-std-net-ml-1989130045.md#function-function-std-net-tcplistenaddress-function-tcplistenaddress-host-port-backlog-std-net-ml-1591213138) | `std/net.ml:595` | 23 | 26 | 9 | 8 | 1 | 1156.73 | 47.64 |
| [`std.net.tcpRecv`](File-std-net-ml-1989130045.md#function-function-std-net-tcprecv-function-tcprecv-sock-maxbytes-std-net-ml-76662791) | `std/net.ml:699` | 20 | 13 | 6 | 5 | 1 | 539.75 | 51.68 |
| [`std.net.tcpSendAll`](File-std-net-ml-1989130045.md#function-function-std-net-tcpsendall-function-tcpsendall-sock-data-std-net-ml-931993120) | `std/net.ml:664` | 24 | 16 | 7 | 7 | 2 | 661.24 | 49.2 |
| [`std.net.tcpShutdown`](File-std-net-ml-1989130045.md#function-function-std-net-tcpshutdown-function-tcpshutdown-sock-how-std-net-ml-386614342) | `std/net.ml:728` | 10 | 6 | 3 | 2 | 1 | 203.56 | 61.62 |
| [`std.net.udpBind`](File-std-net-ml-1989130045.md#function-function-std-net-udpbind-function-udpbind-sock-port-std-net-ml-259267451) | `std/net.ml:771` | 16 | 12 | 5 | 4 | 1 | 492.41 | 54.21 |
| [`std.net.udpOpen`](File-std-net-ml-1989130045.md#function-function-std-net-udpopen-function-udpopen-std-net-ml-167881978) | `std/net.ml:755` | 10 | 6 | 3 | 2 | 1 | 232.19 | 61.22 |
| [`std.net.udpRecvFrom`](File-std-net-ml-1989130045.md#function-function-std-net-udprecvfrom-function-udprecvfrom-sock-maxbytes-std-net-ml-226021939) | `std/net.ml:829` | 22 | 16 | 5 | 4 | 1 | 791.62 | 49.75 |
| [`std.net.udpSendTo`](File-std-net-ml-1989130045.md#function-function-std-net-udpsendto-function-udpsendto-sock-host-port-data-std-net-ml-2003989505) | `std/net.ml:796` | 24 | 16 | 7 | 6 | 1 | 771.1 | 48.74 |
| [`std.path.changeExtension`](File-std-path-ml-701536411.md#function-function-std-path-changeextension-function-changeextension-path-newextension-std-path-ml-379942222) | `std/path.ml:121` | 9 | 11 | 6 | 5 | 1 | 543.7 | 59.22 |
| [`std.path.directoryName`](File-std-path-ml-701536411.md#function-function-std-path-directoryname-function-directoryname-path-std-path-ml-1704846025) | `std/path.ml:89` | 14 | 13 | 6 | 8 | 3 | 479.22 | 55.42 |
| [`std.path.extension`](File-std-path-ml-701536411.md#function-function-std-path-extension-function-extension-path-std-path-ml-598017679) | `std/path.ml:106` | 11 | 10 | 5 | 5 | 2 | 430 | 58.17 |
| [`std.path.fileName`](File-std-path-ml-701536411.md#function-function-std-path-filename-function-filename-path-std-path-ml-8033517) | `std/path.ml:72` | 14 | 13 | 6 | 8 | 3 | 539.75 | 55.06 |
| [`std.path.isAbsolute`](File-std-path-ml-701536411.md#function-function-std-path-isabsolute-function-isabsolute-path-std-path-ml-2109808033) | `std/path.ml:41` | 7 | 8 | 13 | 12 | 1 | 630.9 | 60.21 |
| [`std.path.join`](File-std-path-ml-701536411.md#function-function-std-path-join-function-join-left-right-std-path-ml-2015239089) | `std/path.ml:56` | 13 | 17 | 10 | 9 | 1 | 729.46 | 54.31 |
| [`std.path.separator`](File-std-path-ml-701536411.md#function-function-std-path-separator-function-separator-std-path-ml-1502985602) | `std/path.ml:25` | 3 | 1 | 1 | 0 | 0 | 38.04 | 78.39 |
| [`std.platform.architecture`](File-std-platform-ml-201801091.md#function-function-std-platform-architecture-function-architecture-std-platform-ml-585994492) | `std/platform.ml:24` | 3 | 1 | 1 | 0 | 0 | 22.46 | 80 |
| [`std.platform.dynamicLibraryExtension`](File-std-platform-ml-201801091.md#function-function-std-platform-dynamiclibraryextension-function-dynamiclibraryextension-std-platform-ml-724141498) | `std/platform.ml:74` | 3 | 1 | 1 | 0 | 0 | 22.46 | 80 |
| [`std.platform.executableExtension`](File-std-platform-ml-201801091.md#function-function-std-platform-executableextension-function-executableextension-std-platform-ml-304518794) | `std/platform.ml:65` | 3 | 1 | 1 | 0 | 0 | 22.46 | 80 |
| [`std.platform.isLinux`](File-std-platform-ml-201801091.md#function-function-std-platform-islinux-function-islinux-std-platform-ml-689142728) | `std/platform.ml:38` | 3 | 1 | 1 | 0 | 0 | 22.46 | 80 |
| [`std.platform.isWindows`](File-std-platform-ml-201801091.md#function-function-std-platform-iswindows-function-iswindows-std-platform-ml-1628994826) | `std/platform.ml:29` | 3 | 1 | 1 | 0 | 0 | 22.46 | 80 |
| [`std.platform.lineEnding`](File-std-platform-ml-201801091.md#function-function-std-platform-lineending-function-lineending-std-platform-ml-807574324) | `std/platform.ml:56` | 3 | 1 | 1 | 0 | 0 | 22.46 | 80 |
| [`std.platform.operatingSystem`](File-std-platform-ml-201801091.md#function-function-std-platform-operatingsystem-function-operatingsystem-std-platform-ml-1171546320) | `std/platform.ml:15` | 3 | 1 | 1 | 0 | 0 | 22.46 | 80 |
| [`std.platform.pathSeparator`](File-std-platform-ml-201801091.md#function-function-std-platform-pathseparator-function-pathseparator-std-platform-ml-2119383760) | `std/platform.ml:47` | 3 | 1 | 1 | 0 | 0 | 22.46 | 80 |
| [`std.process.currentDirectory`](File-std-process-ml-507069519.md#function-function-std-process-currentdirectory-function-currentdirectory-std-process-ml-1016102948) | `std/process.ml:116` | 6 | 5 | 3 | 2 | 1 | 206.32 | 66.42 |
| [`std.process.environment`](File-std-process-ml-507069519.md#function-function-std-process-environment-function-environment-name-std-process-ml-1459757785) | `std/process.ml:94` | 10 | 12 | 7 | 6 | 1 | 523.19 | 58.21 |
| [`std.process.executablePath`](File-std-process-ml-507069519.md#function-function-std-process-executablepath-function-executablepath-std-process-ml-649110652) | `std/process.ml:77` | 6 | 5 | 3 | 2 | 1 | 215.49 | 66.28 |
| [`std.process.id`](File-std-process-ml-507069519.md#function-function-std-process-id-function-id-std-process-ml-156871044) | `std/process.ml:68` | 3 | 1 | 1 | 0 | 0 | 28.07 | 79.32 |
| [`std.process.setCurrentDirectory`](File-std-process-ml-507069519.md#function-function-std-process-setcurrentdirectory-function-setcurrentdirectory-path-std-process-ml-2023618091) | `std/process.ml:132` | 5 | 5 | 4 | 3 | 1 | 200.67 | 68.09 |
| [`std.random.choice`](File-std-random-ml-66683891.md#function-function-std-random-choice-function-choice-rng-xs-std-random-ml-362850290) | `std/random.ml:136` | 10 | 6 | 3 | 2 | 1 | 199.04 | 61.69 |
| [`std.random.RNG.nextBool`](Type-std-random-rng-1201142756.md#method-method-std-random-rng-nextbool-function-nextbool-std-random-ml-792594308) | `std/random.ml:83` | 3 | 1 | 1 | 0 | 0 | 64.53 | 76.79 |
| [`std.random.RNG.nextFloat`](Type-std-random-rng-1201142756.md#method-method-std-random-rng-nextfloat-function-nextfloat-std-random-ml-266740162) | `std/random.ml:77` | 3 | 1 | 1 | 0 | 0 | 66.61 | 76.69 |
| [`std.random.RNG.nextInt`](Type-std-random-rng-1201142756.md#method-method-std-random-rng-nextint-function-nextint-maxexclusive-std-random-ml-549682610) | `std/random.ml:66` | 9 | 5 | 3 | 2 | 1 | 145.95 | 63.63 |
| [`std.random.RNG.nextU32`](Type-std-random-rng-1201142756.md#method-method-std-random-rng-nextu32-function-nextu32-std-random-ml-1111191742) | `std/random.ml:55` | 8 | 6 | 1 | 0 | 0 | 303.07 | 62.79 |
| [`std.random.RNG.rangeFloat`](Type-std-random-rng-1201142756.md#method-method-std-random-rng-rangefloat-function-rangefloat-mininclusive-maxexclusive-std-random-ml-375016824) | `std/random.ml:103` | 3 | 1 | 1 | 0 | 0 | 97.67 | 75.53 |
| [`std.random.RNG.rangeInt`](Type-std-random-rng-1201142756.md#method-method-std-random-rng-rangeint-function-rangeint-mininclusive-maxexclusive-std-random-ml-1648743864) | `std/random.ml:90` | 9 | 5 | 4 | 3 | 1 | 206.44 | 62.44 |
| [`std.random.RNG.Seed`](Type-std-random-rng-1201142756.md#static_method-static-method-std-random-rng-seed-static-function-seed-seed-std-random-ml-1525826490) | `std/random.ml:35` | 15 | 9 | 4 | 4 | 2 | 354.63 | 55.95 |
| [`std.random.seeded`](File-std-random-ml-66683891.md#function-function-std-random-seeded-function-seeded-seed-std-random-ml-2021080487) | `std/random.ml:110` | 3 | 1 | 1 | 0 | 0 | 64.53 | 76.79 |
| [`std.random.shuffleInPlace`](File-std-random-ml-66683891.md#function-function-std-random-shuffleinplace-function-shuffleinplace-rng-xs-std-random-ml-2030459042) | `std/random.ml:117` | 14 | 10 | 3 | 2 | 1 | 354.63 | 56.74 |
| [`std.result.Option.andThen`](Type-std-result-option-1652402760.md#method-method-std-result-option-andthen-function-andthen-f-std-result-ml-1549329048) | `std/result.ml:86` | 6 | 3 | 2 | 1 | 1 | 126.71 | 68.03 |
| [`std.result.Option.isNone`](Type-std-result-option-1652402760.md#method-method-std-result-option-isnone-function-isnone-std-result-ml-2144417308) | `std/result.ml:45` | 3 | 1 | 1 | 0 | 0 | 36.54 | 78.52 |
| [`std.result.Option.isSome`](Type-std-result-option-1652402760.md#method-method-std-result-option-issome-function-issome-std-result-ml-965212188) | `std/result.ml:40` | 3 | 1 | 1 | 0 | 0 | 31.7 | 78.95 |
| [`std.result.Option.map`](Type-std-result-option-1652402760.md#method-method-std-result-option-map-function-map-f-std-result-ml-1644523560) | `std/result.ml:77` | 6 | 3 | 2 | 1 | 1 | 166.8 | 67.2 |
| [`std.result.Option.None`](Type-std-result-option-1652402760.md#static_method-static-method-std-result-option-none-static-function-none-std-result-ml-1586653) | `std/result.ml:35` | 3 | 1 | 1 | 0 | 0 | 68.53 | 76.6 |
| [`std.result.Option.Some`](Type-std-result-option-1652402760.md#static_method-static-method-std-result-option-some-static-function-some-v-std-result-ml-1822127959) | `std/result.ml:30` | 3 | 1 | 1 | 0 | 0 | 72.34 | 76.44 |
| [`std.result.Option.unwrap`](Type-std-result-option-1652402760.md#method-method-std-result-option-unwrap-function-unwrap-std-result-ml-660767988) | `std/result.ml:59` | 6 | 3 | 2 | 1 | 1 | 64.53 | 70.08 |
| [`std.result.Option.unwrapOr`](Type-std-result-option-1652402760.md#method-method-std-result-option-unwrapor-function-unwrapor-fallback-std-result-ml-1110684614) | `std/result.ml:51` | 6 | 3 | 2 | 1 | 1 | 74.01 | 69.67 |
| [`std.result.Option.unwrapOrElse`](Type-std-result-option-1652402760.md#method-method-std-result-option-unwraporelse-function-unwraporelse-thunk-std-result-ml-183966738) | `std/result.ml:68` | 6 | 3 | 2 | 1 | 1 | 81.41 | 69.38 |
| [`std.result.Result.andThen`](Type-std-result-result-654473432.md#method-method-std-result-result-andthen-function-andthen-f-std-result-ml-3241512) | `std/result.ml:153` | 6 | 3 | 2 | 1 | 1 | 85.11 | 69.24 |
| [`std.result.Result.Err`](Type-std-result-result-654473432.md#static_method-static-method-std-result-result-err-static-function-err-msg-std-result-ml-1963913706) | `std/result.ml:111` | 3 | 1 | 1 | 0 | 0 | 82.04 | 76.06 |
| [`std.result.Result.isErr`](Type-std-result-result-654473432.md#method-method-std-result-result-iserr-function-iserr-std-result-ml-195507302) | `std/result.ml:121` | 3 | 1 | 1 | 0 | 0 | 36.54 | 78.52 |
| [`std.result.Result.isOk`](Type-std-result-result-654473432.md#method-method-std-result-result-isok-function-isok-std-result-ml-1733939076) | `std/result.ml:116` | 3 | 1 | 1 | 0 | 0 | 31.7 | 78.95 |
| [`std.result.Result.map`](Type-std-result-result-654473432.md#method-method-std-result-result-map-function-map-f-std-result-ml-1978001208) | `std/result.ml:144` | 6 | 3 | 2 | 1 | 1 | 130.8 | 67.94 |
| [`std.result.Result.Ok`](Type-std-result-result-654473432.md#static_method-static-method-std-result-result-ok-static-function-ok-v-std-result-ml-455002863) | `std/result.ml:105` | 3 | 1 | 1 | 0 | 0 | 82.04 | 76.06 |
| [`std.result.Result.unwrap`](Type-std-result-result-654473432.md#method-method-std-result-result-unwrap-function-unwrap-std-result-ml-271790180) | `std/result.ml:135` | 6 | 3 | 2 | 1 | 1 | 64.53 | 70.08 |
| [`std.result.Result.unwrapOr`](Type-std-result-result-654473432.md#method-method-std-result-result-unwrapor-function-unwrapor-fallback-std-result-ml-1349488118) | `std/result.ml:127` | 6 | 3 | 2 | 1 | 1 | 74.01 | 69.67 |
| [`std.sort.isSorted`](File-std-sort-ml-1000391650.md#function-function-std-sort-issorted-function-issorted-arr-lessfn-std-sort-ml-1072433950) | `std/sort.ml:168` | 18 | 11 | 6 | 6 | 2 | 417.09 | 53.46 |
| [`std.sort.sort`](File-std-sort-ml-1000391650.md#function-function-std-sort-sort-function-sort-arr-std-sort-ml-333187585) | `std/sort.ml:39` | 3 | 1 | 1 | 0 | 0 | 46.51 | 77.78 |
| [`std.sort.sortBy`](File-std-sort-ml-1000391650.md#function-function-std-sort-sortby-function-sortby-arr-lessfn-std-sort-ml-529537194) | `std/sort.ml:46` | 24 | 17 | 7 | 7 | 2 | 595.23 | 49.52 |
| [`std.sort.sortFast`](File-std-sort-ml-1000391650.md#function-function-std-sort-sortfast-function-sortfast-arr-std-sort-ml-1925522137) | `std/sort.ml:81` | 3 | 1 | 1 | 0 | 0 | 46.51 | 77.78 |
| [`std.sort.sortFastBy`](File-std-sort-ml-1000391650.md#function-function-std-sort-sortfastby-function-sortfastby-arr-lessfn-std-sort-ml-1761662250) | `std/sort.ml:88` | 59 | 45 | 11 | 25 | 4 | 1533.07 | 37.59 |
| [`std.string.contains`](File-std-string-ml-1276545685.md#function-function-std-string-contains-function-contains-s-needle-std-string-ml-890712776) | `std/string.ml:301` | 7 | 4 | 2 | 1 | 1 | 151.27 | 66.03 |
| [`std.string.countOf`](File-std-string-ml-1276545685.md#function-function-std-string-countof-function-countof-s-needle-std-string-ml-1466834176) | `std/string.ml:489` | 24 | 17 | 6 | 6 | 2 | 490.47 | 50.25 |
| [`std.string.endsWith`](File-std-string-ml-1276545685.md#function-function-std-string-endswith-function-endswith-s-suffix-std-string-ml-1833247770) | `std/string.ml:264` | 3 | 1 | 1 | 0 | 0 | 53.15 | 77.38 |
| [`std.string.equalsIgnoreCaseAscii`](File-std-string-ml-1276545685.md#function-function-std-string-equalsignorecaseascii-function-equalsignorecaseascii-a-b-std-string-ml-2118708601) | `std/string.ml:579` | 3 | 1 | 1 | 0 | 0 | 53.15 | 77.38 |
| [`std.string.indexOf`](File-std-string-ml-1276545685.md#function-function-std-string-indexof-function-indexof-s-needle-start-std-string-ml-1830793656) | `std/string.ml:272` | 12 | 7 | 4 | 3 | 1 | 216.64 | 59.57 |
| [`std.string.isAlnumAscii`](File-std-string-ml-1276545685.md#function-function-std-string-isalnumascii-function-isalnumascii-ch-std-string-ml-991856061) | `std/string.ml:560` | 3 | 1 | 1 | 0 | 0 | 92.51 | 75.69 |
| [`std.string.isAlphaAscii`](File-std-string-ml-1276545685.md#function-function-std-string-isalphaascii-function-isalphaascii-ch-std-string-ml-69464141) | `std/string.ml:548` | 9 | 5 | 3 | 2 | 1 | 230.7 | 62.23 |
| [`std.string.isBlank`](File-std-string-ml-1276545685.md#function-function-std-string-isblank-function-isblank-s-std-string-ml-1002423985) | `std/string.ml:329` | 3 | 1 | 1 | 0 | 0 | 36 | 78.56 |
| [`std.string.isDigitAscii`](File-std-string-ml-1276545685.md#function-function-std-string-isdigitascii-function-isdigitascii-ch-std-string-ml-1642095953) | `std/string.ml:536` | 9 | 5 | 3 | 2 | 1 | 168.56 | 63.19 |
| [`std.string.isEmpty`](File-std-string-ml-1276545685.md#function-function-std-string-isempty-function-isempty-s-std-string-ml-464897055) | `std/string.ml:232` | 6 | 3 | 2 | 1 | 1 | 104 | 68.63 |
| [`std.string.join`](File-std-string-ml-1276545685.md#function-function-std-string-join-function-join-parts-sep-std-string-ml-1383969706) | `std/string.ml:388` | 3 | 1 | 1 | 0 | 0 | 53.15 | 77.38 |
| [`std.string.lastIndexOf`](File-std-string-ml-1276545685.md#function-function-std-string-lastindexof-function-lastindexof-s-needle-std-string-ml-183528886) | `std/string.ml:288` | 9 | 5 | 3 | 2 | 1 | 148.46 | 63.58 |
| [`std.string.ltrim`](File-std-string-ml-1276545685.md#function-function-std-string-ltrim-function-ltrim-s-std-string-ml-1358329729) | `std/string.ml:311` | 3 | 1 | 1 | 0 | 0 | 36 | 78.56 |
| [`std.string.removeAll`](File-std-string-ml-1276545685.md#function-function-std-string-removeall-function-removeall-s-needle-std-string-ml-1652900222) | `std/string.ml:520` | 3 | 1 | 1 | 0 | 0 | 83.76 | 75.99 |
| [`std.string.repeat`](File-std-string-ml-1276545685.md#function-function-std-string-repeat-function-repeat-s-count-std-string-ml-194349680) | `std/string.ml:242` | 3 | 1 | 1 | 0 | 0 | 53.15 | 77.38 |
| [`std.string.replaceAll`](File-std-string-ml-1276545685.md#function-function-std-string-replaceall-function-replaceall-s-needle-repl-std-string-ml-840926615) | `std/string.ml:396` | 41 | 29 | 11 | 15 | 3 | 1040.72 | 42.21 |
| [`std.string.replaceFirst`](File-std-string-ml-1276545685.md#function-function-std-string-replacefirst-function-replacefirst-s-needle-repl-std-string-ml-1457517015) | `std/string.ml:446` | 36 | 25 | 10 | 9 | 1 | 913.14 | 43.98 |
| [`std.string.reverse`](File-std-string-ml-1276545685.md#function-function-std-string-reverse-function-reverse-s-std-string-ml-478686905) | `std/string.ml:526` | 3 | 1 | 1 | 0 | 0 | 36 | 78.56 |
| [`std.string.rtrim`](File-std-string-ml-1276545685.md#function-function-std-string-rtrim-function-rtrim-s-std-string-ml-2074447113) | `std/string.ml:317` | 3 | 1 | 1 | 0 | 0 | 36 | 78.56 |
| [`std.string.split`](File-std-string-ml-1276545685.md#function-function-std-string-split-function-split-s-sep-std-string-ml-439300297) | `std/string.ml:336` | 42 | 32 | 9 | 11 | 2 | 1096.32 | 42.09 |
| [`std.string.startsWith`](File-std-string-ml-1276545685.md#function-function-std-string-startswith-function-startswith-s-prefix-std-string-ml-864273261) | `std/string.ml:257` | 3 | 1 | 1 | 0 | 0 | 53.15 | 77.38 |
| [`std.string.substr`](File-std-string-ml-1276545685.md#function-function-std-string-substr-function-substr-s-start-length-std-string-ml-1364948665) | `std/string.ml:250` | 3 | 1 | 1 | 0 | 0 | 69.19 | 76.57 |
| [`std.string.toLowerAscii`](File-std-string-ml-1276545685.md#function-function-std-string-tolowerascii-function-tolowerascii-s-std-string-ml-2007062345) | `std/string.ml:566` | 3 | 1 | 1 | 0 | 0 | 36 | 78.56 |
| [`std.string.toUpperAscii`](File-std-string-ml-1276545685.md#function-function-std-string-toupperascii-function-toupperascii-s-std-string-ml-994049617) | `std/string.ml:572` | 3 | 1 | 1 | 0 | 0 | 36 | 78.56 |
| [`std.string.trim`](File-std-string-ml-1276545685.md#function-function-std-string-trim-function-trim-s-std-string-ml-2004823441) | `std/string.ml:323` | 3 | 1 | 1 | 0 | 0 | 36 | 78.56 |
| [`std.string_builder.StringBuilder.append`](Type-std-string-builder-stringbuilder-567404247.md#method-method-std-string-builder-stringbuilder-append-function-append-value-std-string-builder-ml-1611521868) | `std/string_builder.ml:161` | 7 | 4 | 2 | 1 | 1 | 125.1 | 66.61 |
| [`std.string_builder.StringBuilder.appendLine`](Type-std-string-builder-stringbuilder-567404247.md#method-method-std-string-builder-stringbuilder-appendline-function-appendline-value-std-string-builder-ml-1228486276) | `std/string_builder.ml:171` | 4 | 2 | 1 | 0 | 0 | 65.73 | 74 |
| [`std.string_builder.StringBuilder.appendSlice`](Type-std-string-builder-stringbuilder-567404247.md#method-method-std-string-builder-stringbuilder-appendslice-function-appendslice-s-offset-length-std-string-builder-ml-924904113) | `std/string_builder.ml:119` | 36 | 25 | 10 | 9 | 1 | 763.12 | 44.52 |
| [`std.string_builder.StringBuilder.appendString`](Type-std-string-builder-stringbuilder-567404247.md#method-method-std-string-builder-stringbuilder-appendstring-function-appendstring-s-std-string-builder-ml-1654662588) | `std/string_builder.ml:102` | 12 | 8 | 3 | 2 | 1 | 292.56 | 58.79 |
| [`std.string_builder.StringBuilder.clear`](Type-std-string-builder-stringbuilder-567404247.md#method-method-std-string-builder-stringbuilder-clear-function-clear-std-string-builder-ml-1859141821) | `std/string_builder.ml:73` | 3 | 1 | 1 | 0 | 0 | 36.54 | 78.52 |
| [`std.string_builder.StringBuilder.len`](Type-std-string-builder-stringbuilder-567404247.md#method-method-std-string-builder-stringbuilder-len-function-len-std-string-builder-ml-444722389) | `std/string_builder.ml:68` | 3 | 1 | 1 | 0 | 0 | 31.7 | 78.95 |
| [`std.string_builder.StringBuilder.new`](Type-std-string-builder-stringbuilder-567404247.md#static_method-static-method-std-string-builder-stringbuilder-new-static-function-new-std-string-builder-ml-1046518366) | `std/string_builder.ml:50` | 3 | 1 | 1 | 0 | 0 | 66.61 | 76.69 |
| [`std.string_builder.StringBuilder.reserve`](Type-std-string-builder-stringbuilder-567404247.md#method-method-std-string-builder-stringbuilder-reserve-function-reserve-extra-std-string-builder-ml-1183173349) | `std/string_builder.ml:79` | 19 | 13 | 5 | 4 | 1 | 446.93 | 52.88 |
| [`std.string_builder.StringBuilder.toString`](Type-std-string-builder-stringbuilder-567404247.md#method-method-std-string-builder-stringbuilder-tostring-function-tostring-std-string-builder-ml-1779129711) | `std/string_builder.ml:177` | 6 | 3 | 2 | 1 | 1 | 137.61 | 67.78 |
| [`std.string_builder.StringBuilder.withCapacity`](Type-std-string-builder-stringbuilder-567404247.md#static_method-static-method-std-string-builder-stringbuilder-withcapacity-static-function-withcapacity-cap-std-string-builder-ml-306477140) | `std/string_builder.ml:56` | 10 | 6 | 3 | 2 | 1 | 255.41 | 60.93 |
| [`std.threading.Event.close`](Type-std-threading-event-883500562.md#method-method-std-threading-event-close-function-close-std-threading-ml-458936001) | `std/threading.ml:289` | 9 | 7 | 3 | 2 | 1 | 166.8 | 63.22 |
| [`std.threading.Event.isClosed`](Type-std-threading-event-883500562.md#method-method-std-threading-event-isclosed-function-isclosed-std-threading-ml-424965693) | `std/threading.ml:284` | 3 | 1 | 1 | 0 | 0 | 31.7 | 78.95 |
| [`std.threading.Event.IsClosed`](Type-std-threading-event-883500562.md#method-method-std-threading-event-isclosed-function-isclosed-std-threading-ml-2083169725) | `std/threading.ml:311` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.threading.Event.new`](Type-std-threading-event-883500562.md#static_method-static-method-std-threading-event-new-static-function-new-manualreset-initialstate-std-threading-ml-955984394) | `std/threading.ml:240` | 10 | 6 | 4 | 3 | 1 | 331.71 | 60 |
| [`std.threading.Event.reset`](Type-std-threading-event-883500562.md#method-method-std-threading-event-reset-function-reset-std-threading-ml-899439323) | `std/threading.ml:278` | 4 | 3 | 2 | 1 | 1 | 83.76 | 73.13 |
| [`std.threading.Event.Reset`](Type-std-threading-event-883500562.md#method-method-std-threading-event-reset-function-reset-std-threading-ml-851676123) | `std/threading.ml:309` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.threading.Event.set`](Type-std-threading-event-883500562.md#method-method-std-threading-event-set-function-set-std-threading-ml-175502265) | `std/threading.ml:272` | 4 | 3 | 2 | 1 | 1 | 83.76 | 73.13 |
| [`std.threading.Event.Set`](Type-std-threading-event-883500562.md#method-method-std-threading-event-set-function-set-std-threading-ml-1006217145) | `std/threading.ml:307` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.threading.Event.tryWait`](Type-std-threading-event-883500562.md#method-method-std-threading-event-trywait-function-trywait-std-threading-ml-1669113241) | `std/threading.ml:267` | 3 | 1 | 1 | 0 | 0 | 43.19 | 78.01 |
| [`std.threading.Event.TryWait`](Type-std-threading-event-883500562.md#method-method-std-threading-event-trywait-function-trywait-std-threading-ml-1736278617) | `std/threading.ml:305` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.threading.Event.wait`](Type-std-threading-event-883500562.md#method-method-std-threading-event-wait-function-wait-std-threading-ml-2104680781) | `std/threading.ml:252` | 4 | 3 | 2 | 1 | 1 | 110.36 | 72.29 |
| [`std.threading.Event.Wait`](Type-std-threading-event-883500562.md#method-method-std-threading-event-wait-function-wait-std-threading-ml-2053849165) | `std/threading.ml:300` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.threading.Event.waitFor`](Type-std-threading-event-883500562.md#method-method-std-threading-event-waitfor-function-waitfor-milliseconds-std-threading-ml-1897816367) | `std/threading.ml:259` | 6 | 3 | 5 | 4 | 1 | 199.69 | 66.25 |
| [`std.threading.Event.WaitFor`](Type-std-threading-event-883500562.md#method-method-std-threading-event-waitfor-function-waitfor-milliseconds-std-threading-ml-1651884527) | `std/threading.ml:303` | 1 | 1 | 1 | 0 | 0 | 46.51 | 88.19 |
| [`std.threading.Lock.Acquire`](Type-std-threading-lock-164120817.md#method-method-std-threading-lock-acquire-function-acquire-std-threading-ml-730248196) | `std/threading.ml:124` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.threading.Lock.acquire`](Type-std-threading-lock-164120817.md#method-method-std-threading-lock-acquire-function-acquire-std-threading-ml-1409763972) | `std/threading.ml:82` | 4 | 3 | 2 | 1 | 1 | 110.36 | 72.29 |
| [`std.threading.Lock.AcquireFor`](Type-std-threading-lock-164120817.md#method-method-std-threading-lock-acquirefor-function-acquirefor-milliseconds-std-threading-ml-706820674) | `std/threading.ml:127` | 1 | 1 | 1 | 0 | 0 | 46.51 | 88.19 |
| [`std.threading.Lock.acquireFor`](Type-std-threading-lock-164120817.md#method-method-std-threading-lock-acquirefor-function-acquirefor-milliseconds-std-threading-ml-1593851138) | `std/threading.ml:89` | 6 | 3 | 5 | 4 | 1 | 199.69 | 66.25 |
| [`std.threading.Lock.close`](Type-std-threading-lock-164120817.md#method-method-std-threading-lock-close-function-close-std-threading-ml-259621520) | `std/threading.ml:113` | 9 | 7 | 3 | 2 | 1 | 166.8 | 63.22 |
| [`std.threading.Lock.isClosed`](Type-std-threading-lock-164120817.md#method-method-std-threading-lock-isclosed-function-isclosed-std-threading-ml-1648794824) | `std/threading.ml:108` | 3 | 1 | 1 | 0 | 0 | 31.7 | 78.95 |
| [`std.threading.Lock.IsClosed`](Type-std-threading-lock-164120817.md#method-method-std-threading-lock-isclosed-function-isclosed-std-threading-ml-758314184) | `std/threading.ml:133` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.threading.Lock.new`](Type-std-threading-lock-164120817.md#static_method-static-method-std-threading-lock-new-static-function-new-std-threading-ml-2018063371) | `std/threading.ml:73` | 7 | 4 | 2 | 1 | 1 | 166.91 | 65.73 |
| [`std.threading.Lock.release`](Type-std-threading-lock-164120817.md#method-method-std-threading-lock-release-function-release-std-threading-ml-1801433858) | `std/threading.ml:102` | 4 | 3 | 2 | 1 | 1 | 83.76 | 73.13 |
| [`std.threading.Lock.Release`](Type-std-threading-lock-164120817.md#method-method-std-threading-lock-release-function-release-std-threading-ml-521757954) | `std/threading.ml:131` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.threading.Lock.TryAcquire`](Type-std-threading-lock-164120817.md#method-method-std-threading-lock-tryacquire-function-tryacquire-std-threading-ml-103662424) | `std/threading.ml:129` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.threading.Lock.tryAcquire`](Type-std-threading-lock-164120817.md#method-method-std-threading-lock-tryacquire-function-tryacquire-std-threading-ml-1996881112) | `std/threading.ml:97` | 3 | 1 | 1 | 0 | 0 | 43.19 | 78.01 |
| [`std.threading.Semaphore.acquire`](Type-std-threading-semaphore-750847000.md#method-method-std-threading-semaphore-acquire-function-acquire-std-threading-ml-1510023359) | `std/threading.ml:163` | 4 | 3 | 2 | 1 | 1 | 110.36 | 72.29 |
| [`std.threading.Semaphore.Acquire`](Type-std-threading-semaphore-750847000.md#method-method-std-threading-semaphore-acquire-function-acquire-std-threading-ml-704951551) | `std/threading.ml:213` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.threading.Semaphore.acquireFor`](Type-std-threading-semaphore-750847000.md#method-method-std-threading-semaphore-acquirefor-function-acquirefor-milliseconds-std-threading-ml-1568461297) | `std/threading.ml:170` | 6 | 3 | 5 | 4 | 1 | 199.69 | 66.25 |
| [`std.threading.Semaphore.AcquireFor`](Type-std-threading-semaphore-750847000.md#method-method-std-threading-semaphore-acquirefor-function-acquirefor-milliseconds-std-threading-ml-92650353) | `std/threading.ml:216` | 1 | 1 | 1 | 0 | 0 | 46.51 | 88.19 |
| [`std.threading.Semaphore.close`](Type-std-threading-semaphore-750847000.md#method-method-std-threading-semaphore-close-function-close-std-threading-ml-2091815591) | `std/threading.ml:202` | 9 | 7 | 3 | 2 | 1 | 166.8 | 63.22 |
| [`std.threading.Semaphore.isClosed`](Type-std-threading-semaphore-750847000.md#method-method-std-threading-semaphore-isclosed-function-isclosed-std-threading-ml-331623347) | `std/threading.ml:197` | 3 | 1 | 1 | 0 | 0 | 31.7 | 78.95 |
| [`std.threading.Semaphore.IsClosed`](Type-std-threading-semaphore-750847000.md#method-method-std-threading-semaphore-isclosed-function-isclosed-std-threading-ml-1130993587) | `std/threading.ml:225` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.threading.Semaphore.new`](Type-std-threading-semaphore-750847000.md#static_method-static-method-std-threading-semaphore-new-static-function-new-initialcount-maximumcount-std-threading-ml-1769797430) | `std/threading.ml:148` | 13 | 8 | 8 | 7 | 1 | 479.22 | 55.86 |
| [`std.threading.Semaphore.release`](Type-std-threading-semaphore-750847000.md#method-method-std-threading-semaphore-release-function-release-std-threading-ml-302421665) | `std/threading.ml:183` | 3 | 1 | 1 | 0 | 0 | 43.19 | 78.01 |
| [`std.threading.Semaphore.Release`](Type-std-threading-semaphore-750847000.md#method-method-std-threading-semaphore-release-function-release-std-threading-ml-291476961) | `std/threading.ml:220` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.threading.Semaphore.releaseMany`](Type-std-threading-semaphore-750847000.md#method-method-std-threading-semaphore-releasemany-function-releasemany-count-std-threading-ml-1703356314) | `std/threading.ml:189` | 6 | 3 | 5 | 4 | 1 | 204.33 | 66.18 |
| [`std.threading.Semaphore.ReleaseMany`](Type-std-threading-semaphore-750847000.md#method-method-std-threading-semaphore-releasemany-function-releasemany-count-std-threading-ml-1835952538) | `std/threading.ml:223` | 1 | 1 | 1 | 0 | 0 | 46.51 | 88.19 |
| [`std.threading.Semaphore.tryAcquire`](Type-std-threading-semaphore-750847000.md#method-method-std-threading-semaphore-tryacquire-function-tryacquire-std-threading-ml-2104513587) | `std/threading.ml:178` | 3 | 1 | 1 | 0 | 0 | 43.19 | 78.01 |
| [`std.threading.Semaphore.TryAcquire`](Type-std-threading-semaphore-750847000.md#method-method-std-threading-semaphore-tryacquire-function-tryacquire-std-threading-ml-599040883) | `std/threading.ml:218` | 1 | 1 | 1 | 0 | 0 | 38.04 | 88.8 |
| [`std.time.clock.addMillis`](File-std-time-ml-975894601.md#function-function-std-time-clock-addmillis-function-addmillis-t-delta-std-time-ml-1733200724) | `std/time.ml:738` | 15 | 10 | 4 | 3 | 1 | 372.92 | 55.8 |
| [`std.time.clock.compare`](File-std-time-ml-975894601.md#function-function-std-time-clock-compare-function-compare-a-b-std-time-ml-1662221955) | `std/time.ml:694` | 11 | 17 | 9 | 8 | 1 | 522.69 | 57.04 |
| [`std.time.clock.fromMillis`](File-std-time-ml-975894601.md#function-function-std-time-clock-frommillis-function-frommillis-ms-std-time-ml-576832168) | `std/time.ml:717` | 15 | 11 | 4 | 3 | 1 | 488.4 | 54.98 |
| [`std.time.clock.isValid`](File-std-time-ml-975894601.md#function-function-std-time-clock-isvalid-function-isvalid-t-std-time-ml-358966926) | `std/time.ml:687` | 3 | 1 | 1 | 0 | 0 | 130.8 | 74.64 |
| [`std.time.clock.isValidHMSM`](File-std-time-ml-975894601.md#function-function-std-time-clock-isvalidhmsm-function-isvalidhmsm-h-m-s0-ms-std-time-ml-348818806) | `std/time.ml:674` | 10 | 11 | 13 | 12 | 1 | 464.39 | 57.76 |
| [`std.time.clock.parse`](File-std-time-ml-975894601.md#function-function-std-time-clock-parse-function-parse-text-std-time-ml-549001107) | `std/time.ml:767` | 42 | 30 | 14 | 19 | 3 | 1884.3 | 39.77 |
| [`std.time.clock.toMillis`](File-std-time-ml-975894601.md#function-function-std-time-clock-tomillis-function-tomillis-t-std-time-ml-2034526210) | `std/time.ml:708` | 6 | 3 | 2 | 1 | 1 | 230.7 | 66.21 |
| [`std.time.clock.toString`](File-std-time-ml-975894601.md#function-function-std-time-clock-tostring-function-tostring-t-std-time-ml-68025454) | `std/time.ml:758` | 6 | 3 | 2 | 1 | 1 | 334.7 | 65.08 |
| [`std.time.clockToString`](File-std-time-ml-975894601.md#function-function-std-time-clocktostring-function-clocktostring-t-std-time-ml-904167438) | `std/time.ml:1086` | 3 | 1 | 1 | 0 | 0 | 64.53 | 76.79 |
| [`std.time.date.addDays`](File-std-time-ml-975894601.md#function-function-std-time-date-adddays-function-adddays-d-delta-std-time-ml-164994134) | `std/time.ml:593` | 10 | 6 | 3 | 2 | 1 | 260.06 | 60.87 |
| [`std.time.date.compare`](File-std-time-ml-975894601.md#function-function-std-time-date-compare-function-compare-a-b-std-time-ml-265951007) | `std/time.ml:580` | 9 | 13 | 7 | 6 | 1 | 397.62 | 60.04 |
| [`std.time.date.dayOfWeek`](File-std-time-ml-975894601.md#function-function-std-time-date-dayofweek-function-dayofweek-d-std-time-ml-1357661304) | `std/time.ml:618` | 7 | 4 | 2 | 1 | 1 | 180.94 | 65.49 |
| [`std.time.date.daysInMonth`](File-std-time-ml-975894601.md#function-function-std-time-date-daysinmonth-function-daysinmonth-year-month-std-time-ml-483008705) | `std/time.ml:445` | 23 | 29 | 17 | 17 | 2 | 824.52 | 47.59 |
| [`std.time.date.diffDays`](File-std-time-ml-975894601.md#function-function-std-time-date-diffdays-function-diffdays-a-b-std-time-ml-1684126225) | `std/time.ml:607` | 8 | 5 | 3 | 2 | 1 | 252.17 | 63.08 |
| [`std.time.date.fromOrdinal`](File-std-time-ml-975894601.md#function-function-std-time-date-fromordinal-function-fromordinal-days-std-time-ml-1450309647) | `std/time.ml:525` | 38 | 33 | 9 | 9 | 2 | 1362.41 | 42.38 |
| [`std.time.date.isLeapYear`](File-std-time-ml-975894601.md#function-function-std-time-date-isleapyear-function-isleapyear-year-std-time-ml-576789919) | `std/time.ml:429` | 12 | 7 | 4 | 3 | 1 | 229.06 | 59.4 |
| [`std.time.date.isValid`](File-std-time-ml-975894601.md#function-function-std-time-date-isvalid-function-isvalid-d-std-time-ml-398313186) | `std/time.ml:492` | 3 | 1 | 1 | 0 | 0 | 112 | 75.11 |
| [`std.time.date.isValidYMD`](File-std-time-ml-975894601.md#function-function-std-time-date-isvalidymd-function-isvalidymd-year-month-day-std-time-ml-1097498691) | `std/time.ml:474` | 13 | 8 | 7 | 6 | 1 | 423.73 | 56.36 |
| [`std.time.date.parse`](File-std-time-ml-975894601.md#function-function-std-time-date-parse-function-parse-text-std-time-ml-1488842447) | `std/time.ml:639` | 20 | 14 | 8 | 7 | 1 | 922.43 | 49.78 |
| [`std.time.date.toOrdinal`](File-std-time-ml-975894601.md#function-function-std-time-date-toordinal-function-toordinal-d-std-time-ml-2117441882) | `std/time.ml:498` | 17 | 13 | 4 | 3 | 1 | 874.74 | 52.02 |
| [`std.time.date.toString`](File-std-time-ml-975894601.md#function-function-std-time-date-tostring-function-tostring-d-std-time-ml-1073583202) | `std/time.ml:630` | 6 | 3 | 2 | 1 | 1 | 267.57 | 65.76 |
| [`std.time.datetime.addDays`](File-std-time-ml-975894601.md#function-function-std-time-datetime-adddays-function-adddays-dt-deltadays-std-time-ml-203304236) | `std/time.ml:893` | 13 | 8 | 4 | 3 | 1 | 357.23 | 57.29 |
| [`std.time.datetime.addMillis`](File-std-time-ml-975894601.md#function-function-std-time-datetime-addmillis-function-addmillis-dt-delta-std-time-ml-1561373415) | `std/time.ml:859` | 26 | 19 | 6 | 5 | 1 | 835.29 | 47.87 |
| [`std.time.datetime.compare`](File-std-time-ml-975894601.md#function-function-std-time-datetime-compare-function-compare-a-b-std-time-ml-1157888456) | `std/time.ml:830` | 7 | 4 | 2 | 1 | 1 | 229.06 | 64.77 |
| [`std.time.datetime.fromSystemTime`](File-std-time-ml-975894601.md#function-function-std-time-datetime-fromsystemtime-function-fromsystemtime-st-std-time-ml-1983396154) | `std/time.ml:952` | 25 | 19 | 10 | 9 | 1 | 922.47 | 47.4 |
| [`std.time.datetime.fromUnixMillis`](File-std-time-ml-975894601.md#function-function-std-time-datetime-fromunixmillis-function-fromunixmillis-unixms-std-time-ml-399158673) | `std/time.ml:1007` | 22 | 16 | 6 | 5 | 1 | 707.2 | 49.96 |
| [`std.time.datetime.isValid`](File-std-time-ml-975894601.md#function-function-std-time-datetime-isvalid-function-isvalid-dt-std-time-ml-101864515) | `std/time.ml:823` | 3 | 1 | 1 | 0 | 0 | 122.11 | 74.85 |
| [`std.time.datetime.nowLocal`](File-std-time-ml-975894601.md#function-function-std-time-datetime-nowlocal-function-nowlocal-std-time-ml-1503210091) | `std/time.ml:984` | 4 | 2 | 1 | 0 | 0 | 98.99 | 72.76 |
| [`std.time.datetime.nowUnixMillisUtc`](File-std-time-ml-975894601.md#function-function-std-time-datetime-nowunixmillisutc-function-nowunixmillisutc-std-time-ml-1128288483) | `std/time.ml:1034` | 7 | 4 | 2 | 1 | 1 | 165.67 | 65.76 |
| [`std.time.datetime.nowUtc`](File-std-time-ml-975894601.md#function-function-std-time-datetime-nowutc-function-nowutc-std-time-ml-120915363) | `std/time.ml:990` | 4 | 2 | 1 | 0 | 0 | 98.99 | 72.76 |
| [`std.time.datetime.parse`](File-std-time-ml-975894601.md#function-function-std-time-datetime-parse-function-parse-text-std-time-ml-1598500980) | `std/time.ml:918` | 23 | 16 | 7 | 6 | 1 | 883.18 | 48.73 |
| [`std.time.datetime.toMillis`](File-std-time-ml-975894601.md#function-function-std-time-datetime-tomillis-function-tomillis-dt-std-time-ml-874033111) | `std/time.ml:840` | 12 | 8 | 4 | 3 | 1 | 388.64 | 57.79 |
| [`std.time.datetime.toString`](File-std-time-ml-975894601.md#function-function-std-time-datetime-tostring-function-tostring-dt-std-time-ml-1324149955) | `std/time.ml:909` | 6 | 3 | 2 | 1 | 1 | 216.64 | 66.4 |
| [`std.time.datetime.toUnixMillis`](File-std-time-ml-975894601.md#function-function-std-time-datetime-tounixmillis-function-tounixmillis-dt-std-time-ml-894528563) | `std/time.ml:997` | 7 | 4 | 2 | 1 | 1 | 189.99 | 65.34 |
| [`std.time.datetimeToString`](File-std-time-ml-975894601.md#function-function-std-time-datetimetostring-function-datetimetostring-dt-std-time-ml-1282710884) | `std/time.ml:1092` | 3 | 1 | 1 | 0 | 0 | 64.53 | 76.79 |
| [`std.time.dateToString`](File-std-time-ml-975894601.md#function-function-std-time-datetostring-function-datetostring-d-std-time-ml-1682286890) | `std/time.ml:1080` | 3 | 1 | 1 | 0 | 0 | 64.53 | 76.79 |
| [`std.time.elapsed`](File-std-time-ml-975894601.md#function-function-std-time-elapsed-function-elapsed-start-time-end-time-std-time-ml-1524773121) | `std/time.ml:323` | 9 | 5 | 4 | 3 | 1 | 159.41 | 63.22 |
| [`std.time.formatDuration`](File-std-time-ml-975894601.md#function-function-std-time-formatduration-function-formatduration-ms-std-time-ml-951102696) | `std/time.ml:1045` | 27 | 20 | 6 | 5 | 1 | 1023.29 | 46.89 |
| [`std.time.sleep`](File-std-time-ml-975894601.md#function-function-std-time-sleep-function-sleep-ms-std-time-ml-2137114338) | `std/time.ml:295` | 9 | 5 | 4 | 3 | 1 | 178.38 | 62.88 |
| [`std.time.ticks`](File-std-time-ml-975894601.md#function-function-std-time-ticks-function-ticks-std-time-ml-23716212) | `std/time.ml:288` | 3 | 1 | 1 | 0 | 0 | 46.51 | 77.78 |
| [`std.time.win32.GetLocalTime`](File-std-time-ml-975894601.md#function-function-std-time-win32-getlocaltime-function-getlocaltime-std-time-ml-2017549839) | `std/time.ml:145` | 5 | 3 | 1 | 0 | 0 | 113.3 | 70.23 |
| [`std.time.win32.GetSystemTime`](File-std-time-ml-975894601.md#function-function-std-time-win32-getsystemtime-function-getsystemtime-std-time-ml-1514521483) | `std/time.ml:152` | 5 | 3 | 1 | 0 | 0 | 113.3 | 70.23 |
| [`std.tls.accept`](File-std-tls-ml-2076630303.md#function-function-std-tls-accept-function-accept-socket-options-std-tls-ml-800200611) | `std/tls.ml:192` | 3 | 1 | 1 | 0 | 0 | 69.19 | 76.57 |
| [`std.tls.acceptServer`](File-std-tls-ml-2076630303.md#function-function-std-tls-acceptserver-function-acceptserver-activeprovider-socket-options-std-tls-ml-616544682) | `std/tls.ml:173` | 8 | 9 | 4 | 3 | 1 | 364.35 | 61.83 |
| [`std.tls.clientOptions`](File-std-tls-ml-2076630303.md#function-function-std-tls-clientoptions-function-clientoptions-servername-std-tls-ml-739294414) | `std/tls.ml:87` | 3 | 1 | 1 | 0 | 0 | 71.7 | 76.47 |
| [`std.tls.close`](File-std-tls-ml-2076630303.md#function-function-std-tls-close-function-close-stream-std-tls-ml-845826000) | `std/tls.ml:241` | 8 | 9 | 4 | 3 | 1 | 278.63 | 62.64 |
| [`std.tls.connect`](File-std-tls-ml-2076630303.md#function-function-std-tls-connect-function-connect-socket-options-std-tls-ml-1752825555) | `std/tls.ml:185` | 3 | 1 | 1 | 0 | 0 | 69.19 | 76.57 |
| [`std.tls.connectClient`](File-std-tls-ml-2076630303.md#function-function-std-tls-connectclient-function-connectclient-activeprovider-socket-options-std-tls-ml-1045079724) | `std/tls.ml:160` | 8 | 9 | 4 | 3 | 1 | 360.55 | 61.86 |
| [`std.tls.isStream`](File-std-tls-ml-2076630303.md#function-function-std-tls-isstream-function-isstream-value-std-tls-ml-1952310795) | `std/tls.ml:198` | 3 | 1 | 1 | 0 | 0 | 34.87 | 78.66 |
| [`std.tls.nativeProvider`](File-std-tls-ml-2076630303.md#function-function-std-tls-nativeprovider-function-nativeprovider-std-tls-ml-1730938456) | `std/tls.ml:147` | 3 | 1 | 1 | 0 | 0 | 159.41 | 74.04 |
| [`std.tls.nativeProviderName`](File-std-tls-ml-2076630303.md#function-function-std-tls-nativeprovidername-function-nativeprovidername-std-tls-ml-1534691896) | `std/tls.ml:152` | 3 | 1 | 1 | 0 | 0 | 38.04 | 78.39 |
| [`std.tls.pinnedClientOptions`](File-std-tls-ml-2076630303.md#function-function-std-tls-pinnedclientoptions-function-pinnedclientoptions-servername-sha256pin-std-tls-ml-1120473458) | `std/tls.ml:94` | 3 | 1 | 1 | 0 | 0 | 81.41 | 76.08 |
| [`std.tls.provider`](File-std-tls-ml-2076630303.md#function-function-std-tls-provider-function-provider-name-openclient-openserver-sendbytes-receivebytes-shutdownstream-closestream-std-tls-ml-1543267410) | `std/tls.ml:137` | 8 | 7 | 5 | 5 | 2 | 491.14 | 60.78 |
| [`std.tls.receive`](File-std-tls-ml-2076630303.md#function-function-std-tls-receive-function-receive-stream-maximumbytes-std-tls-ml-1474410327) | `std/tls.ml:223` | 8 | 10 | 8 | 7 | 1 | 510.53 | 60.26 |
| [`std.tls.sendAll`](File-std-tls-ml-2076630303.md#function-function-std-tls-sendall-function-sendall-stream-data-std-tls-ml-334269506) | `std/tls.ml:205` | 14 | 13 | 9 | 10 | 2 | 699.99 | 53.87 |
| [`std.tls.serverOptions`](File-std-tls-ml-2076630303.md#function-function-std-tls-serveroptions-function-serveroptions-certificatereference-privatekeyreference-std-tls-ml-1841010559) | `std/tls.ml:101` | 3 | 1 | 1 | 0 | 0 | 71.7 | 76.47 |
| [`std.tls.shutdown`](File-std-tls-ml-2076630303.md#function-function-std-tls-shutdown-function-shutdown-stream-std-tls-ml-1878438672) | `std/tls.ml:234` | 4 | 3 | 3 | 2 | 1 | 135.93 | 71.53 |
| [`std.tls.validateClientOptions`](File-std-tls-ml-2076630303.md#function-function-std-tls-validateclientoptions-function-validateclientoptions-options-std-tls-ml-702450042) | `std/tls.ml:107` | 10 | 15 | 14 | 13 | 1 | 910.78 | 55.58 |
| [`std.tls.validateServerOptions`](File-std-tls-ml-2076630303.md#function-function-std-tls-validateserveroptions-function-validateserveroptions-options-std-tls-ml-787870250) | `std/tls.ml:120` | 8 | 11 | 9 | 8 | 1 | 573.86 | 59.77 |
| [`std.uuid.format`](File-std-uuid-ml-1903850359.md#function-function-std-uuid-format-function-format-raw-std-uuid-ml-2051708080) | `std/uuid.ml:27` | 5 | 4 | 3 | 2 | 1 | 500 | 65.45 |
| [`std.uuid.isValid`](File-std-uuid-ml-1903850359.md#function-function-std-uuid-isvalid-function-isvalid-text-std-uuid-ml-2002706769) | `std/uuid.ml:64` | 3 | 1 | 1 | 0 | 0 | 58.81 | 77.07 |
| [`std.uuid.parse`](File-std-uuid-ml-1903850359.md#function-function-std-uuid-parse-function-parse-text-std-uuid-ml-99981495) | `std/uuid.ml:53` | 8 | 9 | 9 | 8 | 1 | 966.32 | 58.19 |
| [`std.uuid.v4`](File-std-uuid-ml-1903850359.md#function-function-std-uuid-v4-function-v4-std-uuid-ml-1680180020) | `std/uuid.ml:43` | 7 | 6 | 2 | 1 | 1 | 157.17 | 65.92 |
| [`std.uuid.v4Bytes`](File-std-uuid-ml-1903850359.md#function-function-std-uuid-v4bytes-function-v4bytes-std-uuid-ml-166922686) | `std/uuid.ml:34` | 7 | 6 | 2 | 1 | 1 | 275.78 | 64.21 |

## Code duplication

A clone group is an exact sequence of 6 normalized, contiguous code lines found more than once. Comments and formatting whitespace are ignored. Duplicated-line totals count overlapping windows only once.

Found 163 clone group(s). At most 163 groups are shown.

<details>
<summary>Clone 1 — 3 occurrences</summary>

    value = buffer [ offset + 7 ]
    if value >= 128 then value = value - 256 end if
    i = 6
    while i >= 0
    value = ( value << 8 ) | buffer [ offset + i ]
    i = i - 1

- [`std/_linux_fs.ml:122`](File-std-linux-fs-ml-2121665983.md)
- [`std/concurrent/shared_value.ml:106`](File-std-concurrent-shared-value-ml-2112657235.md)
- [`std/io/file.ml:59`](File-std-io-file-ml-2074692665.md)

</details>

<details>
<summary>Clone 2 — 3 occurrences</summary>

    if value >= 128 then value = value - 256 end if
    i = 6
    while i >= 0
    value = ( value << 8 ) | buffer [ offset + i ]
    i = i - 1
    end while

- [`std/_linux_fs.ml:123`](File-std-linux-fs-ml-2121665983.md)
- [`std/concurrent/shared_value.ml:107`](File-std-concurrent-shared-value-ml-2112657235.md)
- [`std/io/file.ml:60`](File-std-io-file-ml-2074692665.md)

</details>

<details>
<summary>Clone 3 — 3 occurrences</summary>

    i = 6
    while i >= 0
    value = ( value << 8 ) | buffer [ offset + i ]
    i = i - 1
    end while
    return value

- [`std/_linux_fs.ml:124`](File-std-linux-fs-ml-2121665983.md)
- [`std/concurrent/shared_value.ml:108`](File-std-concurrent-shared-value-ml-2112657235.md)
- [`std/io/file.ml:61`](File-std-io-file-ml-2074692665.md)

</details>

<details>
<summary>Clone 4 — 3 occurrences</summary>

    while i >= 0
    value = ( value << 8 ) | buffer [ offset + i ]
    i = i - 1
    end while
    return value
    end function

- [`std/_linux_fs.ml:125`](File-std-linux-fs-ml-2121665983.md)
- [`std/concurrent/shared_value.ml:109`](File-std-concurrent-shared-value-ml-2112657235.md)
- [`std/io/file.ml:62`](File-std-io-file-ml-2074692665.md)

</details>

<details>
<summary>Clone 5 — 2 occurrences</summary>

    i0 = start
    if i0 < 0 then
    i0 = 0
    end if
    if i0 > n then
    i0 = n

- [`std/array.ml:113`](File-std-array-ml-1258125823.md)
- [`std/bytes.ml:260`](File-std-bytes-ml-1351945333.md)

</details>

<details>
<summary>Clone 6 — 4 occurrences</summary>

    if i0 < 0 then
    i0 = 0
    end if
    if i0 > n then
    i0 = n
    end if

- [`std/array.ml:114`](File-std-array-ml-1258125823.md)
- [`std/bytes.ml:261`](File-std-bytes-ml-1351945333.md)
- [`std/string.ml:139`](File-std-string-ml-1276545685.md)
- [`std/string.ml:92`](File-std-string-ml-1276545685.md)

</details>

<details>
<summary>Clone 7 — 2 occurrences</summary>

    if typeof ( a ) != "array" then
    return false
    end if
    if typeof ( pred ) != "function" then
    return false
    end if

- [`std/array.ml:245`](File-std-array-ml-1258125823.md)
- [`std/array.ml:265`](File-std-array-ml-1258125823.md)

</details>

<details>
<summary>Clone 8 — 3 occurrences</summary>

    return
    end if
    if typeof ( offset ) != "int" then
    return
    end if
    if typeof ( length ) != "int" then

- [`std/array.ml:60`](File-std-array-ml-1258125823.md)
- [`std/bytes.ml:80`](File-std-bytes-ml-1351945333.md)
- [`std/string_builder.ml:121`](File-std-string-builder-ml-412876577.md)

</details>

<details>
<summary>Clone 9 — 3 occurrences</summary>

    end if
    if typeof ( offset ) != "int" then
    return
    end if
    if typeof ( length ) != "int" then
    return

- [`std/array.ml:61`](File-std-array-ml-1258125823.md)
- [`std/bytes.ml:81`](File-std-bytes-ml-1351945333.md)
- [`std/string_builder.ml:122`](File-std-string-builder-ml-412876577.md)

</details>

<details>
<summary>Clone 10 — 3 occurrences</summary>

    if typeof ( offset ) != "int" then
    return
    end if
    if typeof ( length ) != "int" then
    return
    end if

- [`std/array.ml:62`](File-std-array-ml-1258125823.md)
- [`std/bytes.ml:82`](File-std-bytes-ml-1351945333.md)
- [`std/string_builder.ml:123`](File-std-string-builder-ml-412876577.md)

</details>

<details>
<summary>Clone 11 — 4 occurrences</summary>

    if typeof ( a ) != "bytes" then
    return
    end if
    if typeof ( b ) != "bytes" then
    return
    end if

- [`std/bytes.ml:134`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:330`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:660`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:685`](File-std-bytes-ml-1351945333.md)

</details>

<details>
<summary>Clone 12 — 2 occurrences</summary>

    if typeof ( a ) != "bytes" then
    return false
    end if
    if typeof ( b ) != "bytes" then
    return false
    end if

- [`std/bytes.ml:147`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:167`](File-std-bytes-ml-1351945333.md)

</details>

<details>
<summary>Clone 13 — 3 occurrences</summary>

    if typeof ( hay ) != "bytes" then
    return
    end if
    if typeof ( needle ) != "bytes" then
    return
    end if

- [`std/bytes.ml:247`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:301`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:317`](File-std-bytes-ml-1351945333.md)

</details>

<details>
<summary>Clone 14 — 2 occurrences</summary>

    return
    end if
    if typeof ( needle ) != "bytes" then
    return
    end if
    if typeof ( start ) != "int" then

- [`std/bytes.ml:248`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:302`](File-std-bytes-ml-1351945333.md)

</details>

<details>
<summary>Clone 15 — 2 occurrences</summary>

    end if
    if typeof ( needle ) != "bytes" then
    return
    end if
    if typeof ( start ) != "int" then
    return

- [`std/bytes.ml:249`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:303`](File-std-bytes-ml-1351945333.md)

</details>

<details>
<summary>Clone 16 — 2 occurrences</summary>

    if typeof ( needle ) != "bytes" then
    return
    end if
    if typeof ( start ) != "int" then
    return
    end if

- [`std/bytes.ml:250`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:304`](File-std-bytes-ml-1351945333.md)

</details>

<details>
<summary>Clone 17 — 3 occurrences</summary>

    if m == 0 then
    return i0
    end if
    if m > n then
    return - 1
    end if

- [`std/bytes.ml:268`](File-std-bytes-ml-1351945333.md)
- [`std/string.ml:146`](File-std-string-ml-1276545685.md)
- [`std/string.ml:99`](File-std-string-ml-1276545685.md)

</details>

<details>
<summary>Clone 18 — 5 occurrences</summary>

    if not _bytes_ok ( b ) then
    return false
    end if
    if not _int_ok ( off ) then
    return false
    end if

- [`std/bytes.ml:431`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:473`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:499`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:563`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:591`](File-std-bytes-ml-1351945333.md)

</details>

<details>
<summary>Clone 19 — 5 occurrences</summary>

    return false
    end if
    if not _int_ok ( off ) then
    return false
    end if
    if not _int_ok ( value ) then

- [`std/bytes.ml:432`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:474`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:500`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:564`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:592`](File-std-bytes-ml-1351945333.md)

</details>

<details>
<summary>Clone 20 — 5 occurrences</summary>

    end if
    if not _int_ok ( off ) then
    return false
    end if
    if not _int_ok ( value ) then
    return false

- [`std/bytes.ml:433`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:475`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:501`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:565`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:593`](File-std-bytes-ml-1351945333.md)

</details>

<details>
<summary>Clone 21 — 5 occurrences</summary>

    if not _int_ok ( off ) then
    return false
    end if
    if not _int_ok ( value ) then
    return false
    end if

- [`std/bytes.ml:434`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:476`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:502`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:566`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:594`](File-std-bytes-ml-1351945333.md)

</details>

<details>
<summary>Clone 22 — 5 occurrences</summary>

    if not _bytes_ok ( b ) then
    return
    end if
    if not _int_ok ( off ) then
    return
    end if

- [`std/bytes.ml:455`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:524`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:543`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:618`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:639`](File-std-bytes-ml-1351945333.md)

</details>

<details>
<summary>Clone 23 — 5 occurrences</summary>

    return
    end if
    if not _int_ok ( off ) then
    return
    end if
    n = len ( b )

- [`std/bytes.ml:456`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:525`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:544`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:619`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:640`](File-std-bytes-ml-1351945333.md)

</details>

<details>
<summary>Clone 24 — 2 occurrences</summary>

    return false
    end if
    if not _int_ok ( value ) then
    return false
    end if
    if value < 0 or value > 0xFFFF then

- [`std/bytes.ml:477`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:503`](File-std-bytes-ml-1351945333.md)

</details>

<details>
<summary>Clone 25 — 2 occurrences</summary>

    end if
    if not _int_ok ( value ) then
    return false
    end if
    if value < 0 or value > 0xFFFF then
    return false

- [`std/bytes.ml:478`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:504`](File-std-bytes-ml-1351945333.md)

</details>

<details>
<summary>Clone 26 — 2 occurrences</summary>

    if not _int_ok ( value ) then
    return false
    end if
    if value < 0 or value > 0xFFFF then
    return false
    end if

- [`std/bytes.ml:479`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:505`](File-std-bytes-ml-1351945333.md)

</details>

<details>
<summary>Clone 27 — 2 occurrences</summary>

    return false
    end if
    if value < 0 or value > 0xFFFF then
    return false
    end if
    n = len ( b )

- [`std/bytes.ml:480`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:506`](File-std-bytes-ml-1351945333.md)

</details>

<details>
<summary>Clone 28 — 2 occurrences</summary>

    end if
    if value < 0 or value > 0xFFFF then
    return false
    end if
    n = len ( b )
    if not _check_range ( off , 2 , n ) then

- [`std/bytes.ml:481`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:507`](File-std-bytes-ml-1351945333.md)

</details>

<details>
<summary>Clone 29 — 2 occurrences</summary>

    if value < 0 or value > 0xFFFF then
    return false
    end if
    n = len ( b )
    if not _check_range ( off , 2 , n ) then
    return false

- [`std/bytes.ml:482`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:508`](File-std-bytes-ml-1351945333.md)

</details>

<details>
<summary>Clone 30 — 2 occurrences</summary>

    return false
    end if
    n = len ( b )
    if not _check_range ( off , 2 , n ) then
    return false
    end if

- [`std/bytes.ml:483`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:509`](File-std-bytes-ml-1351945333.md)

</details>

<details>
<summary>Clone 31 — 2 occurrences</summary>

    end if
    if not _int_ok ( off ) then
    return
    end if
    n = len ( b )
    if not _check_range ( off , 2 , n ) then

- [`std/bytes.ml:526`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:545`](File-std-bytes-ml-1351945333.md)

</details>

<details>
<summary>Clone 32 — 2 occurrences</summary>

    if not _int_ok ( off ) then
    return
    end if
    n = len ( b )
    if not _check_range ( off , 2 , n ) then
    return

- [`std/bytes.ml:527`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:546`](File-std-bytes-ml-1351945333.md)

</details>

<details>
<summary>Clone 33 — 2 occurrences</summary>

    return
    end if
    n = len ( b )
    if not _check_range ( off , 2 , n ) then
    return
    end if

- [`std/bytes.ml:528`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:547`](File-std-bytes-ml-1351945333.md)

</details>

<details>
<summary>Clone 34 — 2 occurrences</summary>

    return false
    end if
    if not _int_ok ( value ) then
    return false
    end if
    if value < 0 or value > 0xFFFFFFFF then

- [`std/bytes.ml:567`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:595`](File-std-bytes-ml-1351945333.md)

</details>

<details>
<summary>Clone 35 — 2 occurrences</summary>

    end if
    if not _int_ok ( value ) then
    return false
    end if
    if value < 0 or value > 0xFFFFFFFF then
    return false

- [`std/bytes.ml:568`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:596`](File-std-bytes-ml-1351945333.md)

</details>

<details>
<summary>Clone 36 — 2 occurrences</summary>

    if not _int_ok ( value ) then
    return false
    end if
    if value < 0 or value > 0xFFFFFFFF then
    return false
    end if

- [`std/bytes.ml:569`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:597`](File-std-bytes-ml-1351945333.md)

</details>

<details>
<summary>Clone 37 — 2 occurrences</summary>

    return false
    end if
    if value < 0 or value > 0xFFFFFFFF then
    return false
    end if
    n = len ( b )

- [`std/bytes.ml:570`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:598`](File-std-bytes-ml-1351945333.md)

</details>

<details>
<summary>Clone 38 — 2 occurrences</summary>

    end if
    if value < 0 or value > 0xFFFFFFFF then
    return false
    end if
    n = len ( b )
    if not _check_range ( off , 4 , n ) then

- [`std/bytes.ml:571`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:599`](File-std-bytes-ml-1351945333.md)

</details>

<details>
<summary>Clone 39 — 2 occurrences</summary>

    if value < 0 or value > 0xFFFFFFFF then
    return false
    end if
    n = len ( b )
    if not _check_range ( off , 4 , n ) then
    return false

- [`std/bytes.ml:572`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:600`](File-std-bytes-ml-1351945333.md)

</details>

<details>
<summary>Clone 40 — 2 occurrences</summary>

    return false
    end if
    n = len ( b )
    if not _check_range ( off , 4 , n ) then
    return false
    end if

- [`std/bytes.ml:573`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:601`](File-std-bytes-ml-1351945333.md)

</details>

<details>
<summary>Clone 41 — 2 occurrences</summary>

    end if
    if not _int_ok ( off ) then
    return
    end if
    n = len ( b )
    if not _check_range ( off , 4 , n ) then

- [`std/bytes.ml:620`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:641`](File-std-bytes-ml-1351945333.md)

</details>

<details>
<summary>Clone 42 — 2 occurrences</summary>

    if not _int_ok ( off ) then
    return
    end if
    n = len ( b )
    if not _check_range ( off , 4 , n ) then
    return

- [`std/bytes.ml:621`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:642`](File-std-bytes-ml-1351945333.md)

</details>

<details>
<summary>Clone 43 — 2 occurrences</summary>

    return
    end if
    n = len ( b )
    if not _check_range ( off , 4 , n ) then
    return
    end if

- [`std/bytes.ml:622`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:643`](File-std-bytes-ml-1351945333.md)

</details>

<details>
<summary>Clone 44 — 2 occurrences</summary>

    end if
    n = len ( b )
    if not _check_range ( off , 4 , n ) then
    return
    end if
    b0 = b [ off ] & 0xFF

- [`std/bytes.ml:623`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:644`](File-std-bytes-ml-1351945333.md)

</details>

<details>
<summary>Clone 45 — 2 occurrences</summary>

    n = len ( b )
    if not _check_range ( off , 4 , n ) then
    return
    end if
    b0 = b [ off ] & 0xFF
    b1 = b [ off + 1 ] & 0xFF

- [`std/bytes.ml:624`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:645`](File-std-bytes-ml-1351945333.md)

</details>

<details>
<summary>Clone 46 — 2 occurrences</summary>

    if not _check_range ( off , 4 , n ) then
    return
    end if
    b0 = b [ off ] & 0xFF
    b1 = b [ off + 1 ] & 0xFF
    b2 = b [ off + 2 ] & 0xFF

- [`std/bytes.ml:625`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:646`](File-std-bytes-ml-1351945333.md)

</details>

<details>
<summary>Clone 47 — 2 occurrences</summary>

    return
    end if
    b0 = b [ off ] & 0xFF
    b1 = b [ off + 1 ] & 0xFF
    b2 = b [ off + 2 ] & 0xFF
    b3 = b [ off + 3 ] & 0xFF

- [`std/bytes.ml:626`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:647`](File-std-bytes-ml-1351945333.md)

</details>

<details>
<summary>Clone 48 — 2 occurrences</summary>

    return
    end if
    if typeof ( b ) != "bytes" then
    return
    end if
    if len ( a ) != len ( b ) then

- [`std/bytes.ml:661`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:686`](File-std-bytes-ml-1351945333.md)

</details>

<details>
<summary>Clone 49 — 2 occurrences</summary>

    end if
    if typeof ( b ) != "bytes" then
    return
    end if
    if len ( a ) != len ( b ) then
    return

- [`std/bytes.ml:662`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:687`](File-std-bytes-ml-1351945333.md)

</details>

<details>
<summary>Clone 50 — 2 occurrences</summary>

    if typeof ( b ) != "bytes" then
    return
    end if
    if len ( a ) != len ( b ) then
    return
    end if

- [`std/bytes.ml:663`](File-std-bytes-ml-1351945333.md)
- [`std/bytes.ml:688`](File-std-bytes-ml-1351945333.md)

</details>

<details>
<summary>Clone 51 — 2 occurrences</summary>

    i = 0
    while i < 8
    buffer [ offset + i ] = ( value >> ( i * 8 ) ) & 0xFF
    i = i + 1
    end while
    end function

- [`std/concurrent/shared_value.ml:94`](File-std-concurrent-shared-value-ml-2112657235.md)
- [`std/net.ml:396`](File-std-net-ml-1989130045.md)

</details>

<details>
<summary>Clone 52 — 2 occurrences</summary>

    this . callback = void
    this . data = void
    this . guard . release ( )
    this . done . set ( )
    return true
    end function

- [`std/concurrent/thread_pool.ml:112`](File-std-concurrent-thread-pool-ml-72857761.md)
- [`std/concurrent/thread_pool.ml:97`](File-std-concurrent-thread-pool-ml-72857761.md)

</details>

<details>
<summary>Clone 53 — 2 occurrences</summary>

    if not this . guard . acquire ( ) then return false end if
    if this . closed or this . stopping then
    this . guard . release ( )
    return false
    end if
    this . accepting = false

- [`std/concurrent/thread_pool.ml:405`](File-std-concurrent-thread-pool-ml-72857761.md)
- [`std/concurrent/thread_pool.ml:419`](File-std-concurrent-thread-pool-ml-72857761.md)

</details>

<details>
<summary>Clone 54 — 2 occurrences</summary>

    if this . closed or this . stopping then
    this . guard . release ( )
    return false
    end if
    this . accepting = false
    this . stopping = true

- [`std/concurrent/thread_pool.ml:406`](File-std-concurrent-thread-pool-ml-72857761.md)
- [`std/concurrent/thread_pool.ml:420`](File-std-concurrent-thread-pool-ml-72857761.md)

</details>

<details>
<summary>Clone 55 — 2 occurrences</summary>

    i = i + 1
    end while
    if not this . guard . acquire ( ) then return false end if
    this . stopped = true
    this . guard . release ( )
    return true

- [`std/concurrent/thread_pool.ml:449`](File-std-concurrent-thread-pool-ml-72857761.md)
- [`std/concurrent/thread_pool.ml:465`](File-std-concurrent-thread-pool-ml-72857761.md)

</details>

<details>
<summary>Clone 56 — 2 occurrences</summary>

    end while
    if not this . guard . acquire ( ) then return false end if
    this . stopped = true
    this . guard . release ( )
    return true
    end function

- [`std/concurrent/thread_pool.ml:450`](File-std-concurrent-thread-pool-ml-72857761.md)
- [`std/concurrent/thread_pool.ml:466`](File-std-concurrent-thread-pool-ml-72857761.md)

</details>

<details>
<summary>Clone 57 — 2 occurrences</summary>

    function max ( a , b )
    if a > b then
    return a
    end if
    return b
    end function

- [`std/core.ml:102`](File-std-core-ml-750389783.md)
- [`std/math.ml:84`](File-std-math-ml-790065500.md)

</details>

<details>
<summary>Clone 58 — 2 occurrences</summary>

    function clamp ( x , lo , hi )
    if x < lo then
    return lo
    end if
    if x > hi then
    return hi

- [`std/core.ml:113`](File-std-core-ml-750389783.md)
- [`std/math.ml:61`](File-std-math-ml-790065500.md)

</details>

<details>
<summary>Clone 59 — 2 occurrences</summary>

    if x < lo then
    return lo
    end if
    if x > hi then
    return hi
    end if

- [`std/core.ml:114`](File-std-core-ml-750389783.md)
- [`std/math.ml:62`](File-std-math-ml-790065500.md)

</details>

<details>
<summary>Clone 60 — 2 occurrences</summary>

    return lo
    end if
    if x > hi then
    return hi
    end if
    return x

- [`std/core.ml:115`](File-std-core-ml-750389783.md)
- [`std/math.ml:63`](File-std-math-ml-790065500.md)

</details>

<details>
<summary>Clone 61 — 2 occurrences</summary>

    end if
    if x > hi then
    return hi
    end if
    return x
    end function

- [`std/core.ml:116`](File-std-core-ml-750389783.md)
- [`std/math.ml:64`](File-std-math-ml-790065500.md)

</details>

<details>
<summary>Clone 62 — 2 occurrences</summary>

    if x < 0 then
    return - 1
    end if
    if x > 0 then
    return 1
    end if

- [`std/core.ml:135`](File-std-core-ml-750389783.md)
- [`std/math.ml:48`](File-std-math-ml-790065500.md)

</details>

<details>
<summary>Clone 63 — 2 occurrences</summary>

    return - 1
    end if
    if x > 0 then
    return 1
    end if
    return 0

- [`std/core.ml:136`](File-std-core-ml-750389783.md)
- [`std/math.ml:49`](File-std-math-ml-790065500.md)

</details>

<details>
<summary>Clone 64 — 2 occurrences</summary>

    end if
    if x > 0 then
    return 1
    end if
    return 0
    end function

- [`std/core.ml:137`](File-std-core-ml-750389783.md)
- [`std/math.ml:50`](File-std-math-ml-790065500.md)

</details>

<details>
<summary>Clone 65 — 2 occurrences</summary>

    function min ( a , b )
    if a < b then
    return a
    end if
    return b
    end function

- [`std/core.ml:92`](File-std-core-ml-750389783.md)
- [`std/math.ml:74`](File-std-math-ml-790065500.md)

</details>

<details>
<summary>Clone 66 — 2 occurrences</summary>

    function _putU32 ( buffer , offset , value )
    buffer [ offset ] = value & 0xFF
    buffer [ offset + 1 ] = ( value >> 8 ) & 0xFF
    buffer [ offset + 2 ] = ( value >> 16 ) & 0xFF
    buffer [ offset + 3 ] = ( value >> 24 ) & 0xFF
    end function

- [`std/crypto/_cng.ml:102`](File-std-crypto-cng-ml-1099901917.md)
- [`std/net.ml:386`](File-std-net-ml-1989130045.md)

</details>

<details>
<summary>Clone 67 — 2 occurrences</summary>

    ok = status == 0
    end if
    if provider != 0 then BCryptCloseAlgorithmProvider ( provider , 0 ) end if
    _zero ( providerBytes )
    if not ok then _zero ( output ) end if
    return ok

- [`std/crypto/_cng.ml:151`](File-std-crypto-cng-ml-1099901917.md)
- [`std/crypto/_cng.ml:177`](File-std-crypto-cng-ml-1099901917.md)

</details>

<details>
<summary>Clone 68 — 2 occurrences</summary>

    end if
    if provider != 0 then BCryptCloseAlgorithmProvider ( provider , 0 ) end if
    _zero ( providerBytes )
    if not ok then _zero ( output ) end if
    return ok
    end function

- [`std/crypto/_cng.ml:152`](File-std-crypto-cng-ml-1099901917.md)
- [`std/crypto/_cng.ml:178`](File-std-crypto-cng-ml-1099901917.md)

</details>

<details>
<summary>Clone 69 — 2 occurrences</summary>

    ok = provider != 0
    if ok then
    status = BCryptImportKeyPair ( provider , 0 , "ECCPRIVATEBLOB" , privateHandleBytes , nativeBytesPtr ( privateBlob ) , len ( privateBlob ) , 0 )
    privateHandle = _getPtr ( privateHandleBytes )
    ok = status == 0 and privateHandle != 0
    end if

- [`std/crypto/_cng.ml:346`](File-std-crypto-cng-ml-1099901917.md)
- [`std/crypto/_cng.ml:382`](File-std-crypto-cng-ml-1099901917.md)

</details>

<details>
<summary>Clone 70 — 2 occurrences</summary>

    if ok then
    status = BCryptImportKeyPair ( provider , 0 , "ECCPRIVATEBLOB" , privateHandleBytes , nativeBytesPtr ( privateBlob ) , len ( privateBlob ) , 0 )
    privateHandle = _getPtr ( privateHandleBytes )
    ok = status == 0 and privateHandle != 0
    end if
    if ok then

- [`std/crypto/_cng.ml:347`](File-std-crypto-cng-ml-1099901917.md)
- [`std/crypto/_cng.ml:383`](File-std-crypto-cng-ml-1099901917.md)

</details>

<details>
<summary>Clone 71 — 2 occurrences</summary>

    _zero ( resultLength )
    _zero ( privateBlob )
    _zero ( publicBlob )
    if not ok then _zero ( output ) end if
    return ok
    end function

- [`std/crypto/_cng.ml:361`](File-std-crypto-cng-ml-1099901917.md)
- [`std/crypto/_cng.ml:422`](File-std-crypto-cng-ml-1099901917.md)

</details>

<details>
<summary>Clone 72 — 2 occurrences</summary>

    if not this . guard . acquire ( ) then return 0 end if
    result = 0
    if not this . closed then result = this . size end if
    this . guard . release ( )
    return result
    end function

- [`std/ds/concurrent_hashmap.ml:148`](File-std-ds-concurrent-hashmap-ml-1798836270.md)
- [`std/ds/concurrent_list.ml:94`](File-std-ds-concurrent-list-ml-291130726.md)

</details>

<details>
<summary>Clone 73 — 2 occurrences</summary>

    if this . closed then
    this . guard . release ( )
    return
    end if
    index = _findSlot ( this . keys , this . states , this . bucketCount , key , false )
    if index < 0 then

- [`std/ds/concurrent_hashmap.ml:213`](File-std-ds-concurrent-hashmap-ml-1798836270.md)
- [`std/ds/concurrent_hashmap.ml:252`](File-std-ds-concurrent-hashmap-ml-1798836270.md)

</details>

<details>
<summary>Clone 74 — 2 occurrences</summary>

    function clear ( )
    if not this . guard . acquire ( ) then return false end if
    if this . closed then
    this . guard . release ( )
    return false
    end if

- [`std/ds/concurrent_hashmap.ml:308`](File-std-ds-concurrent-hashmap-ml-1798836270.md)
- [`std/ds/concurrent_list.ml:281`](File-std-ds-concurrent-list-ml-291130726.md)

</details>

<details>
<summary>Clone 75 — 4 occurrences</summary>

    if not this . guard . acquire ( ) then return [ ] end if
    if this . closed then
    this . guard . release ( )
    return [ ]
    end if
    output = array ( this . size )

- [`std/ds/concurrent_hashmap.ml:324`](File-std-ds-concurrent-hashmap-ml-1798836270.md)
- [`std/ds/concurrent_hashmap.ml:345`](File-std-ds-concurrent-hashmap-ml-1798836270.md)
- [`std/ds/concurrent_hashmap.ml:366`](File-std-ds-concurrent-hashmap-ml-1798836270.md)
- [`std/ds/concurrent_list.ml:299`](File-std-ds-concurrent-list-ml-291130726.md)

</details>

<details>
<summary>Clone 76 — 3 occurrences</summary>

    if this . closed then
    this . guard . release ( )
    return [ ]
    end if
    output = array ( this . size )
    outputIndex = 0

- [`std/ds/concurrent_hashmap.ml:325`](File-std-ds-concurrent-hashmap-ml-1798836270.md)
- [`std/ds/concurrent_hashmap.ml:346`](File-std-ds-concurrent-hashmap-ml-1798836270.md)
- [`std/ds/concurrent_hashmap.ml:367`](File-std-ds-concurrent-hashmap-ml-1798836270.md)

</details>

<details>
<summary>Clone 77 — 3 occurrences</summary>

    this . guard . release ( )
    return [ ]
    end if
    output = array ( this . size )
    outputIndex = 0
    i = 0

- [`std/ds/concurrent_hashmap.ml:326`](File-std-ds-concurrent-hashmap-ml-1798836270.md)
- [`std/ds/concurrent_hashmap.ml:347`](File-std-ds-concurrent-hashmap-ml-1798836270.md)
- [`std/ds/concurrent_hashmap.ml:368`](File-std-ds-concurrent-hashmap-ml-1798836270.md)

</details>

<details>
<summary>Clone 78 — 3 occurrences</summary>

    return [ ]
    end if
    output = array ( this . size )
    outputIndex = 0
    i = 0
    while i < this . bucketCount

- [`std/ds/concurrent_hashmap.ml:327`](File-std-ds-concurrent-hashmap-ml-1798836270.md)
- [`std/ds/concurrent_hashmap.ml:348`](File-std-ds-concurrent-hashmap-ml-1798836270.md)
- [`std/ds/concurrent_hashmap.ml:369`](File-std-ds-concurrent-hashmap-ml-1798836270.md)

</details>

<details>
<summary>Clone 79 — 3 occurrences</summary>

    end if
    output = array ( this . size )
    outputIndex = 0
    i = 0
    while i < this . bucketCount
    if this . states [ i ] == 1 then

- [`std/ds/concurrent_hashmap.ml:328`](File-std-ds-concurrent-hashmap-ml-1798836270.md)
- [`std/ds/concurrent_hashmap.ml:349`](File-std-ds-concurrent-hashmap-ml-1798836270.md)
- [`std/ds/concurrent_hashmap.ml:370`](File-std-ds-concurrent-hashmap-ml-1798836270.md)

</details>

<details>
<summary>Clone 80 — 3 occurrences</summary>

    outputIndex = outputIndex + 1
    end if
    i = i + 1
    end while
    this . guard . release ( )
    return output

- [`std/ds/concurrent_hashmap.ml:335`](File-std-ds-concurrent-hashmap-ml-1798836270.md)
- [`std/ds/concurrent_hashmap.ml:356`](File-std-ds-concurrent-hashmap-ml-1798836270.md)
- [`std/ds/concurrent_hashmap.ml:377`](File-std-ds-concurrent-hashmap-ml-1798836270.md)

</details>

<details>
<summary>Clone 81 — 3 occurrences</summary>

    end if
    i = i + 1
    end while
    this . guard . release ( )
    return output
    end function

- [`std/ds/concurrent_hashmap.ml:336`](File-std-ds-concurrent-hashmap-ml-1798836270.md)
- [`std/ds/concurrent_hashmap.ml:357`](File-std-ds-concurrent-hashmap-ml-1798836270.md)
- [`std/ds/concurrent_hashmap.ml:378`](File-std-ds-concurrent-hashmap-ml-1798836270.md)

</details>

<details>
<summary>Clone 82 — 2 occurrences</summary>

    h = h ^ ( h >> 16 )
    h = ( h * 0x7feb352d ) & 0xFFFFFFFF
    h = h ^ ( h >> 15 )
    h = ( h * 0x846ca68b ) & 0xFFFFFFFF
    h = h ^ ( h >> 16 )
    return h & 0xFFFFFFFF

- [`std/ds/concurrent_hashmap.ml:36`](File-std-ds-concurrent-hashmap-ml-1798836270.md)
- [`std/ds/hashmap.ml:68`](File-std-ds-hashmap-ml-1269372918.md)

</details>

<details>
<summary>Clone 83 — 2 occurrences</summary>

    h = ( h * 0x7feb352d ) & 0xFFFFFFFF
    h = h ^ ( h >> 15 )
    h = ( h * 0x846ca68b ) & 0xFFFFFFFF
    h = h ^ ( h >> 16 )
    return h & 0xFFFFFFFF
    end function

- [`std/ds/concurrent_hashmap.ml:37`](File-std-ds-concurrent-hashmap-ml-1798836270.md)
- [`std/ds/hashmap.ml:69`](File-std-ds-hashmap-ml-1269372918.md)

</details>

<details>
<summary>Clone 84 — 2 occurrences</summary>

    this . closed = true
    this . guard . release ( )
    this . guard . close ( )
    return true
    end function
    end struct

- [`std/ds/concurrent_hashmap.ml:393`](File-std-ds-concurrent-hashmap-ml-1798836270.md)
- [`std/ds/concurrent_list.ml:320`](File-std-ds-concurrent-list-ml-291130726.md)

</details>

<details>
<summary>Clone 85 — 2 occurrences</summary>

    if typeof ( index ) != "int" then return end if
    if not this . guard . acquire ( ) then return end if
    if this . closed or index < 0 or index >= this . size then
    this . guard . release ( )
    return
    end if

- [`std/ds/concurrent_list.ml:171`](File-std-ds-concurrent-list-ml-291130726.md)
- [`std/ds/concurrent_list.ml:239`](File-std-ds-concurrent-list-ml-291130726.md)

</details>

<details>
<summary>Clone 86 — 2 occurrences</summary>

    if not this . guard . acquire ( ) then return end if
    if this . closed or index < 0 or index >= this . size then
    this . guard . release ( )
    return
    end if
    result = this . buf [ index ]

- [`std/ds/concurrent_list.ml:172`](File-std-ds-concurrent-list-ml-291130726.md)
- [`std/ds/concurrent_list.ml:240`](File-std-ds-concurrent-list-ml-291130726.md)

</details>

<details>
<summary>Clone 87 — 2 occurrences</summary>

    i = this . size
    while i > index
    this . buf [ i ] = this . buf [ i - 1 ]
    i = i - 1
    end while
    this . buf [ index ] = value

- [`std/ds/concurrent_list.ml:225`](File-std-ds-concurrent-list-ml-291130726.md)
- [`std/ds/list.ml:255`](File-std-ds-list-ml-2070188142.md)

</details>

<details>
<summary>Clone 88 — 2 occurrences</summary>

    while i > index
    this . buf [ i ] = this . buf [ i - 1 ]
    i = i - 1
    end while
    this . buf [ index ] = value
    this . size = this . size + 1

- [`std/ds/concurrent_list.ml:226`](File-std-ds-concurrent-list-ml-291130726.md)
- [`std/ds/list.ml:256`](File-std-ds-list-ml-2070188142.md)

</details>

<details>
<summary>Clone 89 — 3 occurrences</summary>

    function _allocArray ( n , fill )
    if typeof ( n ) != "int" then
    return
    end if
    if n <= 0 then
    return [ ]

- [`std/ds/hashmap.ml:37`](File-std-ds-hashmap-ml-1269372918.md)
- [`std/ds/list.ml:32`](File-std-ds-list-ml-2070188142.md)
- [`std/ds/queue.ml:31`](File-std-ds-queue-ml-1555253413.md)

</details>

<details>
<summary>Clone 90 — 3 occurrences</summary>

    if typeof ( n ) != "int" then
    return
    end if
    if n <= 0 then
    return [ ]
    end if

- [`std/ds/hashmap.ml:38`](File-std-ds-hashmap-ml-1269372918.md)
- [`std/ds/list.ml:33`](File-std-ds-list-ml-2070188142.md)
- [`std/ds/queue.ml:32`](File-std-ds-queue-ml-1555253413.md)

</details>

<details>
<summary>Clone 91 — 3 occurrences</summary>

    return
    end if
    if n <= 0 then
    return [ ]
    end if
    return array ( n , fill )

- [`std/ds/hashmap.ml:39`](File-std-ds-hashmap-ml-1269372918.md)
- [`std/ds/list.ml:34`](File-std-ds-list-ml-2070188142.md)
- [`std/ds/queue.ml:33`](File-std-ds-queue-ml-1555253413.md)

</details>

<details>
<summary>Clone 92 — 3 occurrences</summary>

    end if
    if n <= 0 then
    return [ ]
    end if
    return array ( n , fill )
    end function

- [`std/ds/hashmap.ml:40`](File-std-ds-hashmap-ml-1269372918.md)
- [`std/ds/list.ml:35`](File-std-ds-list-ml-2070188142.md)
- [`std/ds/queue.ml:34`](File-std-ds-queue-ml-1555253413.md)

</details>

<details>
<summary>Clone 93 — 2 occurrences</summary>

    function _nextPow2 ( n )
    if typeof ( n ) != "int" then
    return 16
    end if
    if n <= 16 then
    return 16

- [`std/ds/hashmap.ml:49`](File-std-ds-hashmap-ml-1269372918.md)
- [`std/string_builder.ml:26`](File-std-string-builder-ml-412876577.md)

</details>

<details>
<summary>Clone 94 — 2 occurrences</summary>

    if typeof ( n ) != "int" then
    return 16
    end if
    if n <= 16 then
    return 16
    end if

- [`std/ds/hashmap.ml:50`](File-std-ds-hashmap-ml-1269372918.md)
- [`std/string_builder.ml:27`](File-std-string-builder-ml-412876577.md)

</details>

<details>
<summary>Clone 95 — 2 occurrences</summary>

    return 16
    end if
    if n <= 16 then
    return 16
    end if
    c = 16

- [`std/ds/hashmap.ml:51`](File-std-ds-hashmap-ml-1269372918.md)
- [`std/string_builder.ml:28`](File-std-string-builder-ml-412876577.md)

</details>

<details>
<summary>Clone 96 — 2 occurrences</summary>

    end if
    if n <= 16 then
    return 16
    end if
    c = 16
    while c < n

- [`std/ds/hashmap.ml:52`](File-std-ds-hashmap-ml-1269372918.md)
- [`std/string_builder.ml:29`](File-std-string-builder-ml-412876577.md)

</details>

<details>
<summary>Clone 97 — 2 occurrences</summary>

    if n <= 16 then
    return 16
    end if
    c = 16
    while c < n
    c = c << 1

- [`std/ds/hashmap.ml:53`](File-std-ds-hashmap-ml-1269372918.md)
- [`std/string_builder.ml:30`](File-std-string-builder-ml-412876577.md)

</details>

<details>
<summary>Clone 98 — 2 occurrences</summary>

    return 16
    end if
    c = 16
    while c < n
    c = c << 1
    end while

- [`std/ds/hashmap.ml:54`](File-std-ds-hashmap-ml-1269372918.md)
- [`std/string_builder.ml:31`](File-std-string-builder-ml-412876577.md)

</details>

<details>
<summary>Clone 99 — 2 occurrences</summary>

    end if
    c = 16
    while c < n
    c = c << 1
    end while
    return c

- [`std/ds/hashmap.ml:55`](File-std-ds-hashmap-ml-1269372918.md)
- [`std/string_builder.ml:32`](File-std-string-builder-ml-412876577.md)

</details>

<details>
<summary>Clone 100 — 2 occurrences</summary>

    c = 16
    while c < n
    c = c << 1
    end while
    return c
    end function

- [`std/ds/hashmap.ml:56`](File-std-ds-hashmap-ml-1269372918.md)
- [`std/string_builder.ml:33`](File-std-string-builder-ml-412876577.md)

</details>

<details>
<summary>Clone 101 — 2 occurrences</summary>

    if typeof ( index ) != "int" then
    return
    end if
    if index < 0 or index >= this . size then
    return
    end if

- [`std/ds/list.ml:177`](File-std-ds-list-ml-2070188142.md)
- [`std/ds/list.ml:268`](File-std-ds-list-ml-2070188142.md)

</details>

<details>
<summary>Clone 102 — 2 occurrences</summary>

    function popOr ( fallbackValue )
    v = this . pop ( )
    if typeof ( v ) == "void" then
    return fallbackValue
    end if
    return v

- [`std/ds/list.ml:230`](File-std-ds-list-ml-2070188142.md)
- [`std/ds/stack.ml:276`](File-std-ds-stack-ml-117945432.md)

</details>

<details>
<summary>Clone 103 — 2 occurrences</summary>

    v = this . pop ( )
    if typeof ( v ) == "void" then
    return fallbackValue
    end if
    return v
    end function

- [`std/ds/list.ml:231`](File-std-ds-list-ml-2070188142.md)
- [`std/ds/stack.ml:277`](File-std-ds-stack-ml-117945432.md)

</details>

<details>
<summary>Clone 104 — 3 occurrences</summary>

    function _nextPow2 ( n )
    if typeof ( n ) != "int" then
    return 8
    end if
    if n <= 8 then
    return 8

- [`std/ds/list.ml:44`](File-std-ds-list-ml-2070188142.md)
- [`std/ds/queue.ml:43`](File-std-ds-queue-ml-1555253413.md)
- [`std/ds/stack.ml:39`](File-std-ds-stack-ml-117945432.md)

</details>

<details>
<summary>Clone 105 — 3 occurrences</summary>

    if typeof ( n ) != "int" then
    return 8
    end if
    if n <= 8 then
    return 8
    end if

- [`std/ds/list.ml:45`](File-std-ds-list-ml-2070188142.md)
- [`std/ds/queue.ml:44`](File-std-ds-queue-ml-1555253413.md)
- [`std/ds/stack.ml:40`](File-std-ds-stack-ml-117945432.md)

</details>

<details>
<summary>Clone 106 — 3 occurrences</summary>

    return 8
    end if
    if n <= 8 then
    return 8
    end if
    c = 8

- [`std/ds/list.ml:46`](File-std-ds-list-ml-2070188142.md)
- [`std/ds/queue.ml:45`](File-std-ds-queue-ml-1555253413.md)
- [`std/ds/stack.ml:41`](File-std-ds-stack-ml-117945432.md)

</details>

<details>
<summary>Clone 107 — 3 occurrences</summary>

    end if
    if n <= 8 then
    return 8
    end if
    c = 8
    while c < n

- [`std/ds/list.ml:47`](File-std-ds-list-ml-2070188142.md)
- [`std/ds/queue.ml:46`](File-std-ds-queue-ml-1555253413.md)
- [`std/ds/stack.ml:42`](File-std-ds-stack-ml-117945432.md)

</details>

<details>
<summary>Clone 108 — 3 occurrences</summary>

    if n <= 8 then
    return 8
    end if
    c = 8
    while c < n
    c = c << 1

- [`std/ds/list.ml:48`](File-std-ds-list-ml-2070188142.md)
- [`std/ds/queue.ml:47`](File-std-ds-queue-ml-1555253413.md)
- [`std/ds/stack.ml:43`](File-std-ds-stack-ml-117945432.md)

</details>

<details>
<summary>Clone 109 — 3 occurrences</summary>

    return 8
    end if
    c = 8
    while c < n
    c = c << 1
    end while

- [`std/ds/list.ml:49`](File-std-ds-list-ml-2070188142.md)
- [`std/ds/queue.ml:48`](File-std-ds-queue-ml-1555253413.md)
- [`std/ds/stack.ml:44`](File-std-ds-stack-ml-117945432.md)

</details>

<details>
<summary>Clone 110 — 3 occurrences</summary>

    end if
    c = 8
    while c < n
    c = c << 1
    end while
    return c

- [`std/ds/list.ml:50`](File-std-ds-list-ml-2070188142.md)
- [`std/ds/queue.ml:49`](File-std-ds-queue-ml-1555253413.md)
- [`std/ds/stack.ml:45`](File-std-ds-stack-ml-117945432.md)

</details>

<details>
<summary>Clone 111 — 3 occurrences</summary>

    c = 8
    while c < n
    c = c << 1
    end while
    return c
    end function

- [`std/ds/list.ml:51`](File-std-ds-list-ml-2070188142.md)
- [`std/ds/queue.ml:50`](File-std-ds-queue-ml-1555253413.md)
- [`std/ds/stack.ml:46`](File-std-ds-stack-ml-117945432.md)

</details>

<details>
<summary>Clone 112 — 2 occurrences</summary>

    if typeof ( n ) != "int" then
    return
    end if
    if n < 0 then
    return
    end if

- [`std/ds/stack.ml:28`](File-std-ds-stack-ml-117945432.md)
- [`std/sort.ml:213`](File-std-sort-ml-1000391650.md)

</details>

<details>
<summary>Clone 113 — 2 occurrences</summary>

    return
    end if
    if n < 0 then
    return
    end if
    return array ( n , fill )

- [`std/ds/stack.ml:29`](File-std-ds-stack-ml-117945432.md)
- [`std/sort.ml:214`](File-std-sort-ml-1000391650.md)

</details>

<details>
<summary>Clone 114 — 2 occurrences</summary>

    end if
    if n < 0 then
    return
    end if
    return array ( n , fill )
    end function

- [`std/ds/stack.ml:30`](File-std-ds-stack-ml-117945432.md)
- [`std/sort.ml:215`](File-std-sort-ml-1000391650.md)

</details>

<details>
<summary>Clone 115 — 2 occurrences</summary>

    function _decodeOrEmpty ( b )
    if typeof ( b ) != "bytes" then
    return
    end if
    if len ( b ) == 0 then
    return ""

- [`std/encoding/base64.ml:68`](File-std-encoding-base64-ml-1044483879.md)
- [`std/string.ml:69`](File-std-string-ml-1276545685.md)

</details>

<details>
<summary>Clone 116 — 2 occurrences</summary>

    if typeof ( b ) != "bytes" then
    return
    end if
    if len ( b ) == 0 then
    return ""
    end if

- [`std/encoding/base64.ml:69`](File-std-encoding-base64-ml-1044483879.md)
- [`std/string.ml:70`](File-std-string-ml-1276545685.md)

</details>

<details>
<summary>Clone 117 — 2 occurrences</summary>

    return
    end if
    if len ( b ) == 0 then
    return ""
    end if
    return decode ( b )

- [`std/encoding/base64.ml:70`](File-std-encoding-base64-ml-1044483879.md)
- [`std/string.ml:71`](File-std-string-ml-1276545685.md)

</details>

<details>
<summary>Clone 118 — 2 occurrences</summary>

    end if
    if len ( b ) == 0 then
    return ""
    end if
    return decode ( b )
    end function

- [`std/encoding/base64.ml:71`](File-std-encoding-base64-ml-1044483879.md)
- [`std/string.ml:72`](File-std-string-ml-1276545685.md)

</details>

<details>
<summary>Clone 119 — 3 occurrences</summary>

    if typeof ( s ) != "string" or typeof ( width ) != "int" or typeof ( ch ) != "string" then
    return
    end if
    n = width - len ( s )
    if n <= 0 or len ( ch ) == 0 then
    return s

- [`std/fmt.ml:37`](File-std-fmt-ml-2123112301.md)
- [`std/fmt.ml:52`](File-std-fmt-ml-2123112301.md)
- [`std/fmt.ml:67`](File-std-fmt-ml-2123112301.md)

</details>

<details>
<summary>Clone 120 — 3 occurrences</summary>

    return
    end if
    n = width - len ( s )
    if n <= 0 or len ( ch ) == 0 then
    return s
    end if

- [`std/fmt.ml:38`](File-std-fmt-ml-2123112301.md)
- [`std/fmt.ml:53`](File-std-fmt-ml-2123112301.md)
- [`std/fmt.ml:68`](File-std-fmt-ml-2123112301.md)

</details>

<details>
<summary>Clone 121 — 2 occurrences</summary>

    h = CreateFileW (
    path ,
    std . fs . Access . GENERIC_READ ,
    std . fs . Share . FILE_SHARE_READ ,
    0 ,
    std . fs . Creation . OPEN_EXISTING ,

- [`std/fs.ml:524`](File-std-fs-ml-1285967051.md)
- [`std/fs.ml:626`](File-std-fs-ml-1285967051.md)

</details>

<details>
<summary>Clone 122 — 2 occurrences</summary>

    path ,
    std . fs . Access . GENERIC_READ ,
    std . fs . Share . FILE_SHARE_READ ,
    0 ,
    std . fs . Creation . OPEN_EXISTING ,
    std . fs . FileAttr . FILE_ATTRIBUTE_NORMAL ,

- [`std/fs.ml:525`](File-std-fs-ml-1285967051.md)
- [`std/fs.ml:627`](File-std-fs-ml-1285967051.md)

</details>

<details>
<summary>Clone 123 — 2 occurrences</summary>

    std . fs . Access . GENERIC_READ ,
    std . fs . Share . FILE_SHARE_READ ,
    0 ,
    std . fs . Creation . OPEN_EXISTING ,
    std . fs . FileAttr . FILE_ATTRIBUTE_NORMAL ,
    0

- [`std/fs.ml:526`](File-std-fs-ml-1285967051.md)
- [`std/fs.ml:628`](File-std-fs-ml-1285967051.md)

</details>

<details>
<summary>Clone 124 — 2 occurrences</summary>

    std . fs . Share . FILE_SHARE_READ ,
    0 ,
    std . fs . Creation . OPEN_EXISTING ,
    std . fs . FileAttr . FILE_ATTRIBUTE_NORMAL ,
    0
    )

- [`std/fs.ml:527`](File-std-fs-ml-1285967051.md)
- [`std/fs.ml:629`](File-std-fs-ml-1285967051.md)

</details>

<details>
<summary>Clone 125 — 2 occurrences</summary>

    0 ,
    std . fs . Creation . OPEN_EXISTING ,
    std . fs . FileAttr . FILE_ATTRIBUTE_NORMAL ,
    0
    )
    if h == std . fs . INVALID_HANDLE_VALUE then

- [`std/fs.ml:528`](File-std-fs-ml-1285967051.md)
- [`std/fs.ml:630`](File-std-fs-ml-1285967051.md)

</details>

<details>
<summary>Clone 126 — 2 occurrences</summary>

    pos = 0
    while pos < size
    toRead = size - pos
    if toRead > std . fs . IO_BUF_SIZE then
    toRead = std . fs . IO_BUF_SIZE
    end if

- [`std/fs.ml:562`](File-std-fs-ml-1285967051.md)
- [`std/fs.ml:670`](File-std-fs-ml-1285967051.md)

</details>

<details>
<summary>Clone 127 — 2 occurrences</summary>

    j = 0
    while j < m and hay [ i + j ] == needle [ j ]
    j = j + 1
    end while
    if j == m then
    return i

- [`std/string.ml:113`](File-std-string-ml-1276545685.md)
- [`std/string.ml:217`](File-std-string-ml-1276545685.md)

</details>

<details>
<summary>Clone 128 — 2 occurrences</summary>

    while j < m and hay [ i + j ] == needle [ j ]
    j = j + 1
    end while
    if j == m then
    return i
    end if

- [`std/string.ml:114`](File-std-string-ml-1276545685.md)
- [`std/string.ml:218`](File-std-string-ml-1276545685.md)

</details>

<details>
<summary>Clone 129 — 2 occurrences</summary>

    n = len ( hay )
    m = len ( needle )
    i0 = start
    if typeof ( i0 ) != "int" then
    i0 = 0
    end if

- [`std/string.ml:133`](File-std-string-ml-1276545685.md)
- [`std/string.ml:86`](File-std-string-ml-1276545685.md)

</details>

<details>
<summary>Clone 130 — 2 occurrences</summary>

    m = len ( needle )
    i0 = start
    if typeof ( i0 ) != "int" then
    i0 = 0
    end if
    if i0 < 0 then

- [`std/string.ml:134`](File-std-string-ml-1276545685.md)
- [`std/string.ml:87`](File-std-string-ml-1276545685.md)

</details>

<details>
<summary>Clone 131 — 2 occurrences</summary>

    i0 = start
    if typeof ( i0 ) != "int" then
    i0 = 0
    end if
    if i0 < 0 then
    i0 = 0

- [`std/string.ml:135`](File-std-string-ml-1276545685.md)
- [`std/string.ml:88`](File-std-string-ml-1276545685.md)

</details>

<details>
<summary>Clone 132 — 2 occurrences</summary>

    if typeof ( i0 ) != "int" then
    i0 = 0
    end if
    if i0 < 0 then
    i0 = 0
    end if

- [`std/string.ml:136`](File-std-string-ml-1276545685.md)
- [`std/string.ml:89`](File-std-string-ml-1276545685.md)

</details>

<details>
<summary>Clone 133 — 2 occurrences</summary>

    i0 = 0
    end if
    if i0 < 0 then
    i0 = 0
    end if
    if i0 > n then

- [`std/string.ml:137`](File-std-string-ml-1276545685.md)
- [`std/string.ml:90`](File-std-string-ml-1276545685.md)

</details>

<details>
<summary>Clone 134 — 2 occurrences</summary>

    end if
    if i0 < 0 then
    i0 = 0
    end if
    if i0 > n then
    i0 = n

- [`std/string.ml:138`](File-std-string-ml-1276545685.md)
- [`std/string.ml:91`](File-std-string-ml-1276545685.md)

</details>

<details>
<summary>Clone 135 — 5 occurrences</summary>

    if typeof ( s ) != "string" then
    return
    end if
    if typeof ( needle ) != "string" then
    return
    end if

- [`std/string.ml:273`](File-std-string-ml-1276545685.md)
- [`std/string.ml:289`](File-std-string-ml-1276545685.md)
- [`std/string.ml:397`](File-std-string-ml-1276545685.md)
- [`std/string.ml:447`](File-std-string-ml-1276545685.md)
- [`std/string.ml:490`](File-std-string-ml-1276545685.md)

</details>

<details>
<summary>Clone 136 — 2 occurrences</summary>

    return
    end if
    if typeof ( needle ) != "string" then
    return
    end if
    if typeof ( repl ) != "string" then

- [`std/string.ml:398`](File-std-string-ml-1276545685.md)
- [`std/string.ml:448`](File-std-string-ml-1276545685.md)

</details>

<details>
<summary>Clone 137 — 2 occurrences</summary>

    end if
    if typeof ( needle ) != "string" then
    return
    end if
    if typeof ( repl ) != "string" then
    return

- [`std/string.ml:399`](File-std-string-ml-1276545685.md)
- [`std/string.ml:449`](File-std-string-ml-1276545685.md)

</details>

<details>
<summary>Clone 138 — 2 occurrences</summary>

    if typeof ( needle ) != "string" then
    return
    end if
    if typeof ( repl ) != "string" then
    return
    end if

- [`std/string.ml:400`](File-std-string-ml-1276545685.md)
- [`std/string.ml:450`](File-std-string-ml-1276545685.md)

</details>

<details>
<summary>Clone 139 — 2 occurrences</summary>

    if typeof ( ch ) != "string" then
    return false
    end if
    if len ( ch ) != 1 then
    return false
    end if

- [`std/string.ml:537`](File-std-string-ml-1276545685.md)
- [`std/string.ml:549`](File-std-string-ml-1276545685.md)

</details>

<details>
<summary>Clone 140 — 3 occurrences</summary>

    function close ( )
    if this . closed then return false end if
    ok = CloseHandle ( this . handle )
    if ok then
    this . closed = true
    this . handle = 0

- [`std/threading.ml:113`](File-std-threading-ml-508437988.md)
- [`std/threading.ml:202`](File-std-threading-ml-508437988.md)
- [`std/threading.ml:289`](File-std-threading-ml-508437988.md)

</details>

<details>
<summary>Clone 141 — 3 occurrences</summary>

    if this . closed then return false end if
    ok = CloseHandle ( this . handle )
    if ok then
    this . closed = true
    this . handle = 0
    end if

- [`std/threading.ml:114`](File-std-threading-ml-508437988.md)
- [`std/threading.ml:203`](File-std-threading-ml-508437988.md)
- [`std/threading.ml:290`](File-std-threading-ml-508437988.md)

</details>

<details>
<summary>Clone 142 — 3 occurrences</summary>

    ok = CloseHandle ( this . handle )
    if ok then
    this . closed = true
    this . handle = 0
    end if
    return ok

- [`std/threading.ml:115`](File-std-threading-ml-508437988.md)
- [`std/threading.ml:204`](File-std-threading-ml-508437988.md)
- [`std/threading.ml:291`](File-std-threading-ml-508437988.md)

</details>

<details>
<summary>Clone 143 — 3 occurrences</summary>

    if ok then
    this . closed = true
    this . handle = 0
    end if
    return ok
    end function

- [`std/threading.ml:116`](File-std-threading-ml-508437988.md)
- [`std/threading.ml:205`](File-std-threading-ml-508437988.md)
- [`std/threading.ml:292`](File-std-threading-ml-508437988.md)

</details>

<details>
<summary>Clone 144 — 2 occurrences</summary>

    function acquireFor ( milliseconds )
    if this . closed or typeof ( milliseconds ) != "int" or milliseconds < 0 or milliseconds > MAX_PORTABLE_TIMEOUT_MS then
    return false
    end if
    return _waitSucceeded ( WaitForSingleObject ( this . handle , milliseconds ) )
    end function

- [`std/threading.ml:170`](File-std-threading-ml-508437988.md)
- [`std/threading.ml:89`](File-std-threading-ml-508437988.md)

</details>

<details>
<summary>Clone 145 — 2 occurrences</summary>

    if secBufferType ( buffers , index ) == SECBUFFER_EXTRA then
    extraLength = secBufferLength ( buffers , index )
    pointerResult = try ( secBufferPointer ( buffers , index ) )
    if typeof ( pointerResult ) != "error" then extraPointer = pointerResult end if
    end if
    index = index + 1

- [`std/tls/_schannel.ml:1144`](File-std-tls-schannel-ml-805501109.md)
- [`std/tls/_schannel.ml:1301`](File-std-tls-schannel-ml-805501109.md)

</details>

<details>
<summary>Clone 146 — 2 occurrences</summary>

    extraLength = secBufferLength ( buffers , index )
    pointerResult = try ( secBufferPointer ( buffers , index ) )
    if typeof ( pointerResult ) != "error" then extraPointer = pointerResult end if
    end if
    index = index + 1
    end while

- [`std/tls/_schannel.ml:1145`](File-std-tls-schannel-ml-805501109.md)
- [`std/tls/_schannel.ml:1302`](File-std-tls-schannel-ml-805501109.md)

</details>

<details>
<summary>Clone 147 — 2 occurrences</summary>

    pointerResult = try ( secBufferPointer ( buffers , index ) )
    if typeof ( pointerResult ) != "error" then extraPointer = pointerResult end if
    end if
    index = index + 1
    end while
    if extraLength <= 0 then return bytes ( 0 ) end if

- [`std/tls/_schannel.ml:1146`](File-std-tls-schannel-ml-805501109.md)
- [`std/tls/_schannel.ml:1303`](File-std-tls-schannel-ml-805501109.md)

</details>

<details>
<summary>Clone 148 — 2 occurrences</summary>

    if typeof ( pointerResult ) != "error" then extraPointer = pointerResult end if
    end if
    index = index + 1
    end while
    if extraLength <= 0 then return bytes ( 0 ) end if
    basePointer = nativeBytesPtr ( inputBytes )

- [`std/tls/_schannel.ml:1147`](File-std-tls-schannel-ml-805501109.md)
- [`std/tls/_schannel.ml:1304`](File-std-tls-schannel-ml-805501109.md)

</details>

<details>
<summary>Clone 149 — 2 occurrences</summary>

    end if
    index = index + 1
    end while
    if extraLength <= 0 then return bytes ( 0 ) end if
    basePointer = nativeBytesPtr ( inputBytes )
    offset = len ( inputBytes ) - extraLength

- [`std/tls/_schannel.ml:1148`](File-std-tls-schannel-ml-805501109.md)
- [`std/tls/_schannel.ml:1305`](File-std-tls-schannel-ml-805501109.md)

</details>

<details>
<summary>Clone 150 — 2 occurrences</summary>

    index = index + 1
    end while
    if extraLength <= 0 then return bytes ( 0 ) end if
    basePointer = nativeBytesPtr ( inputBytes )
    offset = len ( inputBytes ) - extraLength
    if extraPointer >= basePointer and extraPointer <= basePointer + len ( inputBytes ) - extraLength then offset = extraPointer - basePointer end if

- [`std/tls/_schannel.ml:1149`](File-std-tls-schannel-ml-805501109.md)
- [`std/tls/_schannel.ml:1306`](File-std-tls-schannel-ml-805501109.md)

</details>

<details>
<summary>Clone 151 — 2 occurrences</summary>

    inbound = try ( appendBytes ( inbound , received ) )
    if typeof ( inbound ) == "error" then closeContext ( context ) ; return inbound end if
    input = inputTokenDesc ( inbound )
    token = bytes ( TLS_TOKEN_BYTES , 0 )
    outputBuffer = createSecBuffer ( SECBUFFER_TOKEN , token )
    outputDesc = createSecBufferDesc ( outputBuffer )

- [`std/tls/_schannel.ml:1182`](File-std-tls-schannel-ml-805501109.md)
- [`std/tls/_schannel.ml:1222`](File-std-tls-schannel-ml-805501109.md)

</details>

<details>
<summary>Clone 152 — 2 occurrences</summary>

    sent = try ( network . tcpSendAll ( socketHandle , outputToken ) )
    if typeof ( sent ) == "error" then closeContext ( context ) ; return sent end if
    end if
    extra = try ( handshakeExtra ( inbound , input [ 0 ] ) )
    if typeof ( extra ) == "error" then closeContext ( context ) ; return extra end if
    inbound = extra

- [`std/tls/_schannel.ml:1195`](File-std-tls-schannel-ml-805501109.md)
- [`std/tls/_schannel.ml:1242`](File-std-tls-schannel-ml-805501109.md)

</details>

<details>
<summary>Clone 153 — 2 occurrences</summary>

    if typeof ( sent ) == "error" then closeContext ( context ) ; return sent end if
    end if
    extra = try ( handshakeExtra ( inbound , input [ 0 ] ) )
    if typeof ( extra ) == "error" then closeContext ( context ) ; return extra end if
    inbound = extra
    end while

- [`std/tls/_schannel.ml:1196`](File-std-tls-schannel-ml-805501109.md)
- [`std/tls/_schannel.ml:1243`](File-std-tls-schannel-ml-805501109.md)

</details>

<details>
<summary>Clone 154 — 2 occurrences</summary>

    end if
    extra = try ( handshakeExtra ( inbound , input [ 0 ] ) )
    if typeof ( extra ) == "error" then closeContext ( context ) ; return extra end if
    inbound = extra
    end while
    context . encryptedInput = inbound

- [`std/tls/_schannel.ml:1197`](File-std-tls-schannel-ml-805501109.md)
- [`std/tls/_schannel.ml:1244`](File-std-tls-schannel-ml-805501109.md)

</details>

<details>
<summary>Clone 155 — 2 occurrences</summary>

    extra = try ( handshakeExtra ( inbound , input [ 0 ] ) )
    if typeof ( extra ) == "error" then closeContext ( context ) ; return extra end if
    inbound = extra
    end while
    context . encryptedInput = inbound
    finished = try ( finishContext ( context ) )

- [`std/tls/_schannel.ml:1198`](File-std-tls-schannel-ml-805501109.md)
- [`std/tls/_schannel.ml:1245`](File-std-tls-schannel-ml-805501109.md)

</details>

<details>
<summary>Clone 156 — 2 occurrences</summary>

    if typeof ( extra ) == "error" then closeContext ( context ) ; return extra end if
    inbound = extra
    end while
    context . encryptedInput = inbound
    finished = try ( finishContext ( context ) )
    if typeof ( finished ) == "error" then closeContext ( context ) ; return finished end if

- [`std/tls/_schannel.ml:1199`](File-std-tls-schannel-ml-805501109.md)
- [`std/tls/_schannel.ml:1246`](File-std-tls-schannel-ml-805501109.md)

</details>

<details>
<summary>Clone 157 — 2 occurrences</summary>

    inbound = extra
    end while
    context . encryptedInput = inbound
    finished = try ( finishContext ( context ) )
    if typeof ( finished ) == "error" then closeContext ( context ) ; return finished end if
    return finished

- [`std/tls/_schannel.ml:1200`](File-std-tls-schannel-ml-805501109.md)
- [`std/tls/_schannel.ml:1247`](File-std-tls-schannel-ml-805501109.md)

</details>

<details>
<summary>Clone 158 — 2 occurrences</summary>

    end while
    context . encryptedInput = inbound
    finished = try ( finishContext ( context ) )
    if typeof ( finished ) == "error" then closeContext ( context ) ; return finished end if
    return finished
    end function

- [`std/tls/_schannel.ml:1201`](File-std-tls-schannel-ml-805501109.md)
- [`std/tls/_schannel.ml:1248`](File-std-tls-schannel-ml-805501109.md)

</details>

<details>
<summary>Clone 159 — 2 occurrences</summary>

    inputBytes = context . encryptedInput
    buffers = createSecBufferArray ( 4 )
    writeSecBuffer ( buffers , 0 , SECBUFFER_DATA , nativeBytesPtr ( inputBytes ) , len ( inputBytes ) )
    writeSecBuffer ( buffers , 1 , SECBUFFER_EMPTY , 0 , 0 )
    writeSecBuffer ( buffers , 2 , SECBUFFER_EMPTY , 0 , 0 )
    writeSecBuffer ( buffers , 3 , SECBUFFER_EMPTY , 0 , 0 )

- [`std/tls/_schannel.ml:1374`](File-std-tls-schannel-ml-805501109.md)
- [`std/tls/_schannel.ml:1416`](File-std-tls-schannel-ml-805501109.md)

</details>

<details>
<summary>Clone 160 — 2 occurrences</summary>

    buffers = createSecBufferArray ( 4 )
    writeSecBuffer ( buffers , 0 , SECBUFFER_DATA , nativeBytesPtr ( inputBytes ) , len ( inputBytes ) )
    writeSecBuffer ( buffers , 1 , SECBUFFER_EMPTY , 0 , 0 )
    writeSecBuffer ( buffers , 2 , SECBUFFER_EMPTY , 0 , 0 )
    writeSecBuffer ( buffers , 3 , SECBUFFER_EMPTY , 0 , 0 )
    desc = createSecBufferDescForArray ( buffers , 4 )

- [`std/tls/_schannel.ml:1375`](File-std-tls-schannel-ml-805501109.md)
- [`std/tls/_schannel.ml:1417`](File-std-tls-schannel-ml-805501109.md)

</details>

<details>
<summary>Clone 161 — 2 occurrences</summary>

    writeSecBuffer ( buffers , 0 , SECBUFFER_DATA , nativeBytesPtr ( inputBytes ) , len ( inputBytes ) )
    writeSecBuffer ( buffers , 1 , SECBUFFER_EMPTY , 0 , 0 )
    writeSecBuffer ( buffers , 2 , SECBUFFER_EMPTY , 0 , 0 )
    writeSecBuffer ( buffers , 3 , SECBUFFER_EMPTY , 0 , 0 )
    desc = createSecBufferDescForArray ( buffers , 4 )
    quality = bytes ( 4 , 0 )

- [`std/tls/_schannel.ml:1376`](File-std-tls-schannel-ml-805501109.md)
- [`std/tls/_schannel.ml:1418`](File-std-tls-schannel-ml-805501109.md)

</details>

<details>
<summary>Clone 162 — 2 occurrences</summary>

    writeSecBuffer ( buffers , 1 , SECBUFFER_EMPTY , 0 , 0 )
    writeSecBuffer ( buffers , 2 , SECBUFFER_EMPTY , 0 , 0 )
    writeSecBuffer ( buffers , 3 , SECBUFFER_EMPTY , 0 , 0 )
    desc = createSecBufferDescForArray ( buffers , 4 )
    quality = bytes ( 4 , 0 )
    status = DecryptMessage ( context . handle , desc , 0 , quality )

- [`std/tls/_schannel.ml:1377`](File-std-tls-schannel-ml-805501109.md)
- [`std/tls/_schannel.ml:1419`](File-std-tls-schannel-ml-805501109.md)

</details>

<details>
<summary>Clone 163 — 2 occurrences</summary>

    plain = try ( decryptedData ( inputBytes , buffers ) )
    if typeof ( plain ) == "error" then return plain end if
    extra = try ( decryptExtra ( inputBytes , buffers ) )
    if typeof ( extra ) == "error" then return extra end if
    context . encryptedInput = extra
    return plain

- [`std/tls/_schannel.ml:1403`](File-std-tls-schannel-ml-805501109.md)
- [`std/tls/_schannel.ml:1433`](File-std-tls-schannel-ml-805501109.md)

</details>


## Definitions

- **Cognitive complexity:** decision complexity weighted by nesting; logical `and`/`or` operators add one.
- **Cyclomatic complexity:** one plus decisions from conditions, loops, switch cases, and logical `and`/`or` operators.
- **Documentation coverage:** percentage of documented API summaries, parameter contracts, fields, constants, globals, and enum variants. Empty categories report 100% and do not affect the overall ratio.
- **Halstead metrics:** operators and operands are counted from MiniLang lexical tokens. Estimated defects are volume divided by 3,000.
- **Maintainability index:** normalized 0–100 index based on Halstead volume, cyclomatic complexity, and source lines. Project MI is source-line weighted across files.
- **SLOC:** non-empty lines containing MiniLang tokens after conditional preprocessing; comment-only lines are excluded.
