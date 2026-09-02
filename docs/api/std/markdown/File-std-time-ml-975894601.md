# `std/time.ml`

[Home](README.md) · [Files](Files.md)

Provides the std time package.

Package: [`std.time`](Package-std-time-1528865365.md)

Reachable from entry: **no**

## Imports

- `std/fmt.ml` as `fmt` → [std/fmt.ml](File-std-fmt-ml-2123112301.md)
- `std/string.ml` as `s` → [std/string.ml](File-std-string-ml-1276545685.md)

## Declarations

<a id="namespace-namespace-std-time-clock-namespace-clock-std-time-ml-505750649"></a>
### clock

```ml
namespace clock
```

Time-of-day construction, formatting and arithmetic.


Source: `std/time.ml:668`

<a id="function-function-std-time-clock-addmillis-function-addmillis-t-delta-std-time-ml-1733200724"></a>
### addMillis

```ml
function addMillis(t, delta)
```

Add milliseconds to a time (wraps within 24h).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `t` | `dynamic` | — | Value supplied for `t`. |
| `delta` | `dynamic` | — | Value supplied for `delta`. |


Source: `std/time.ml:738`

<a id="function-function-std-time-clock-compare-function-compare-a-b-std-time-ml-1662221955"></a>
### compare

```ml
function compare(a, b)
```

Compare two times.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | First input value. |
| `b` | `dynamic` | — | Second input value. |


Source: `std/time.ml:694`

<a id="function-function-std-time-clock-frommillis-function-frommillis-ms-std-time-ml-576832168"></a>
### fromMillis

```ml
function fromMillis(ms)
```

Convert milliseconds since 00:00 into a Time.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `ms` | `dynamic` | — | Value supplied for `ms`. |


Source: `std/time.ml:717`

<a id="function-function-std-time-clock-isvalid-function-isvalid-t-std-time-ml-358966926"></a>
### isValid

```ml
function isValid(t)
```

Validate a Time struct.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `t` | `dynamic` | — | Value supplied for `t`. |


Source: `std/time.ml:687`

<a id="function-function-std-time-clock-isvalidhmsm-function-isvalidhmsm-h-m-s0-ms-std-time-ml-348818806"></a>
### isValidHMSM

```ml
function isValidHMSM(h, m, s0, ms)
```

Validate a time quadruple (hour, minute, second, millisecond).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `h` | `dynamic` | — | Value supplied for `h`. |
| `m` | `dynamic` | — | Value supplied for `m`. |
| `s0` | `dynamic` | — | Value supplied for `s0`. |
| `ms` | `dynamic` | — | Value supplied for `ms`. |


Source: `std/time.ml:674`

<a id="function-function-std-time-clock-parse-function-parse-text-std-time-ml-549001107"></a>
### parse

```ml
function parse(text)
```

Parse time in the form HH:MM or HH:MM:SS[.mmm].

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `text` | `dynamic` | — | Text to process. |


Source: `std/time.ml:767`

<a id="function-function-std-time-clock-tomillis-function-tomillis-t-std-time-ml-2034526210"></a>
### toMillis

```ml
function toMillis(t)
```

Convert a Time into milliseconds since 00:00:00.000.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `t` | `dynamic` | — | Value supplied for `t`. |


Source: `std/time.ml:708`

<a id="function-function-std-time-clock-tostring-function-tostring-t-std-time-ml-68025454"></a>
### toString

```ml
function toString(t)
```

Format time as HH:MM:SS.mmm.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `t` | `dynamic` | — | Value supplied for `t`. |


Source: `std/time.ml:758`

<a id="function-function-std-time-clocktostring-function-clocktostring-t-std-time-ml-904167438"></a>
### clockToString

```ml
function clockToString(t)
```

Format a Time as a string (HH:MM:SS.mmm).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `t` | `dynamic` | — | Value supplied for `t`. |


Source: `std/time.ml:1086`

<a id="namespace-namespace-std-time-date-namespace-date-std-time-ml-498128071"></a>
### date

```ml
namespace date
```

Calendar-date construction, validation and arithmetic.


Source: `std/time.ml:426`

- [std.time.Date](Type-std-time-date-1789990781.md) — struct
<a id="function-function-std-time-date-adddays-function-adddays-d-delta-std-time-ml-164994134"></a>
### addDays

```ml
function addDays(d, delta)
```

Add days to a date.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `d` | `dynamic` | — | Value supplied for `d`. |
| `delta` | `dynamic` | — | Value supplied for `delta`. |


Source: `std/time.ml:593`

<a id="function-function-std-time-date-compare-function-compare-a-b-std-time-ml-265951007"></a>
### compare

```ml
function compare(a, b)
```

Compare two dates.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | First input value. |
| `b` | `dynamic` | — | Second input value. |


Source: `std/time.ml:580`

<a id="function-function-std-time-date-dayofweek-function-dayofweek-d-std-time-ml-1357661304"></a>
### dayOfWeek

```ml
function dayOfWeek(d)
```

Compute day of week for a date.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `d` | `dynamic` | — | Value supplied for `d`. |


Source: `std/time.ml:618`

<a id="function-function-std-time-date-daysinmonth-function-daysinmonth-year-month-std-time-ml-483008705"></a>
### daysInMonth

```ml
function daysInMonth(year, month)
```

Number of days in a month for a given year.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `year` | `dynamic` | — | Value supplied for `year`. |
| `month` | `dynamic` | — | Value supplied for `month`. |


Source: `std/time.ml:445`

<a id="function-function-std-time-date-diffdays-function-diffdays-a-b-std-time-ml-1684126225"></a>
### diffDays

```ml
function diffDays(a, b)
```

Difference in days between two dates.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | First input value. |
| `b` | `dynamic` | — | Second input value. |


Source: `std/time.ml:607`

<a id="function-function-std-time-date-fromordinal-function-fromordinal-days-std-time-ml-1450309647"></a>
### fromOrdinal

```ml
function fromOrdinal(days)
```

Inverse of toOrdinal.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `days` | `dynamic` | — | Value supplied for `days`. |


Source: `std/time.ml:525`

<a id="function-function-std-time-date-isleapyear-function-isleapyear-year-std-time-ml-576789919"></a>
### isLeapYear

```ml
function isLeapYear(year)
```

Check if a year is a leap year (Gregorian rules).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `year` | `dynamic` | — | Value supplied for `year`. |


Source: `std/time.ml:429`

<a id="function-function-std-time-date-isvalid-function-isvalid-d-std-time-ml-398313186"></a>
### isValid

```ml
function isValid(d)
```

Validate a Date struct.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `d` | `dynamic` | — | Value supplied for `d`. |


Source: `std/time.ml:492`

<a id="function-function-std-time-date-isvalidymd-function-isvalidymd-year-month-day-std-time-ml-1097498691"></a>
### isValidYMD

```ml
function isValidYMD(year, month, day)
```

Validate a date triple (year, month, day).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `year` | `dynamic` | — | Value supplied for `year`. |
| `month` | `dynamic` | — | Value supplied for `month`. |
| `day` | `dynamic` | — | Value supplied for `day`. |


Source: `std/time.ml:474`

<a id="function-function-std-time-date-parse-function-parse-text-std-time-ml-1488842447"></a>
### parse

```ml
function parse(text)
```

Parse a date in the form YYYY-MM-DD.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `text` | `dynamic` | — | Text to process. |


Source: `std/time.ml:639`

<a id="function-function-std-time-date-toordinal-function-toordinal-d-std-time-ml-2117441882"></a>
### toOrdinal

```ml
function toOrdinal(d)
```

Convert a Date to an ordinal day count.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `d` | `dynamic` | — | Value supplied for `d`. |


Source: `std/time.ml:498`

<a id="function-function-std-time-date-tostring-function-tostring-d-std-time-ml-1073583202"></a>
### toString

```ml
function toString(d)
```

Format date as YYYY-MM-DD.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `d` | `dynamic` | — | Value supplied for `d`. |


Source: `std/time.ml:630`

<a id="namespace-namespace-std-time-datetime-namespace-datetime-std-time-ml-253586669"></a>
### datetime

```ml
namespace datetime
```

Combined local/UTC date-time conversion and arithmetic.


Source: `std/time.ml:820`

- [std.time.DateTime](Type-std-time-datetime-1990581564.md) — struct
<a id="function-function-std-time-datetime-adddays-function-adddays-dt-deltadays-std-time-ml-203304236"></a>
### addDays

```ml
function addDays(dt, deltaDays)
```

Add whole days to a DateTime (keeps clock time).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `dt` | `dynamic` | — | Value supplied for `dt`. |
| `deltaDays` | `dynamic` | — | Value supplied for `deltaDays`. |


Source: `std/time.ml:893`

<a id="function-function-std-time-datetime-addmillis-function-addmillis-dt-delta-std-time-ml-1561373415"></a>
### addMillis

```ml
function addMillis(dt, delta)
```

Add milliseconds to a DateTime.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `dt` | `dynamic` | — | Value supplied for `dt`. |
| `delta` | `dynamic` | — | Value supplied for `delta`. |


Source: `std/time.ml:859`

<a id="function-function-std-time-datetime-compare-function-compare-a-b-std-time-ml-1157888456"></a>
### compare

```ml
function compare(a, b)
```

Compare two date-times.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | First input value. |
| `b` | `dynamic` | — | Second input value. |


Source: `std/time.ml:830`

<a id="function-function-std-time-datetime-fromsystemtime-function-fromsystemtime-st-std-time-ml-1983396154"></a>
### fromSystemTime

```ml
function fromSystemTime(st)
```

Convert a native SystemTime value to a DateTime.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `st` | `dynamic` | — | Value supplied for `st`. |


Source: `std/time.ml:952`

<a id="function-function-std-time-datetime-fromunixmillis-function-fromunixmillis-unixms-std-time-ml-399158673"></a>
### fromUnixMillis

```ml
function fromUnixMillis(unixMs)
```

Convert Unix milliseconds since 1970-01-01T00:00:00Z to a DateTime.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `unixMs` | `dynamic` | — | Value supplied for `unixMs`. |


Source: `std/time.ml:1007`

<a id="function-function-std-time-datetime-isvalid-function-isvalid-dt-std-time-ml-101864515"></a>
### isValid

```ml
function isValid(dt)
```

Validate a DateTime struct.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `dt` | `dynamic` | — | Value supplied for `dt`. |


Source: `std/time.ml:823`

<a id="function-function-std-time-datetime-nowlocal-function-nowlocal-std-time-ml-1503210091"></a>
### nowLocal

```ml
function nowLocal()
```

Current local wall-clock DateTime.


Source: `std/time.ml:984`

<a id="function-function-std-time-datetime-nowunixmillisutc-function-nowunixmillisutc-std-time-ml-1128288483"></a>
### nowUnixMillisUtc

```ml
function nowUnixMillisUtc()
```

Current Unix milliseconds based on UTC time.


Source: `std/time.ml:1034`

<a id="function-function-std-time-datetime-nowutc-function-nowutc-std-time-ml-120915363"></a>
### nowUtc

```ml
function nowUtc()
```

Current UTC wall-clock DateTime.


Source: `std/time.ml:990`

<a id="function-function-std-time-datetime-parse-function-parse-text-std-time-ml-1598500980"></a>
### parse

```ml
function parse(text)
```

Parse a DateTime in the form "YYYY-MM-DD HH:MM:SS[.mmm]" (also accepts 'T').

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `text` | `dynamic` | — | Text to process. |


Source: `std/time.ml:918`

<a id="function-function-std-time-datetime-tomillis-function-tomillis-dt-std-time-ml-874033111"></a>
### toMillis

```ml
function toMillis(dt)
```

Convert a DateTime to milliseconds since 0001-01-01 00:00:00.000.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `dt` | `dynamic` | — | Value supplied for `dt`. |


Source: `std/time.ml:840`

<a id="function-function-std-time-datetime-tostring-function-tostring-dt-std-time-ml-1324149955"></a>
### toString

```ml
function toString(dt)
```

Format a DateTime as "YYYY-MM-DD HH:MM:SS.mmm".

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `dt` | `dynamic` | — | Value supplied for `dt`. |


Source: `std/time.ml:909`

<a id="function-function-std-time-datetime-tounixmillis-function-tounixmillis-dt-std-time-ml-894528563"></a>
### toUnixMillis

```ml
function toUnixMillis(dt)
```

Convert a DateTime to Unix milliseconds since 1970-01-01T00:00:00Z.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `dt` | `dynamic` | — | Value supplied for `dt`. |


Source: `std/time.ml:997`

<a id="function-function-std-time-datetimetostring-function-datetimetostring-dt-std-time-ml-1282710884"></a>
### datetimeToString

```ml
function datetimeToString(dt)
```

Format a DateTime as a string (YYYY-MM-DD HH:MM:SS.mmm).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `dt` | `dynamic` | — | Value supplied for `dt`. |


Source: `std/time.ml:1092`

<a id="function-function-std-time-datetostring-function-datetostring-d-std-time-ml-1682286890"></a>
### dateToString

```ml
function dateToString(d)
```

Format a Date as a string (YYYY-MM-DD).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `d` | `dynamic` | — | Value supplied for `d`. |


Source: `std/time.ml:1080`

<a id="function-function-std-time-elapsed-function-elapsed-start-time-end-time-std-time-ml-1524773121"></a>
### elapsed

```ml
function elapsed(start_time, end_time)
```

Compute elapsed milliseconds between two tick readings.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `start_time` | `dynamic` | — | Value supplied for `start_time`. |
| `end_time` | `dynamic` | — | Value supplied for `end_time`. |


Source: `std/time.ml:323`

<a id="function-function-std-time-formatduration-function-formatduration-ms-std-time-ml-951102696"></a>
### formatDuration

```ml
function formatDuration(ms)
```

Format a duration in milliseconds into a readable string.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `ms` | `dynamic` | — | Value supplied for `ms`. |


Source: `std/time.ml:1045`

<a id="constant-constant-std-time-max-portable-sleep-ms-const-max-portable-sleep-ms-2147483647-std-time-ml-175303927"></a>
### MAX_PORTABLE_SLEEP_MS

```ml
const MAX_PORTABLE_SLEEP_MS = 2147483647
```

Track the max portable sleep ms value used by this standard-library module.


Source: `std/time.ml:26`

<a id="function-function-std-time-sleep-function-sleep-ms-std-time-ml-2137114338"></a>
### sleep

```ml
function sleep(ms)
```

Sleep for a number of milliseconds.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `ms` | `dynamic` | — | Value supplied for `ms`. |


Source: `std/time.ml:295`

- [std.time.SystemTime](Type-std-time-systemtime-224467961.md) — struct
<a id="constant-constant-std-time-systemtime-size-const-systemtime-size-16-std-time-ml-2026073104"></a>
### SYSTEMTIME_SIZE

```ml
const SYSTEMTIME_SIZE = 16
```

SYSTEMTIME decoding helpers (used for WinAPI GetLocalTime/GetSystemTime).


Source: `std/time.ml:44`

<a id="function-function-std-time-ticks-function-ticks-std-time-ml-23716212"></a>
### ticks

```ml
function ticks()
```

Read monotonic milliseconds since system start (no wall-clock).


Source: `std/time.ml:288`

- [std.time.Time](Type-std-time-time-366461368.md) — struct
<a id="constant-constant-std-time-time-err-const-time-err-300-std-time-ml-448941524"></a>
### TIME_ERR

```ml
const TIME_ERR = 300
```

Monotonic timing, durations and calendar conversion on Windows and Linux.


Source: `std/time.ml:24`

<a id="constant-constant-std-time-unix-epoch-ordinal-const-unix-epoch-ordinal-719162-std-time-ml-1386203359"></a>
### UNIX_EPOCH_ORDINAL

```ml
const UNIX_EPOCH_ORDINAL = 719162
```

Ordinal day count for 1970-01-01, with 0001-01-01 as day 0.


Source: `std/time.ml:366`

<a id="namespace-namespace-std-time-win32-namespace-win32-std-time-ml-2147453897"></a>
### win32

```ml
namespace win32
```

------------------------------------------------------------ Platform-native time helpers. ------------------------------------------------------------


Source: `std/time.ml:109`

<a id="function-function-std-time-win32-getlocaltime-function-getlocaltime-std-time-ml-2017549839"></a>
### GetLocalTime

```ml
function GetLocalTime()
```

Get local wall-clock time via Win32 GetLocalTime.


Source: `std/time.ml:145`

<a id="function-function-std-time-win32-getsystemtime-function-getsystemtime-std-time-ml-1514521483"></a>
### GetSystemTime

```ml
function GetSystemTime()
```

Get UTC wall-clock time via Win32 GetSystemTime.


Source: `std/time.ml:152`

- [std.time.win32.SYSTEMTIME](Type-std-time-win32-systemtime-704459330.md) — extern_struct
