/*
Copyright 2026 Nils Kopal

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package std.time
import std.string as s
import std.fmt as fmt

const TIME_ERR = 300

function _timeErr(msg)
  return error(TIME_ERR, msg)
end function

/*
std.time

Native Win32 time helpers + small calendar/date/time library.
- ticks(): monotonic milliseconds since boot
- sleep(ms): sleep for a number of milliseconds
- date/clock/datetime: parsing, formatting, arithmetic
*/

// ------------------------------------------------------------
// SYSTEMTIME decoding helpers (used for WinAPI GetLocalTime/GetSystemTime)
// ------------------------------------------------------------

const SYSTEMTIME_SIZE = 16

struct SystemTime
  year,
  month,
  dayOfWeek,
  day,
  hour,
  minute,
  second,
  millisecond,
end struct

function _u16le(b, off)
  /*
  read an unsigned 16-bit little-endian value from a byte buffer
  input: bytes b, int off
  returns: int value
  */
  return b[off] + b[off + 1] * 256
end function

function _decodeSystemTime(buf)
  /*
  decode a Win32 SYSTEMTIME buffer into a std.time.SystemTime struct
  input: bytes buf (length >= 16)
  returns: SystemTime value (or void on invalid input)
  */
  if typeof(buf) != "bytes" then
    return
  end if
  if len(buf) < 16 then
    return
  end if

  return std.time.SystemTime(
  std.time._u16le(buf, 0),
  std.time._u16le(buf, 2),
  std.time._u16le(buf, 4),
  std.time._u16le(buf, 6),
  std.time._u16le(buf, 8),
  std.time._u16le(buf, 10),
  std.time._u16le(buf, 12),
  std.time._u16le(buf, 14)
)
end function

// ------------------------------------------------------------
// Win32 time helpers (native compiler only)
// ------------------------------------------------------------

namespace win32
  // SYSTEMTIME layout for GetLocalTime/GetSystemTime
  extern struct SYSTEMTIME
    year as u16
    month as u16
    dayOfWeek as u16
    day as u16
    hour as u16
    minute as u16
    second as u16
    millisecond as u16
  end struct

  // Use the 64-bit tick counter to avoid 32-bit wrap-around.
  extern function GetTickCount64() from "kernel32.dll" returns u64
  extern function Sleep(dwMilliseconds as u32) from "kernel32.dll" returns void

  // Wall-clock (local / UTC)
  // WinAPI uses an out-pointer. The MiniLang stdlib provides 0-arg wrappers that
  // return a decoded std.time.SystemTime value.
  extern function _GetLocalTime(outBuf as bytes) from "kernel32.dll" symbol "GetLocalTime" returns void
  extern function _GetSystemTime(outBuf as bytes) from "kernel32.dll" symbol "GetSystemTime" returns void

  /*
  get local wall-clock time via Win32 GetLocalTime
  input: none
  returns: SystemTime value (or void on failure)
  */
  function GetLocalTime()
    buf = bytes(std.time.SYSTEMTIME_SIZE)
    _GetLocalTime(buf)
    return std.time._decodeSystemTime(buf)
  end function

  /*
  get UTC wall-clock time via Win32 GetSystemTime
  input: none
  returns: SystemTime value (or void on failure)
  */
  function GetSystemTime()
    buf = bytes(std.time.SYSTEMTIME_SIZE)
    _GetSystemTime(buf)
    return std.time._decodeSystemTime(buf)
  end function
end namespace

/*
read monotonic milliseconds since system start (no wall-clock)
input: none
returns: int milliseconds (u64)
*/
function ticks()
  // Milliseconds since system start (monotonic). Returns an int-compatible u64.
  return std.time.win32.GetTickCount64()
end function

/*
sleep for a number of milliseconds
input: int ms
returns: void
*/
function sleep(ms)
  // Sleeps for `ms` milliseconds.
  // Negative/invalid -> no-op.
  if typeof(ms) != "int" then
    return
  end if
  if ms < 0 then
    return
  end if
  std.time.win32.Sleep(ms)
end function

/*
compute elapsed milliseconds between two tick readings
input: int start_time, int end_time
returns: int elapsedMs (or void on invalid input)
*/
function elapsed(start_time, end_time)
  // Returns elapsed milliseconds between two tick readings.
  // With GetTickCount64, wrap-around is not a practical concern.
  if typeof(start_time) != "int" or typeof(end_time) != "int" then
    return
  end if
  if end_time < start_time then
    return
  end if
  return end_time - start_time
end function

// ------------------------------------------------------------
// Calendar date/time (proleptic Gregorian, year 1..9999)
// ------------------------------------------------------------

struct Date
  year,
  month,
  day,
end struct

struct Time
  hour,
  minute,
  second,
  millisecond,
end struct

struct DateTime
  date,
  time,
end struct

// Ordinal day count for 1970-01-01, with 0001-01-01 as day 0.
const UNIX_EPOCH_ORDINAL = 719162

function _toInt(x)
  /*
  convert a value to int if possible
  input: any x
  returns: int value (or void if conversion fails)
  */
  if typeof(x) == "int" then
    return x
  end if
  if typeof(x) == "string" then
    n = toNumber(x)
    if typeof(n) != "int" then
      return
    end if
    return n
  end if
  return
end function

function _idiv(a, b)
  /*
  integer floor division for ints (using '%' semantics)
  input: int a, int b
  returns: int q = floor(a/b) (or void on invalid input)
  */
  if typeof(a) != "int" or typeof(b) != "int" then
    return
  end if
  if b == 0 then
    return
  end if
  rem = a % b
  return (a - rem) / b
end function

/*
format an int as two digits (zero padded)
input: int n
returns: string text
*/
function _pad2(n)
  return fmt.padLeft("" + n, 2, "0")
end function

/*
format an int as three digits (zero padded)
input: int n
returns: string text
*/
function _pad3(n)
  return fmt.padLeft("" + n, 3, "0")
end function

/*
format an int as four digits (zero padded)
input: int n
returns: string text
*/
function _pad4(n)
  return fmt.padLeft("" + n, 4, "0")
end function

namespace date
  /*
  check if a year is a leap year (Gregorian rules)
  input: int year
  returns: bool isLeap
  */
  function isLeapYear(year)
    if typeof(year) != "int" then
      return false
    end if
    if (year % 4) != 0 then
      return false
    end if
    if (year % 100) != 0 then
      return true
    end if
    return (year % 400) == 0
  end function

  /*
  number of days in a month for a given year
  input: int year, int month (1..12)
  returns: int days (or void on invalid input)
  */
  function daysInMonth(year, month)
    if typeof(year) != "int" or typeof(month) != "int" then
      return
    end if
    if month < 1 or month > 12 then
      return
    end if

    if month == 1 then return 31 end if
    if month == 2 then
      if std.time.date.isLeapYear(year) then return 29 end if
      return 28
    end if
    if month == 3 then return 31 end if
    if month == 4 then return 30 end if
    if month == 5 then return 31 end if
    if month == 6 then return 30 end if
    if month == 7 then return 31 end if
    if month == 8 then return 31 end if
    if month == 9 then return 30 end if
    if month == 10 then return 31 end if
    if month == 11 then return 30 end if
    return 31 // month == 12
  end function

  /*
  validate a date triple (year, month, day)
  input: int year, int month, int day
  returns: bool valid
  */
  function isValidYMD(year, month, day)
    if typeof(year) != "int" or typeof(month) != "int" or typeof(day) != "int" then
      return false
    end if
    if year < 1 or year > 9999 then
      return false
    end if

    dim = std.time.date.daysInMonth(year, month)
    if typeof(dim) == "void" then
      return false
    end if

    return day >= 1 and day <= dim
  end function

  /*
  validate a Date struct
  input: Date d
  returns: bool valid
  */
  function isValid(d)
    return std.time.date.isValidYMD(d.year, d.month, d.day)
  end function

  /*
  convert a Date to an ordinal day count
  input: Date d
  returns: int daysSince00010101 (or void on invalid input)
  */
  function toOrdinal(d)
    // Days since 0001-01-01 (day 0). Valid for year 1..9999.
    if not std.time.date.isValid(d) then
      return
    end if

    y = d.year
    m = d.month
    dd = d.day

    y1 = y - 1
    leap = std.time._idiv(y1, 4) - std.time._idiv(y1, 100) + std.time._idiv(y1, 400)
    days = y1 * 365 + leap

    // Days before month in a common year. idx: month-1
    cum =[0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334]
    days = days + cum[m - 1]

    if m > 2 and std.time.date.isLeapYear(y) then
      days = days + 1
    end if

    return days +(dd - 1)
  end function

  /*
  inverse of toOrdinal
  input: int daysSince00010101
  returns: Date value (or void on invalid input)
  */
  function fromOrdinal(days)
    // Inverse of toOrdinal. `days` is days since 0001-01-01 (day 0).
    if typeof(days) != "int" then
      return
    end if
    if days < 0 then
      return
    end if

    n = days
    y = 1

    // 400-year cycles
    n400 = std.time._idiv(n, 146097)
    y = y +(n400 * 400)
    n = n -(n400 * 146097)

    // 100-year cycles (max 3)
    n100 = std.time._idiv(n, 36524)
    if n100 == 4 then n100 = 3 end if
    y = y +(n100 * 100)
    n = n -(n100 * 36524)

    // 4-year cycles
    n4 = std.time._idiv(n, 1461)
    y = y +(n4 * 4)
    n = n -(n4 * 1461)

    // 1-year cycles (max 3)
    n1 = std.time._idiv(n, 365)
    if n1 == 4 then n1 = 3 end if
    y = y + n1
    n = n -(n1 * 365)

    if y < 1 or y > 9999 then
      return
    end if

    doy = n // 0..365
    m = 1
    while m <= 12
      dim = std.time.date.daysInMonth(y, m)
      if doy < dim then
        break
      end if
      doy = doy - dim
      m = m + 1
    end while

    return std.time.Date(y, m, doy + 1)
  end function

  /*
  compare two dates
  input: Date a, Date b
  returns: int (-1, 0, 1)
  */
  function compare(a, b)
    if a.year < b.year then return -1 end if
    if a.year > b.year then return 1 end if
    if a.month < b.month then return -1 end if
    if a.month > b.month then return 1 end if
    if a.day < b.day then return -1 end if
    if a.day > b.day then return 1 end if
    return 0
  end function

  /*
  add days to a date
  input: Date d, int deltaDays
  returns: Date newDate (or void on invalid input)
  */
  function addDays(d, delta)
    if typeof(delta) != "int" then
      return
    end if
    ord = std.time.date.toOrdinal(d)
    if typeof(ord) == "void" then
      return
    end if
    return std.time.date.fromOrdinal(ord + delta)
  end function

  /*
  difference in days between two dates
  input: Date a, Date b
  returns: int (b - a) in days (or void on invalid input)
  */
  function diffDays(a, b)
    oa = std.time.date.toOrdinal(a)
    ob = std.time.date.toOrdinal(b)
    if typeof(oa) == "void" or typeof(ob) == "void" then
      return
    end if
    return ob - oa
  end function

  /*
  compute day of week for a date
  input: Date d
  returns: int (Monday=1 .. Sunday=7) (or void on invalid input)
  */
  function dayOfWeek(d)
    // Monday=1 .. Sunday=7
    ord = std.time.date.toOrdinal(d)
    if typeof(ord) == "void" then
      return
    end if
    // 0001-01-01 is Monday => ord=0 => 1
    return ((ord % 7) + 1)
  end function

  /*
  format date as YYYY-MM-DD
  input: Date d
  returns: string (or void on invalid input)
  */
  function toString(d)
    if not std.time.date.isValid(d) then
      return
    end if
    return std.time._pad4(d.year) + "-" + std.time._pad2(d.month) + "-" + std.time._pad2(d.day)
  end function

  /*
  parse a date in the form YYYY-MM-DD
  input: string text
  returns: Result<Date, string>
  */
  function parse(text)
    // Returns Result<Date, string>
    if typeof(text) != "string" then
      return _timeErr("date.parse: expected string")
    end if

    s0 = s.trim(text)
    parts = s.split(s0, "-")
    if typeof(parts) == "void" or len(parts) != 3 then
      return _timeErr("date.parse: expected YYYY-MM-DD")
    end if

    yy = std.time._toInt(parts[0])
    mm = std.time._toInt(parts[1])
    dd = std.time._toInt(parts[2])

    if typeof(yy) == "void" or typeof(mm) == "void" or typeof(dd) == "void" then
      return _timeErr("date.parse: invalid number")
    end if

    if not std.time.date.isValidYMD(yy, mm, dd) then
      return _timeErr("date.parse: invalid date")
    end if

    return std.time.Date(yy, mm, dd)
  end function
end namespace

namespace clock
  /*
  validate a time quadruple (hour, minute, second, millisecond)
  input: int hour, int minute, int second, int millisecond
  returns: bool valid
  */
  function isValidHMSM(h, m, s0, ms)
    if typeof(h) != "int" or typeof(m) != "int" or typeof(s0) != "int" or typeof(ms) != "int" then
      return false
    end if
    if h < 0 or h > 23 then return false end if
    if m < 0 or m > 59 then return false end if
    if s0 < 0 or s0 > 59 then return false end if
    if ms < 0 or ms > 999 then return false end if
    return true
  end function

  /*
  validate a Time struct
  input: Time t
  returns: bool valid
  */
  function isValid(t)
    return std.time.clock.isValidHMSM(t.hour, t.minute, t.second, t.millisecond)
  end function

  /*
  compare two times
  input: Time a, Time b
  returns: int (-1, 0, 1)
  */
  function compare(a, b)
    if a.hour < b.hour then return -1 end if
    if a.hour > b.hour then return 1 end if
    if a.minute < b.minute then return -1 end if
    if a.minute > b.minute then return 1 end if
    if a.second < b.second then return -1 end if
    if a.second > b.second then return 1 end if
    if a.millisecond < b.millisecond then return -1 end if
    if a.millisecond > b.millisecond then return 1 end if
    return 0
  end function

  /*
  convert a Time into milliseconds since 00:00:00.000
  input: Time t
  returns: int msOfDay (or void on invalid input)
  */
  function toMillis(t)
    if not std.time.clock.isValid(t) then
      return
    end if
    return (((t.hour * 60 + t.minute) * 60 + t.second) * 1000) + t.millisecond
  end function

  /*
  convert milliseconds since 00:00 into a Time
  input: int msOfDay (0..86399999)
  returns: Time value (or void on invalid input)
  */
  function fromMillis(ms)
    if typeof(ms) != "int" then
      return
    end if
    if ms < 0 or ms >= 86400000 then
      return
    end if

    h = std.time._idiv(ms, 3600000)
    rem = ms % 3600000
    mi = std.time._idiv(rem, 60000)
    rem2 = rem % 60000
    ss = std.time._idiv(rem2, 1000)
    mss = rem2 % 1000

    return std.time.Time(h, mi, ss, mss)
  end function

  /*
  add milliseconds to a time (wraps within 24h)
  input: Time t, int deltaMs
  returns: Time newTime (or void on invalid input)
  */
  function addMillis(t, delta)
    if typeof(delta) != "int" then
      return
    end if
    base = std.time.clock.toMillis(t)
    if typeof(base) == "void" then
      return
    end if

    total = base + delta
    total = total % 86400000
    if total < 0 then
      total = total + 86400000
    end if

    return std.time.clock.fromMillis(total)
  end function

  /*
  format time as HH:MM:SS.mmm
  input: Time t
  returns: string (or void on invalid input)
  */
  function toString(t)
    if not std.time.clock.isValid(t) then
      return
    end if
    return std.time._pad2(t.hour) + ":" + std.time._pad2(t.minute) + ":" + std.time._pad2(t.second) + "." + std.time._pad3(t.millisecond)
  end function

  /*
  parse time in the form HH:MM or HH:MM:SS[.mmm]
  input: string text
  returns: Result<Time, string>
  */
  function parse(text)
    // Returns Result<Time, string>
    if typeof(text) != "string" then
      return _timeErr("time.parse: expected string")
    end if

    s0 = s.trim(text)
    parts = s.split(s0, ":")
    if typeof(parts) == "void" or(len(parts) != 2 and len(parts) != 3) then
      return _timeErr("time.parse: expected HH:MM or HH:MM:SS[.mmm]")
    end if

    hh = std.time._toInt(parts[0])
    mm = std.time._toInt(parts[1])
    ss = 0
    ms = 0

    if typeof(hh) == "void" or typeof(mm) == "void" then
      return _timeErr("time.parse: invalid number")
    end if

    if len(parts) == 3 then
      secPart = parts[2]
      dot = s.indexOf(secPart, ".", 0)
      if typeof(dot) == "void" then
        return _timeErr("time.parse: internal error")
      end if

      if dot >= 0 then
        left = s.substr(secPart, 0, dot)
        right = s.substr(secPart, dot + 1, len(secPart) -(dot + 1))
        ss = std.time._toInt(left)
        ms = std.time._toInt(right)
        if typeof(ss) == "void" or typeof(ms) == "void" then
          return _timeErr("time.parse: invalid number")
        end if
      else
        ss = std.time._toInt(secPart)
        if typeof(ss) == "void" then
          return _timeErr("time.parse: invalid number")
        end if
      end if
    end if

    if not std.time.clock.isValidHMSM(hh, mm, ss, ms) then
      return _timeErr("time.parse: invalid time")
    end if

    return std.time.Time(hh, mm, ss, ms)
  end function
end namespace

namespace datetime
  /*
  validate a DateTime struct
  input: DateTime dt
  returns: bool valid
  */
  function isValid(dt)
    return std.time.date.isValid(dt.date) and std.time.clock.isValid(dt.time)
  end function

  /*
  compare two date-times
  input: DateTime a, DateTime b
  returns: int (-1, 0, 1)
  */
  function compare(a, b)
    c = std.time.date.compare(a.date, b.date)
    if c != 0 then
      return c
    end if
    return std.time.clock.compare(a.time, b.time)
  end function

  /*
  convert a DateTime to milliseconds since 0001-01-01 00:00:00.000
  input: DateTime dt
  returns: int ms (or void on invalid input)
  */
  function toMillis(dt)
    if not std.time.datetime.isValid(dt) then
      return
    end if

    day_ms = 86400000
    ord = std.time.date.toOrdinal(dt.date)
    ms = std.time.clock.toMillis(dt.time)

    if typeof(ord) == "void" or typeof(ms) == "void" then
      return
    end if

    return (ord * day_ms) + ms
  end function

  /*
  add milliseconds to a DateTime
  input: DateTime dt, int deltaMs
  returns: DateTime newDateTime (or void on invalid input)
  */
  function addMillis(dt, delta)
    if typeof(delta) != "int" then
      return
    end if
    if not std.time.datetime.isValid(dt) then
      return
    end if

    day_ms = 86400000
    base = std.time.clock.toMillis(dt.time)
    if typeof(base) == "void" then
      return
    end if

    total = base + delta
    carry = std.time._idiv(total, day_ms)
    rem = total % day_ms
    if rem < 0 then
      rem = rem + day_ms
      carry = carry - 1
    end if

    nd = std.time.date.addDays(dt.date, carry)
    if typeof(nd) == "void" then
      return
    end if

    nt = std.time.clock.fromMillis(rem)
    return std.time.DateTime(nd, nt)
  end function

  /*
  add whole days to a DateTime (keeps clock time)
  input: DateTime dt, int deltaDays
  returns: DateTime newDateTime (or void on invalid input)
  */
  function addDays(dt, deltaDays)
    if typeof(deltaDays) != "int" then
      return
    end if
    if not std.time.datetime.isValid(dt) then
      return
    end if
    nd = std.time.date.addDays(dt.date, deltaDays)
    if typeof(nd) == "void" then
      return
    end if
    return std.time.DateTime(nd, dt.time)
  end function

  /*
  format a DateTime as "YYYY-MM-DD HH:MM:SS.mmm"
  input: DateTime dt
  returns: string (or void on invalid input)
  */
  function toString(dt)
    if not std.time.datetime.isValid(dt) then
      return
    end if
    return std.time.date.toString(dt.date) + " " + std.time.clock.toString(dt.time)
  end function

  /*
  parse a DateTime in the form "YYYY-MM-DD HH:MM:SS[.mmm]" (also accepts 'T')
  input: string text
  returns: Result<DateTime, string>
  */
  function parse(text)
    // Returns Result<DateTime, string>
    if typeof(text) != "string" then
      return _timeErr("datetime.parse: expected string")
    end if

    s0 = s.trim(text)

    // Accept "YYYY-MM-DD HH:MM:SS" or "YYYY-MM-DDTHH:MM:SS"
    sep = " "
    if s.contains(s0, "T") then
      sep = "T"
    end if

    parts = s.split(s0, sep)
    if typeof(parts) == "void" or len(parts) != 2 then
      return _timeErr("datetime.parse: expected 'YYYY-MM-DD HH:MM:SS[.mmm]'")
    end if

    dr = std.time.date.parse(parts[0])
    if typeof(dr) == "error" then
      return _timeErr("datetime.parse: " + dr.message)
    end if

    tr = std.time.clock.parse(parts[1])
    if typeof(tr) == "error" then
      return _timeErr("datetime.parse: " + tr.message)
    end if

    return std.time.DateTime(dr, tr)
  end function

  /*
  convert Win32 SYSTEMTIME to a DateTime
  input: SystemTime st
  returns: DateTime (or void on invalid input)
  */
  function fromSystemTime(st)
    // Convert Win32 SYSTEMTIME -> DateTime (returns void on invalid)
    if typeof(st) == "void" then
      return
    end if

    y = st.year
    mo = st.month
    da = st.day
    hh = st.hour
    mi = st.minute
    ss = st.second
    ms = st.millisecond

    if typeof(y) != "int" or typeof(mo) != "int" or typeof(da) != "int" then
      return
    end if
    if typeof(hh) != "int" or typeof(mi) != "int" or typeof(ss) != "int" or typeof(ms) != "int" then
      return
    end if

    d = std.time.Date(y, mo, da)
    t0 = std.time.Time(hh, mi, ss, ms)
    dt = std.time.DateTime(d, t0)

    if not std.time.datetime.isValid(dt) then
      return
    end if
    return dt
  end function

  /*
  current local wall-clock DateTime
  input: none
  returns: DateTime (or void on failure)
  */
  function nowLocal()
    st = std.time.win32.GetLocalTime()
    return std.time.datetime.fromSystemTime(st)
  end function

  /*
  current UTC wall-clock DateTime
  input: none
  returns: DateTime (or void on failure)
  */
  function nowUtc()
    st = std.time.win32.GetSystemTime()
    return std.time.datetime.fromSystemTime(st)
  end function

  /*
  convert a DateTime to Unix milliseconds since 1970-01-01T00:00:00Z
  input: DateTime dt
  returns: int unixMs (or void on invalid input)
  */
  function toUnixMillis(dt)
    ms = std.time.datetime.toMillis(dt)
    if typeof(ms) == "void" then
      return
    end if
    return ms -(std.time.UNIX_EPOCH_ORDINAL * 86400000)
  end function

  /*
  convert Unix milliseconds since 1970-01-01T00:00:00Z to a DateTime
  input: int unixMs
  returns: DateTime (or void on invalid input)
  */
  function fromUnixMillis(unixMs)
    if typeof(unixMs) != "int" then
      return
    end if

    total = unixMs +(std.time.UNIX_EPOCH_ORDINAL * 86400000)
    day_ms = 86400000
    days = std.time._idiv(total, day_ms)
    rem = total % day_ms
    if rem < 0 then
      rem = rem + day_ms
      days = days - 1
    end if

    if typeof(days) == "void" then
      return
    end if

    d = std.time.date.fromOrdinal(days)
    t0 = std.time.clock.fromMillis(rem)
    if typeof(d) == "void" or typeof(t0) == "void" then
      return
    end if
    return std.time.DateTime(d, t0)
  end function

  /*
  current Unix milliseconds based on UTC time
  input: none
  returns: int unixMs (or void on failure)
  */
  function nowUnixMillisUtc()
    dt = std.time.datetime.nowUtc()
    if typeof(dt) == "void" then
      return
    end if
    return std.time.datetime.toUnixMillis(dt)
  end function
end namespace

/*
format a duration in milliseconds into a readable string
input: int ms
returns: string text (e.g., "3s 120ms", "2m 05s", "1h 02m 03s")
*/
function formatDuration(ms)
  if typeof(ms) != "int" then
    return
  end if

  sign = ""
  t = ms
  if t < 0 then
    sign = "-"
    t = -t
  end if

  if t < 1000 then
    return sign +("" + t) + "ms"
  end if

  sec = std.time._idiv(t, 1000)
  remMs = t % 1000
  if sec < 60 then
    return sign +("" + sec) + "s " +("" + remMs) + "ms"
  end if

  min = std.time._idiv(sec, 60)
  remSec = sec % 60
  if min < 60 then
    return sign +("" + min) + "m " + std.time._pad2(remSec) + "s"
  end if

  hr = std.time._idiv(min, 60)
  remMin = min % 60
  return sign +("" + hr) + "h " + std.time._pad2(remMin) + "m " + std.time._pad2(remSec) + "s"
end function

/*
format a Date as a string (YYYY-MM-DD)
input: Date d
returns: string text (or void on invalid input)
*/
function dateToString(d)
  return std.time.date.toString(d)
end function

/*
format a Time as a string (HH:MM:SS.mmm)
input: Time t
returns: string text (or void on invalid input)
*/
function clockToString(t)
  return std.time.clock.toString(t)
end function

/*
format a DateTime as a string (YYYY-MM-DD HH:MM:SS.mmm)
input: DateTime dt
returns: string text (or void on invalid input)
*/
function datetimeToString(dt)
  return std.time.datetime.toString(dt)
end function
