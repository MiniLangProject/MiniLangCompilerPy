/// End-to-end allocation/copy/fill/CRC controls. Base64 remains a baseline.
import std.encoding.base64 as b64
import std.checksum.crc32 as crc
#if TARGET_OS == "windows"
extern function counter(output as bytes) from "kernel32.dll" symbol "QueryPerformanceCounter" returns i32
extern function frequency(output as bytes) from "kernel32.dll" symbol "QueryPerformanceFrequency" returns i32
#else
extern function counter(clockId as i32, output as bytes) from "libc.so.6" symbol "clock_gettime" returns i32
#endif

function readCounter(buffer, offset as int) returns int
  value = 0
  for i = 0 to 7 value = value | (buffer[offset + i] << (8 * i)) end for
  return value
end function

function ticks(buffer) returns int
#if TARGET_OS == "windows"
  counter(buffer)
  return readCounter(buffer, 0)
#else
  counter(1, buffer)
  return readCounter(buffer, 0) * 1000000000 + readCounter(buffer, 8)
#endif
end function

function main(args)
  mode = "crc"
  if len(args) > 0 then mode = args[0] end if
  source = bytes(1048581, 90)
  base64Input = bytes(262144, 71)
  encoded = b64.toBase64(base64Input)
  timer = bytes(16)
  ticksPerSecond = 1000000000
#if TARGET_OS == "windows"
  frequency(timer)
  ticksPerSecond = readCounter(timer, 0)
#endif
  gc_collect()
  gc_set_limit(0)
  before = heap_bytes_used()
  started = ticks(timer)
  checksum = 0
  if mode == "crc" then
    for i = 0 to 1023 checksum += crc.computeRange(source, 3, 131072) end for
  else if mode == "copy" then
    for i = 0 to 127
      result = slice(source, 3, 1048576)
      checksum += result[len(result) - 1]
    end for
  else if mode == "fill" then
    for i = 0 to 127
      result = bytes(1048576, 165)
      checksum += result[len(result) - 1]
    end for
  else if mode == "copy-small" then
    for i = 0 to 199999
      result = slice(source, 3, 63)
      checksum += result[62]
    end for
  else if mode == "fill-small" then
    for i = 0 to 199999
      result = bytes(128, 165)
      checksum += result[127]
    end for
  else if mode == "base64-encode" then
    for i = 0 to 15
      result = b64.toBase64(base64Input)
      checksum += len(result)
    end for
  else if mode == "base64-decode" then
    for i = 0 to 15
      result = b64.fromBase64(encoded)
      checksum += len(result)
    end for
  else
    return 1
  end if
  elapsed = (ticks(timer) - started) * 1000 / ticksPerSecond
  allocated = heap_bytes_used() - before
  print mode + " ms=" + elapsed + " bytes=" + allocated + " checksum=" + checksum
end function
