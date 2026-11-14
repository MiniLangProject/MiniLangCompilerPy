// Compare the method facade with the existing positional file function.
import std.fs as fs
import std.io.file as file
import std.process as process
import std.time as time

const ITERATIONS = 50000
const BLOCK_SIZE = 4096

function rawReads(handle, buffer)
  start = time.ticks()
  total = 0
  for i = 0 to ITERATIONS - 1
    count = file.readAt(handle, 0, buffer, 0, BLOCK_SIZE)
    if count != BLOCK_SIZE then return error(1, "raw read failed") end if
    total = total + count
  end for
  return [time.ticks() - start, total]
end function

function methodReads(handle, buffer)
  start = time.ticks()
  total = 0
  for i = 0 to ITERATIONS - 1
    count = handle.readAt(0, buffer, 0, BLOCK_SIZE)
    if count != BLOCK_SIZE then return error(1, "method read failed") end if
    total = total + count
  end for
  return [time.ticks() - start, total]
end function

function main(args)
  path = "stdlib-oop-bench-" + process.id() + ".bin"
#if TARGET_OS == "linux"
  // WSL's /mnt filesystem measures DrvFS overhead rather than method calls.
  path = "/tmp/" + path
#endif
  handle = file.FileHandle.create(path)
  if typeof(handle) == "error" then return 1 end if
  payload = bytes(BLOCK_SIZE, 0x5A)
  if handle.writeAt(0, payload, 0, BLOCK_SIZE) != BLOCK_SIZE then return 2 end if
  buffer = bytes(BLOCK_SIZE, 0)
  warm = rawReads(handle, buffer)
  if typeof(warm) == "error" then return 3 end if
  raw1 = rawReads(handle, buffer)
  method1 = methodReads(handle, buffer)
  method2 = methodReads(handle, buffer)
  raw2 = rawReads(handle, buffer)
  if typeof(raw1) == "error" or typeof(method1) == "error" or typeof(method2) == "error" or typeof(raw2) == "error" then return 4 end if
  expected = ITERATIONS * BLOCK_SIZE
  if raw1[1] != expected or method1[1] != expected or method2[1] != expected or raw2[1] != expected then return 5 end if
  handle.close()
  fs.delete(path)
  print "raw_ms=" + raw1[0] + "," + raw2[0] + " method_ms=" + method1[0] + "," + method2[0]
  return 0
end function
