/*
Copyright 2026 Nils Kopal

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Repeated cached, positional I/O isolates per-call buffer and FFI overhead.
import std.fs as fs
import std.io.file as file
import std.process as process
import std.time as time

function measure(handle, pageSize, iterations)
  source = bytes(pageSize, 0x5A)
  destination = bytes(pageSize, 0)
  started = time.ticks()
  for i = 0 to iterations - 1
    if file.writeAt(handle, 0, source, 0, pageSize) != pageSize then return false end if
  end for
  writeMs = time.ticks() - started
  started = time.ticks()
  for i = 0 to iterations - 1
    if file.readAt(handle, 0, destination, 0, pageSize) != pageSize then return false end if
  end for
  readMs = time.ticks() - started
  if destination != source then return false end if
  print "page_bytes=" + pageSize + " iterations=" + iterations + " write_ms=" + writeMs + " read_ms=" + readMs
  return true
end function

function main(args)
  path = "file-io-bench-" + process.id() + ".bin"
  handle = file.create(path)
  if typeof(handle) == "error" then return 1 end if
  ok = measure(handle, 4096, 80000)
  if ok then ok = measure(handle, 65536, 10000) end if
  if file.close(handle) != true then return 2 end if
  if fs.delete(path) != true then return 3 end if
  if not ok then return 4 end if
  return 0
end function
