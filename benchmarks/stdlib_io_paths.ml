/*
Copyright 2026 Nils Kopal

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Repeated appends and whole-file reads expose avoidable copying in std.fs.
import std.fs as fs
import std.process as process
import std.time as time

function main(args)
  path = "stdlib-io-paths-" + process.id() + ".bin"
  chunk = bytes(4096, 0x5A)
  if fs.delete(path) != true then return 1 end if

  started = time.ticks()
  for i = 0 to 255
    if fs.appendAllBytes(path, chunk) != true then return 2 end if
  end for
  appendMs = time.ticks() - started

  started = time.ticks()
  for i = 0 to 499
    content = fs.readAllBytes(path)
    if typeof(content) != "bytes" or len(content) != 1048576 or content[0] != 0x5A or content[1048575] != 0x5A then return 3 end if
  end for
  readMs = time.ticks() - started

  if fs.delete(path) != true then return 4 end if
  print "append_calls=256 final_bytes=1048576 append_ms=" + appendMs + " read_calls=500 read_ms=" + readMs
  return 0
end function
