/*
Copyright 2026 Nils Kopal

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Fixture used by compression_interop.py to check liblz4 compatibility.
import std.compress as compression
import std.compress.lz4 as lz4
import std.fs as fs

function main(args)
  if len(args) != 3 then return 2 end if
  raw = fs.readAllBytes(args[1])
  if typeof(raw) != "bytes" then return 3 end if
  if args[0] == "encode" then
    encoded = lz4.encode(raw)
    if typeof(encoded) != "bytes" then return 4 end if
    result = fs.writeAllBytes(args[2], encoded)
    if typeof(result) == "error" then return 5 end if
    print "[OK] LZ4 encode fixture"
    return 0
  end if
  if args[0] == "decode" then
    encoded = fs.readAllBytes(args[2])
    if typeof(encoded) != "bytes" then return 6 end if
    decoded = lz4.decode(encoded, len(raw))
    if typeof(decoded) != "bytes" or decoded != raw then return 7 end if
    print "[OK] LZ4 decode fixture"
    return 0
  end if
  if args[0] == "pack" then
    packed = compression.fast(raw)
    if typeof(packed) != "bytes" then return 8 end if
    result = fs.writeAllBytes(args[2], packed)
    if typeof(result) == "error" then return 9 end if
    print "[OK] portable compression pack"
    return 0
  end if
  if args[0] == "unpack" then
    packed = fs.readAllBytes(args[2])
    if typeof(packed) != "bytes" then return 10 end if
    decoded = compression.decompress(packed, len(raw))
    if typeof(decoded) != "bytes" or decoded != raw then return 11 end if
    print "[OK] portable compression unpack"
    return 0
  end if
  return 2
end function
