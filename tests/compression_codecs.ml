/*
Copyright 2026 Nils Kopal

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Portable compression vectors, boundaries and hostile-input tests.
import std.assert as t
import std.compress as compression
import std.compress.lz4 as lz4
import std.compress.rle as rle

ok = true

function checkEq(actual, expected, label)
  global ok
  if not t.assertEq(actual, expected, label) then ok = false end if
end function

function checkTrue(value, label)
  global ok
  if not t.assertTrue(value, label) then ok = false end if
end function

function randomish(n)
  result = bytes(n, 0)
  state = 0x12345678
  i = 0
  while i < n
    state = (state ^ (state << 13)) & 0xFFFFFFFF
    state = (state ^ (state >> 17)) & 0xFFFFFFFF
    state = (state ^ (state << 5)) & 0xFFFFFFFF
    result[i] = state & 255
    i = i + 1
  end while
  return result
end function

function byteSequence(n)
  result = bytes(n, 0)
  i = 0
  while i < n
    result[i] = ((i * 73) ^ (i >> 3)) & 255
    i = i + 1
  end while
  return result
end function

function checkRoundtrip(input, label)
  rawLz4 = lz4.encode(input)
  checkEq(typeof(rawLz4), "bytes", label + " LZ4 encode")
  checkEq(lz4.decode(rawLz4, len(input)), input, label + " LZ4 decode")
  rawRle = rle.encode(input)
  checkEq(typeof(rawRle), "bytes", label + " RLE encode")
  checkEq(rle.decode(rawRle, len(input)), input, label + " RLE decode")
  fast = compression.fast(input)
  compact = compression.compact(input)
  checkEq(compression.decodedSize(fast), len(input), label + " fast size")
  checkEq(compression.decompress(fast, len(input)), input, label + " fast decode")
  checkEq(compression.decompress(compact, len(input)), input, label + " compact decode")
end function

function main(args)
  for each size in [0, 1, 2, 3, 4, 5, 12, 13, 14, 15, 16, 31, 127, 128, 129, 255, 256, 4096, 65536]
    checkRoundtrip(byteSequence(size), "sequence " + size)
  end for
  checkRoundtrip(bytes(1024 * 1024, 0), "one MiB zeroes")
  checkRoundtrip(bytes(1024 * 1024, 65), "one MiB repeated")
  checkRoundtrip(randomish(8 * 1024 * 1024), "eight MiB randomish")
  checkRoundtrip(bytes("abcabcabcabcabcabcabc"), "short periodic")
  data = bytes(1024 * 1024, 0)
  for i = 0 to len(data) - 1
    data[i] = ((i >> 4) + i * 13) & 255
  end for
  checkRoundtrip(data, "one MiB patterned")
  checkTrue(len(compression.fast(bytes(65536, 0))) < 512, "LZ4 compresses repeated data")
  checkTrue(len(compression.compact(bytes(65536, 0))) < 512, "compact compresses repeated data")
  checkEq(compression.fast(bytes(0))[4], compression.RAW, "empty raw payload")
  checkEq(compression.compact(bytes(10, 0))[4], compression.RLE, "compact RLE selection")
  checkEq(compression.fast(randomish(4096))[4], compression.RAW, "incompressible raw fallback")

  known = bytes(5, 0)
  known[0] = 0x40
  known[1] = 65
  known[2] = 66
  known[3] = 67
  known[4] = 68
  checkEq(lz4.decode(known, 4), bytes("ABCD"), "standard LZ4 literal block")
  checkEq(lz4.encode(bytes("ABCD")), known, "standard LZ4 literal encoding")
  checkEq(lz4.encode(bytes(0)), bytes(1, 0), "standard empty LZ4 block")
  matchBlock = bytes(10, 65)
  matchBlock[0] = 0x16
  matchBlock[2] = 1
  matchBlock[3] = 0
  matchBlock[4] = 0x50
  checkEq(lz4.decode(matchBlock, 16), bytes(16, 65), "standard LZ4 overlap match")

  checkEq(typeof(try(lz4.encode("not bytes"))), "error", "LZ4 argument validation")
  checkEq(typeof(try(lz4.decode(bytes(0), 0))), "error", "LZ4 rejects empty block")
  checkEq(typeof(try(lz4.decode(bytes(3, 0), 4))), "error", "LZ4 rejects zero offset")
  checkEq(typeof(try(lz4.decode(bytes(2, 0xFF), 4))), "error", "LZ4 rejects truncated lengths")
  checkEq(typeof(try(lz4.decode(lz4.encode(bytes(100, 0)), 99))), "error", "LZ4 output limit")
  checkEq(typeof(try(rle.decode(bytes(1, 0x80), 3))), "error", "RLE rejects truncated run")
  checkEq(typeof(try(rle.decode(bytes(1, 0x01), 2))), "error", "RLE rejects truncated literal")
  checkEq(typeof(try(rle.decode(rle.encode(bytes(100, 0)), 99))), "error", "RLE output limit")
  checkEq(typeof(try(compression.decompress(compression.fast(bytes(64, 0)), 63))), "error", "container output cap")
  checkEq(typeof(try(compression.compress(bytes(0), "unknown"))), "error", "container mode validation")
  checkEq(typeof(try(compression.decompress(bytes(0), 100))), "error", "container header validation")

  packed = compression.fast(byteSequence(257))
  packed[16] = packed[16] ^ 1
  checkEq(typeof(try(compression.decompress(packed, 257))), "error", "container detects payload corruption")
  packed = compression.fast(bytes(0))
  packed[4] = 99
  checkEq(typeof(try(compression.decompress(packed, 0))), "error", "container rejects unknown algorithm")
  packed = compression.fast(bytes(0))
  packed[5] = 1
  checkEq(typeof(try(compression.decompress(packed, 0))), "error", "container rejects unknown flags")
  malformedSafe = true
  for size = 0 to 511
    noise = randomish(size)
    result = try(lz4.decode(noise, 64))
    if typeof(result) == "bytes" and len(result) != 64 then malformedSafe = false end if
    result = try(rle.decode(noise, 64))
    if typeof(result) == "bytes" and len(result) != 64 then malformedSafe = false end if
  end for
  checkTrue(malformedSafe, "malformed blocks cannot escape the decoded size")
  if not ok then return 1 end if
  print "[OK] compression codecs"
end function
