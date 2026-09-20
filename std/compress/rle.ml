/*
Copyright 2026 Nils Kopal

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

//! Portable byte run-length codec for sparse or highly repetitive data.
//! Tokens 0..127 copy 1..128 literals; tokens 128..255 repeat the next byte
//! 3..130 times. This is not a standardized interchange format.

package std.compress.rle

/// Error code for malformed RLE data.
const RLE_ERR = 251

/// Count a byte run, stopping at one token's maximum length.
/// @internal
function _runLength(input, position, n)
  count = 1
  while count < 130 and position + count < n and input[position + count] == input[position]
    count = count + 1
  end while
  return count
end function

/// Encode bytes using bounded literal and repeat runs.
/// @param input Bytes to compress.
function encode(input)
  if typeof(input) != "bytes" then return error(RLE_ERR, "RLE input must be bytes") end if
  n = len(input)
  if n > 0x7FFFFFFF - (n >> 7) - 2 then return error(RLE_ERR, "RLE input is too large") end if
  output = bytes(n + (n >> 7) + 2, 0)
  readAt = 0
  written = 0
  while readAt < n
    run = _runLength(input, readAt, n)
    if run >= 3 then
      output[written] = 128 | (run - 3)
      output[written + 1] = input[readAt]
      written = written + 2
      readAt = readAt + run
    else
      start = readAt
      readAt = readAt + run
      while readAt < n and readAt - start < 128
        run = _runLength(input, readAt, n)
        if run >= 3 or readAt - start + run > 128 then break end if
        readAt = readAt + run
      end while
      count = readAt - start
      output[written] = count - 1
      written = written + 1
      copyBytes(output, written, input, start, count)
      written = written + count
    end if
  end while
  return slice(output, 0, written)
end function

/// Decode RLE into an exactly bounded output buffer.
/// @param block Encoded RLE bytes.
/// @param expectedSize Exact decoded byte count.
function decode(block, expectedSize)
  if typeof(block) != "bytes" or typeof(expectedSize) != "int" then
    return error(RLE_ERR, "RLE decode expects bytes and an int size")
  end if
  if expectedSize < 0 or expectedSize > 0x7FFFFFFF then
    return error(RLE_ERR, "Invalid RLE output size")
  end if
  output = bytes(expectedSize, 0)
  readAt = 0
  written = 0
  n = len(block)
  while readAt < n
    token = block[readAt]
    readAt = readAt + 1
    if token < 128 then
      count = token + 1
      if count > n - readAt or count > expectedSize - written then
        return error(RLE_ERR, "Invalid RLE literal run")
      end if
      copyBytes(output, written, block, readAt, count)
      readAt = readAt + count
      written = written + count
    else
      count = (token & 127) + 3
      if readAt >= n or count > expectedSize - written then
        return error(RLE_ERR, "Invalid RLE repeat run")
      end if
      fillBytes(output, written, count, block[readAt])
      readAt = readAt + 1
      written = written + count
    end if
  end while
  if written != expectedSize then return error(RLE_ERR, "RLE output length mismatch") end if
  return output
end function
