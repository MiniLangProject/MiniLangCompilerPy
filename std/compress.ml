/*
Copyright 2026 Nils Kopal

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

//! Self-describing, portable byte compression for Windows and Linux.
//! The MLC1 container uses a 16-byte header, a bounded output size, and
//! CRC-32C for accidental corruption detection (not authentication).

package std.compress

import std.compress.lz4 as lz4
import std.compress.rle as rle
import std.checksum.crc32c as crc32c

/// Error code for invalid containers and output limits.
const COMPRESS_ERR = 252
/// Header bytes in an MLC1 container.
const HEADER_SIZE = 16
/// Uncompressed payload.
const RAW = 0
/// Standard LZ4 block payload.
const LZ4 = 1
/// MiniLang byte-run payload.
const RLE = 2

/// Write an unsigned 32-bit integer in little-endian order.
/// @internal
function _put32(output, offset, value)
  output[offset] = value & 255
  output[offset + 1] = (value >> 8) & 255
  output[offset + 2] = (value >> 16) & 255
  output[offset + 3] = (value >> 24) & 255
end function

/// Read an unsigned 32-bit integer from the fixed header.
/// @internal
function _get32(input, offset)
  return input[offset] | (input[offset + 1] << 8) | (input[offset + 2] << 16) | (input[offset + 3] << 24)
end function

/// Pack bytes into a checked container. "fast" tries LZ4; "compact" also
/// tries RLE and selects the smallest result. Incompressible data stays raw.
/// @param input Bytes to compress.
/// @param mode Either "fast" or "compact".
function compress(input, mode)
  if typeof(input) != "bytes" then return error(COMPRESS_ERR, "Compression input must be bytes") end if
  if mode != "fast" and mode != "compact" then return error(COMPRESS_ERR, "Compression mode must be fast or compact") end if
  n = len(input)
  if n > 0x7FFFFFFF - 65536 then return error(COMPRESS_ERR, "Compression input is too large") end if
  algorithm = RAW
  payload = input
  if n >= 13 then
    candidate = lz4.encode(input)
    if typeof(candidate) == "error" then return candidate end if
    if len(candidate) < len(payload) then
      payload = candidate
      algorithm = LZ4
    end if
  end if
  if mode == "compact" and n > 0 then
    candidate = rle.encode(input)
    if typeof(candidate) == "error" then return candidate end if
    if len(candidate) < len(payload) then
      payload = candidate
      algorithm = RLE
    end if
  end if
  result = bytes(HEADER_SIZE + len(payload), 0)
  result[0] = 77
  result[1] = 76
  result[2] = 67
  result[3] = 49
  result[4] = algorithm
  _put32(result, 8, n)
  _put32(result, 12, crc32c.compute(input))
  if len(payload) > 0 then copyBytes(result, HEADER_SIZE, payload, 0, len(payload)) end if
  return result
end function

/// Fast general-purpose compression with raw fallback.
/// @param input Bytes to compress.
function fast(input)
  return compress(input, "fast")
end function

/// Select the smallest of LZ4, RLE, and raw encoding.
/// @param input Bytes to compress.
function compact(input)
  return compress(input, "compact")
end function

/// Return the advertised decoded size without allocating the payload.
/// Always enforce an application-specific limit before trusting untrusted data.
/// @param container MLC1 container bytes.
function decodedSize(container)
  if typeof(container) != "bytes" or len(container) < HEADER_SIZE then
    return error(COMPRESS_ERR, "Truncated compression header")
  end if
  if container[0] != 77 or container[1] != 76 or container[2] != 67 or container[3] != 49 then
    return error(COMPRESS_ERR, "Invalid compression magic")
  end if
  if container[5] != 0 or container[6] != 0 or container[7] != 0 then
    return error(COMPRESS_ERR, "Unsupported compression flags")
  end if
  if container[4] != RAW and container[4] != LZ4 and container[4] != RLE then
    return error(COMPRESS_ERR, "Unknown compression algorithm")
  end if
  size = _get32(container, 8)
  if size > 0x7FFFFFFF then return error(COMPRESS_ERR, "Unsupported compression size") end if
  return size
end function

/// Decompress with an explicit output cap and verify the CRC-32C checksum.
/// The limit prevents a small hostile container from requesting huge memory.
/// @param container MLC1 container bytes.
/// @param maxOutputBytes Maximum accepted decoded byte length.
function decompress(container, maxOutputBytes)
  if typeof(maxOutputBytes) != "int" or maxOutputBytes < 0 then
    return error(COMPRESS_ERR, "Invalid compression output limit")
  end if
  size = decodedSize(container)
  if typeof(size) == "error" then return size end if
  if size > maxOutputBytes then return error(COMPRESS_ERR, "Compression output limit exceeded") end if
  payloadSize = len(container) - HEADER_SIZE
  algorithm = container[4]
  output = void
  if algorithm == RAW then
    if payloadSize != size then return error(COMPRESS_ERR, "Invalid raw payload size") end if
    output = slice(container, HEADER_SIZE, size)
  else
    payload = slice(container, HEADER_SIZE, payloadSize)
    if algorithm == LZ4 then
      output = lz4.decode(payload, size)
    else
      output = rle.decode(payload, size)
    end if
    if typeof(output) == "error" then return output end if
  end if
  if crc32c.compute(output) != _get32(container, 12) then
    return error(COMPRESS_ERR, "Compression checksum mismatch")
  end if
  return output
end function
