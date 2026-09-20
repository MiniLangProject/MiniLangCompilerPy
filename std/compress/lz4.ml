/*
Copyright 2026 Nils Kopal

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

//! Portable LZ4 block compression. Blocks have no embedded size or checksum;
//! use std.compress for a self-describing, checked container.

package std.compress.lz4

/// Error code for malformed input or an invalid size.
const LZ4_ERR = 250

/// Append an LZ4 extension length to an already allocated output.
/// @internal
function _writeLength(output, position, length)
  while length >= 255
    output[position] = 255
    position = position + 1
    length = length - 255
  end while
  output[position] = length
  return position + 1
end function

/// Hash four input bytes into a 64-KiB match table.
/// @internal
function _hash(input, position)
  word = input[position] | (input[position + 1] << 8) | (input[position + 2] << 16) | (input[position + 3] << 24)
  return ((word * 2654435761) >> 16) & 65535
end function

/// Encode a standard, independently decodable LZ4 block.
/// The caller must retain the original byte length for decode().
/// @param input Bytes to compress.
function encode(input)
  if typeof(input) != "bytes" then return error(LZ4_ERR, "LZ4 input must be bytes") end if
  n = len(input)
  if n > 0x7FFFFFFF - (n >> 7) - 32 then return error(LZ4_ERR, "LZ4 input is too large") end if
  output = bytes(n + (n >> 7) + 32, 0)
  if n < 13 then
    output[0] = n << 4
    if n > 0 then copyBytes(output, 1, input, 0, n) end if
    return slice(output, 0, n + 1)
  end if
  table = array(65536, -1)
  anchor = 0
  position = 0
  written = 0
  matchLimit = n - 12
  search = 1
  while position <= matchLimit
    slot = _hash(input, position)
    previous = table[slot]
    table[slot] = position
    if previous >= 0 and position - previous <= 65535 and
       input[previous] == input[position] and input[previous + 1] == input[position + 1] and
       input[previous + 2] == input[position + 2] and input[previous + 3] == input[position + 3] then
      literalLength = position - anchor
      matched = 4
      // Leave at least five trailing literals, as required by the block format.
      while position + matched < n - 5 and input[previous + matched] == input[position + matched]
        matched = matched + 1
      end while
      matchExtra = matched - 4
      literalNibble = literalLength
      if literalNibble > 15 then literalNibble = 15 end if
      matchNibble = matchExtra
      if matchNibble > 15 then matchNibble = 15 end if
      output[written] = (literalNibble << 4) | matchNibble
      written = written + 1
      if literalLength >= 15 then written = _writeLength(output, written, literalLength - 15) end if
      if literalLength > 0 then
        copyBytes(output, written, input, anchor, literalLength)
        written = written + literalLength
      end if
      offset = position - previous
      output[written] = offset & 255
      output[written + 1] = (offset >> 8) & 255
      written = written + 2
      if matchExtra >= 15 then written = _writeLength(output, written, matchExtra - 15) end if
      position = position + matched
      anchor = position
      search = 1
    else
      // LZ4-style acceleration skips progressively more positions when
      // the input offers no matches, avoiding a costly hash for every byte.
      position = position + (search >> 6) + 1
      search = search + 1
    end if
  end while
  literalLength = n - anchor
  literalNibble = literalLength
  if literalNibble > 15 then literalNibble = 15 end if
  output[written] = literalNibble << 4
  written = written + 1
  if literalLength >= 15 then written = _writeLength(output, written, literalLength - 15) end if
  if literalLength > 0 then
    copyBytes(output, written, input, anchor, literalLength)
    written = written + literalLength
  end if
  return slice(output, 0, written)
end function

/// Decode one LZ4 block into exactly expectedSize bytes.
/// The caller-provided size is an allocation bound; malformed or truncated
/// blocks are rejected before any out-of-range copy.
/// @param block Encoded LZ4 bytes.
/// @param expectedSize Exact decoded byte count.
function decode(block, expectedSize)
  if typeof(block) != "bytes" or typeof(expectedSize) != "int" then
    return error(LZ4_ERR, "LZ4 decode expects bytes and an int size")
  end if
  if expectedSize < 0 or expectedSize > 0x7FFFFFFF then
    return error(LZ4_ERR, "Invalid LZ4 output size")
  end if
  inputLength = len(block)
  output = bytes(expectedSize, 0)
  readAt = 0
  written = 0
  while readAt < inputLength
    token = block[readAt]
    readAt = readAt + 1
    literalLength = token >> 4
    if literalLength == 15 then
      extension = 255
      while extension == 255
        if readAt >= inputLength then return error(LZ4_ERR, "Truncated LZ4 literal length") end if
        extension = block[readAt]
        readAt = readAt + 1
        if extension > expectedSize - written - literalLength then return error(LZ4_ERR, "LZ4 output limit exceeded") end if
        literalLength = literalLength + extension
      end while
    end if
    if literalLength > inputLength - readAt or literalLength > expectedSize - written then
      return error(LZ4_ERR, "Invalid LZ4 literal length")
    end if
    if literalLength > 0 then
      copyBytes(output, written, block, readAt, literalLength)
      readAt = readAt + literalLength
      written = written + literalLength
    end if
    if readAt == inputLength then
      if written != expectedSize then return error(LZ4_ERR, "LZ4 output length mismatch") end if
      return output
    end if
    if inputLength - readAt < 2 then return error(LZ4_ERR, "Truncated LZ4 offset") end if
    offset = block[readAt] | (block[readAt + 1] << 8)
    readAt = readAt + 2
    if offset == 0 or offset > written then return error(LZ4_ERR, "Invalid LZ4 offset") end if
    matchLength = (token & 15) + 4
    if (token & 15) == 15 then
      extension = 255
      while extension == 255
        if readAt >= inputLength then return error(LZ4_ERR, "Truncated LZ4 match length") end if
        extension = block[readAt]
        readAt = readAt + 1
        if extension > expectedSize - written - matchLength then return error(LZ4_ERR, "LZ4 output limit exceeded") end if
        matchLength = matchLength + extension
      end while
    end if
    if matchLength > expectedSize - written then return error(LZ4_ERR, "LZ4 output limit exceeded") end if
    copied = 0
    while copied < matchLength
      // Copy only already materialized bytes. Starting with the offset
      // window, each copy can double the available prefix even for offset 1.
      take = offset + copied
      if take > matchLength - copied then take = matchLength - copied end if
      copyBytes(output, written + copied, output, written - offset, take)
      copied = copied + take
    end while
    written = written + matchLength
  end while
  return error(LZ4_ERR, "Empty LZ4 block")
end function
