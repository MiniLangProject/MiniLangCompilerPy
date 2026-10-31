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

//! Provides the std encoding base64 package.

package std.encoding.base64

/// Std.encoding.base64 Minimal Base64 (RFC 4648) utilities: toBase64(bytes) -> string fromBase64(string) -> bytes | void Notes: - fromBase64 ignores ASCII whitespace (space/tab/CR/LF). - returns void on invalid input.
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

/// Helpers (internal).
/// @internal
function _isWs(ch)
  return ch == " " or ch == "\t" or ch == "\n" or ch == "\r"
end function

/// Recognize ASCII whitespace permitted inside encoded input.
/// @internal
function _isWsByte(v)
  return v == 32 or v == 9 or v == 10 or v == 13
end function

/// Remove permitted whitespace and reject non-string input.
/// @internal
function _cleanBytes(text)
  if typeof(text) != "string" then
    return
  end if

  src = bytes(text)
  n = len(src)
  if n == 0 then
    return bytes(0)
  end if

  i = 0
  while i < n and not _isWsByte(src[i])
    i = i + 1
  end while
  if i == n then return src end if

  output = bytes(n, 0)
  if i > 0 then copyBytes(output, 0, src, 0, i) end if
  oi = i
  i = i + 1
  while i < n
    if not _isWsByte(src[i]) then
      output[oi] = src[i]
      oi = oi + 1
    end if
    i = i + 1
  end while

  return slice(output, 0, oi)
end function

/// Decode a validated block or return the canonical empty bytes value.
/// @internal
function _decodeOrEmpty(b)
  if typeof(b) != "bytes" then
    return
  end if
  if len(b) == 0 then
    return ""
  end if
  return decode(b)
end function

/// Convert one Base64 alphabet byte to its six-bit value.
/// @internal
function _valByte(v)
  if v >= 65 and v <= 90 then
    return v - 65
  end if
  if v >= 97 and v <= 122 then
    return 26 +(v - 97)
  end if
  if v >= 48 and v <= 57 then
    return 52 +(v - 48)
  end if
  if v == 43 then
    return 62
  end if
  if v == 47 then
    return 63
  end if
  return -1
end function

/// Encoding: bytes -> base64 string (with '=' padding).
/// @param b Second input value.
function toBase64(b)
  if typeof(b) != "bytes" then
    return
  end if

  n = len(b)
  if n == 0 then
    return ""
  end if

  alph = bytes(ALPHABET)
  blocks = (n + 2) div 3
  output = bytes(blocks * 4, 0)
  oi = 0
  i = 0

  while i < n
    rem = n - i

    b0 = b[i]
    if rem == 1 then
      output[oi] = alph[b0 >> 2]
      output[oi + 1] = alph[(b0 & 3) << 4]
      output[oi + 2] = 61
      output[oi + 3] = 61
      break
    end if

    b1 = b[i + 1]
    if rem == 2 then
      output[oi] = alph[b0 >> 2]
      output[oi + 1] = alph[((b0 & 3) << 4) |(b1 >> 4)]
      output[oi + 2] = alph[(b1 & 15) << 2]
      output[oi + 3] = 61
      break
    end if

    b2 = b[i + 2]
    output[oi] = alph[b0 >> 2]
    output[oi + 1] = alph[((b0 & 3) << 4) |(b1 >> 4)]
    output[oi + 2] = alph[((b1 & 15) << 2) |(b2 >> 6)]
    output[oi + 3] = alph[b2 & 63]

    i = i + 3
    oi = oi + 4
  end while

  return _decodeOrEmpty(output)
end function

/// Decoding: base64 string -> bytes (or void on error).
/// @param text Text to process.
function fromBase64(text)
  if typeof(text) != "string" then
    return
  end if

  t = _cleanBytes(text)
  n = len(t)

  if n == 0 then
    return bytes(0)
  end if

  if (n % 4) != 0 then
    return
  end if

  // padding: only allowed in the final 4-char block as either "xxx=" or "xx=="
  pad = 0
  if n >= 1 and t[n - 1] == 61 then
    pad = 1
    if n >= 2 and t[n - 2] == 61 then
      pad = 2
    end if
  end if

  blocks = n / 4
  outLen = blocks * 3 - pad
  if outLen < 0 then
    return
  end if

  output = bytes(outLen)
  oi = 0

  bi = 0
  // Amortize the lookup table over larger inputs; leave the final padded
  // block to the validation path below.
  if n >= 256 then
    lookup = bytes(256, 255)
    alphabet = bytes(ALPHABET)
    for alphabetIndex = 0 to 63
      lookup[alphabet[alphabetIndex]] = alphabetIndex
    end for
    fullBlocks = blocks - 1
    inputEnd = fullBlocks * 4
    valid = asm unsafe x64(in t as bytes, in lookup as bytes, inout output as bytes, in inputEnd as int, scratch inputAt as int, scratch outputAt as int, scratch ch as int, scratch value as int, scratch packed as int, scratch tmp as int) returns int
      mov result, 1
      mov inputAt, 0
      mov outputAt, 0
      label scan
      cmp inputAt, inputEnd
      jge done
      movzx ch, byte [t.data + inputAt]
      movzx value, byte [lookup.data + ch]
      cmp value, 255
      je invalid
      mov packed, value
      shl packed, 18
      add inputAt, 1
      movzx ch, byte [t.data + inputAt]
      movzx value, byte [lookup.data + ch]
      cmp value, 255
      je invalid
      shl value, 12
      or packed, value
      add inputAt, 1
      movzx ch, byte [t.data + inputAt]
      movzx value, byte [lookup.data + ch]
      cmp value, 255
      je invalid
      shl value, 6
      or packed, value
      add inputAt, 1
      movzx ch, byte [t.data + inputAt]
      movzx value, byte [lookup.data + ch]
      cmp value, 255
      je invalid
      or packed, value
      add inputAt, 1
      mov tmp, packed
      shr tmp, 16
      mov byte [output.data + outputAt], tmp
      add outputAt, 1
      mov tmp, packed
      shr tmp, 8
      mov byte [output.data + outputAt], tmp
      add outputAt, 1
      mov byte [output.data + outputAt], packed
      add outputAt, 1
      jmp scan
      label invalid
      mov result, 0
      label done
    end asm
    if valid == 0 then return end if
    bi = fullBlocks
    oi = fullBlocks * 3
  end if
  while bi < blocks
    i = bi * 4
    c0 = t[i]
    c1 = t[i + 1]
    c2 = t[i + 2]
    c3 = t[i + 3]

    v0 = _valByte(c0)
    v1 = _valByte(c1)
    if v0 < 0 or v1 < 0 then
      return
    end if

    isLast =(bi ==(blocks - 1))

    if not isLast then
      // no padding allowed before the final block
      if c2 == 61 or c3 == 61 then
        return
      end if

      v2 = _valByte(c2)
      v3 = _valByte(c3)
      if v2 < 0 or v3 < 0 then
        return
      end if

      triple =(v0 << 18) |(v1 << 12) |(v2 << 6) | v3
      output[oi] =(triple >> 16) & 255
      output[oi + 1] =(triple >> 8) & 255
      output[oi + 2] = triple & 255

      oi = oi + 3
      bi = bi + 1
      continue
    end if

    // last block: handle padding
    if pad == 0 then
      v2 = _valByte(c2)
      v3 = _valByte(c3)
      if v2 < 0 or v3 < 0 then
        return
      end if
      triple =(v0 << 18) |(v1 << 12) |(v2 << 6) | v3
      output[oi] =(triple >> 16) & 255
      output[oi + 1] =(triple >> 8) & 255
      output[oi + 2] = triple & 255
      // additionally ensure there is no stray '=' inside last block
      // (handled by pad calculation + checks below)
    else if pad == 1 then
      if c3 != 61 then
        return
      end if
      v2 = _valByte(c2)
      if v2 < 0 then
        return
      end if
      triple =(v0 << 18) |(v1 << 12) |(v2 << 6)
      output[oi] =(triple >> 16) & 255
      output[oi + 1] =(triple >> 8) & 255
    else if pad == 2 then
      if c2 != 61 or c3 != 61 then
        return
      end if
      triple =(v0 << 18) |(v1 << 12)
      output[oi] =(triple >> 16) & 255
    else
      return
    end if

    bi = bi + 1
  end while

  return output
end function

