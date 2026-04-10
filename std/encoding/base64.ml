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

package std.encoding.base64

// ------------------------------------------------------------
// std.encoding.base64
// Minimal Base64 (RFC 4648) utilities:
//
// toBase64(bytes)    -> string
// fromBase64(string) -> bytes | void
//
// Notes:
// - fromBase64 ignores ASCII whitespace (space/tab/CR/LF).
// - returns void on invalid input.
// ------------------------------------------------------------

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

// ------------------------------------------------------------
// helpers (internal)
// ------------------------------------------------------------

function _isWs(ch)
  return ch == " " or ch == "\t" or ch == "\n" or ch == "\r"
end function

function _isWsByte(v)
  return v == 32 or v == 9 or v == 10 or v == 13
end function

function _cleanBytes(text)
  if typeof(text) != "string" then
    return
  end if

  src = bytes(text)
  n = len(src)
  if n == 0 then
    return bytes(0)
  end if

  output = bytes(n, 0)
  oi = 0
  i = 0
  while i < n
    if not _isWsByte(src[i]) then
      output[oi] = src[i]
      oi = oi + 1
    end if
    i = i + 1
  end while

  if oi == n then
    return src
  end if
  return slice(output, 0, oi)
end function

function _decodeOrEmpty(b)
  if typeof(b) != "bytes" then
    return
  end if
  if len(b) == 0 then
    return ""
  end if
  return decode(b)
end function

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

// ------------------------------------------------------------
// encoding: bytes -> base64 string (with '=' padding)
// ------------------------------------------------------------

function toBase64(b)
  if typeof(b) != "bytes" then
    return
  end if

  n = len(b)
  if n == 0 then
    return ""
  end if

  alph = bytes(ALPHABET)
  blocks = 0
  i = 0
  while i < n
    blocks = blocks + 1
    i = i + 3
  end while
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

// ------------------------------------------------------------
// decoding: base64 string -> bytes (or void on error)
// ------------------------------------------------------------

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

