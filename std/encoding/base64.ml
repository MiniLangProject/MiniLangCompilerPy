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

import std.string as s

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

function _clean(text)
  output = ""
  for each ch in text
    if not _isWs(ch) then
      output = output + ch
    end if
  end for
  return output
end function

function _val(ch)
  // maps a Base64 character to its 0..63 value; returns -1 if invalid
  idx = s.indexOf(ALPHABET, ch, 0)
  if typeof(idx) == "void" then
    return -1
  end if
  return idx
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

  output = ""
  i = 0

  while i < n
    rem = n - i

    b0 = b[i]
    if rem == 1 then
      output = output + ALPHABET[b0 >> 2]
      output = output + ALPHABET[(b0 & 3) << 4]
      output = output + "=="
      break
    end if

    b1 = b[i + 1]
    if rem == 2 then
      output = output + ALPHABET[b0 >> 2]
      output = output + ALPHABET[((b0 & 3) << 4) |(b1 >> 4)]
      output = output + ALPHABET[(b1 & 15) << 2]
      output = output + "="
      break
    end if

    b2 = b[i + 2]
    output = output + ALPHABET[b0 >> 2]
    output = output + ALPHABET[((b0 & 3) << 4) |(b1 >> 4)]
    output = output + ALPHABET[((b1 & 15) << 2) |(b2 >> 6)]
    output = output + ALPHABET[b2 & 63]

    i = i + 3
  end while

  return output
end function

// ------------------------------------------------------------
// decoding: base64 string -> bytes (or void on error)
// ------------------------------------------------------------

function fromBase64(text)
  if typeof(text) != "string" then
    return
  end if

  t = _clean(text)
  n = len(t)

  if n == 0 then
    return bytes(0)
  end if

  if (n % 4) != 0 then
    return
  end if

  // padding: only allowed in the final 4-char block as either "xxx=" or "xx=="
  pad = 0
  if n >= 1 and t[n - 1] == "=" then
    pad = 1
    if n >= 2 and t[n - 2] == "=" then
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

    v0 = _val(c0)
    v1 = _val(c1)
    if v0 < 0 or v1 < 0 then
      return
    end if

    isLast =(bi ==(blocks - 1))

    if not isLast then
      // no padding allowed before the final block
      if c2 == "=" or c3 == "=" then
        return
      end if

      v2 = _val(c2)
      v3 = _val(c3)
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
      v2 = _val(c2)
      v3 = _val(c3)
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
      if c3 != "=" then
        return
      end if
      v2 = _val(c2)
      if v2 < 0 then
        return
      end if
      triple =(v0 << 18) |(v1 << 12) |(v2 << 6)
      output[oi] =(triple >> 16) & 255
      output[oi + 1] =(triple >> 8) & 255
    else if pad == 2 then
      if c2 != "=" or c3 != "=" then
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

