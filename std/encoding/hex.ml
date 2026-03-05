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

package std.encoding.hex

const HEX_ERR = 210

function _hexErr(msg)
  return error(HEX_ERR, msg)
end function


// ------------------------------------------------------------
// std.encoding.hex
// Thin, ergonomic wrapper around builtins:
// hex(bytes)    -> lowercase hex string
// fromHex(str)  -> bytes (or void on error)
// ------------------------------------------------------------

/*
encodes bytes to lowercase hex
input: bytes b
returns: string hexLower
*/
function encode(b)
  return hex(b)
end function

/*
encodes bytes to uppercase hex
input: bytes b
returns: string hexUpper
*/
function encodeUpper(b)
  s = hex(b)
  if typeof(s) != "string" then
    return
  end if
  output = ""
  i = 0
  while i < len(s)
    c = s[i]
    // convert a-f to A-F (ASCII-only)
    if c == "a" then
      output = output + "A"
    else if c == "b" then
      output = output + "B"
    else if c == "c" then
      output = output + "C"
    else if c == "d" then
      output = output + "D"
    else if c == "e" then
      output = output + "E"
    else if c == "f" then
      output = output + "F"
    else
      output = output + c
    end if
    i = i + 1
  end while
  return output
end function

/*
decodes a hex string to bytes
input: string s
returns: bytes decoded (or void on error)
*/
function decode(s)
  return fromHex(s)
end function

/*
checks whether a hex string is valid
input: string s
returns: bool ok
*/
function isValid(s)
  b = fromHex(s)
  return typeof(b) != "void"
end function

/*
decodes a hex string or returns fallback bytes
input: string s, bytes fallbackBytes
returns: bytes decodedOrFallback
*/
function decodeOr(s, fallbackBytes)
  b = fromHex(s)
  if typeof(b) == "void" then
    return fallbackBytes
  end if
  return b
end function


/*
decodes a hex string or returns an error on failure
input: string s
returns: bytes decoded OR error(code=HEX_ERR)
*/
function decodeOrError(s)
  if typeof(s) != "string" then
    return _hexErr("hex.decodeOrError expects a string")
  end if
  b = fromHex(s)
  if typeof(b) == "void" then
    return _hexErr("Invalid hex string")
  end if
  return b
end function
