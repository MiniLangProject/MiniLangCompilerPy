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

//! Provides the std encoding hex package.

package std.encoding.hex

import std.string as s

/// Lower/uppercase hexadecimal encoding plus strict, error-preserving decoding.
const HEX_ERR = 210

/// Construct a consistent hexadecimal validation error.
/// @internal
function _hexErr(msg)
  return error(HEX_ERR, msg)
end function


// ------------------------------------------------------------
// std.encoding.hex
// Thin, ergonomic wrapper around builtins:
// hex(bytes)    -> lowercase hex string
// fromHex(str)  -> bytes (or void on error)
// ------------------------------------------------------------

/// Encodes bytes to lowercase hex.
/// @param b Second input value.
function encode(b)
  return hex(b)
end function

/// Encodes bytes to uppercase hex.
/// @param b Second input value.
function encodeUpper(b)
  text = hex(b)
  if typeof(text) != "string" then
    return
  end if
  return s.toUpperAscii(text)
end function

/// Decodes a hex string to bytes.
/// @param s Value supplied for `s`.
function decode(s)
  return fromHex(s)
end function

/// Checks whether a hex string is valid.
/// @param s Value supplied for `s`.
function isValid(s)
  b = fromHex(s)
  return typeof(b) != "void"
end function

/// Decodes a hex string or returns fallback bytes.
/// @param s Value supplied for `s`.
/// @param fallbackBytes Value supplied for `fallbackBytes`.
function decodeOr(s, fallbackBytes)
  b = fromHex(s)
  if typeof(b) == "void" then
    return fallbackBytes
  end if
  return b
end function


/// Decodes a hex string or returns an error on failure.
/// @param s Value supplied for `s`.
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
