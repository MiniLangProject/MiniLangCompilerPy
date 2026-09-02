/*
Copyright 2026 Nils Kopal

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// RFC-4122 UUID helpers. Version-4 identifiers use the target's native CSPRNG.
//! Provides the std uuid package.

package std.uuid
import std.crypto as crypto
import std.encoding.hex as hex
import std.string as string

/// Stores the uuid err.
const UUID_ERR = 266

/// Implements error.
/// @internal
function _error(message)
  return error(UUID_ERR, message)
end function

/// Converts format.
/// @param raw Value supplied for `raw`.
function format(raw)
  if typeof(raw) != "bytes" or len(raw) != 16 then return _error("UUID value must be 16 bytes") end if
  text = hex.encode(raw)
  return string.substr(text, 0, 8) + "-" + string.substr(text, 8, 4) + "-" + string.substr(text, 12, 4) + "-" + string.substr(text, 16, 4) + "-" + string.substr(text, 20, 12)
end function

/// Implements v4 bytes.
function v4Bytes()
  raw = crypto.secureRandom(16)
  if typeof(raw) == "error" then return raw end if
  raw[6] = (raw[6] & 0x0F) | 0x40
  raw[8] = (raw[8] & 0x3F) | 0x80
  return raw
end function

/// Implements v4.
function v4()
  raw = v4Bytes()
  if typeof(raw) == "error" then return raw end if
  result = format(raw)
  crypto.secureZero(raw)
  return result
end function

/// Returns parse.
/// @param text Text to process.
function parse(text)
  if typeof(text) != "string" or len(text) != 36 then return _error("invalid UUID text") end if
  if string.substr(text, 8, 1) != "-" or string.substr(text, 13, 1) != "-" or string.substr(text, 18, 1) != "-" or string.substr(text, 23, 1) != "-" then return _error("invalid UUID separators") end if
  compact = string.substr(text, 0, 8) + string.substr(text, 9, 4) + string.substr(text, 14, 4) + string.substr(text, 19, 4) + string.substr(text, 24, 12)
  raw = hex.decode(compact)
  if typeof(raw) != "bytes" or len(raw) != 16 then return _error("invalid UUID encoding") end if
  return raw
end function

/// Reports whether is valid.
/// @param text Text to process.
function isValid(text)
  return typeof(parse(text)) == "bytes"
end function
