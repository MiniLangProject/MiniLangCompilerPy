/*
Copyright 2026 Nils Kopal

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Pure path manipulation for the selected target.  These helpers do not touch
// the filesystem and therefore also work for paths that do not exist yet.
//! Provides the std path package.

package std.path
import std.platform as platform

/// Track the path err value used by this standard-library module.
const PATH_ERR = 260

/// Provide the error operation for this standard-library module.
/// @internal
function _error(message)
  return error(PATH_ERR, message)
end function

/// Provide the separator operation for this standard-library module.
function separator()
  return platform.pathSeparator()
end function

/// Provide the separator byte operation for this standard-library module.
/// @internal
function _separatorByte(value)
#if TARGET_OS == "windows"
  return value == 47 or value == 92
#else
  return value == 47
#endif
end function

/// Reports whether is absolute.
/// @param path Path to operate on.
function isAbsolute(path)
  if typeof(path) != "string" or len(path) == 0 then return false end if
  raw = bytes(path)
#if TARGET_OS == "windows"
  if len(raw) >= 2 and _separatorByte(raw[0]) and _separatorByte(raw[1]) then return true end if
  if len(raw) >= 3 and ((raw[0] >= 65 and raw[0] <= 90) or (raw[0] >= 97 and raw[0] <= 122)) and raw[1] == 58 and _separatorByte(raw[2]) then return true end if
  return false
#else
  return raw[0] == 47
#endif
end function

/// Provide the join operation for this standard-library module.
/// @param left Left input value.
/// @param right Right input value.
function join(left, right)
  if typeof(left) != "string" or typeof(right) != "string" then return _error("join expects strings") end if
  if left == "" then return right end if
  if right == "" then return left end if
  if isAbsolute(right) then return right end if
  a = bytes(left)
  b = bytes(right)
  leftEnds = _separatorByte(a[len(a) - 1])
  rightStarts = _separatorByte(b[0])
  if leftEnds and rightStarts then return left + decode(slice(b, 1, len(b) - 1)) end if
  if leftEnds or rightStarts then return left + right end if
  return left + separator() + right
end function

/// Provide the file name operation for this standard-library module.
/// @param path Path to operate on.
function fileName(path)
  if typeof(path) != "string" then return _error("fileName expects string") end if
  raw = bytes(path)
  if len(raw) == 0 then return "" end if
  i = len(raw) - 1
  while i >= 0
    if _separatorByte(raw[i]) then
      if i == len(raw) - 1 then return "" end if
      return decode(slice(raw, i + 1, len(raw) - i - 1))
    end if
    i = i - 1
  end while
  return path
end function

/// Provide the directory name operation for this standard-library module.
/// @param path Path to operate on.
function directoryName(path)
  if typeof(path) != "string" then return _error("directoryName expects string") end if
  raw = bytes(path)
  if len(raw) == 0 then return "" end if
  i = len(raw) - 1
  while i >= 0
    if _separatorByte(raw[i]) then
      if i == 0 then return separator() end if
      return decode(slice(raw, 0, i))
    end if
    i = i - 1
  end while
  return ""
end function

/// Provide the extension operation for this standard-library module.
/// @param path Path to operate on.
function extension(path)
  name = fileName(path)
  if typeof(name) == "error" or len(name) == 0 then return "" end if
  raw = bytes(name)
  i = len(raw) - 1
  while i > 0
    if raw[i] == 46 then return decode(slice(raw, i, len(raw) - i)) end if
    i = i - 1
  end while
  return ""
end function

/// Provide the change extension operation for this standard-library module.
/// @param path Path to operate on.
/// @param newExtension Value supplied for `newExtension`.
function changeExtension(path, newExtension)
  if typeof(path) != "string" or typeof(newExtension) != "string" then return _error("changeExtension expects strings") end if
  ext = extension(path)
  prefix = path
  if len(ext) > 0 then prefix = decode(slice(bytes(path), 0, len(path) - len(ext))) end if
  if newExtension == "" then return prefix end if
  if bytes(newExtension)[0] == 46 then return prefix + newExtension end if
  return prefix + "." + newExtension
end function
