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

/// Locate the final platform separator without copying the whole path.
/// @internal
function _lastSeparator(path)
  index = stringLastIndexOf(path, "/")
#if TARGET_OS == "windows"
  alternate = stringLastIndexOf(path, "\\")
  if alternate > index then index = alternate end if
#endif
  return index
end function

/// Recognize either native path separator at the start or end.
/// @internal
function _startsSeparator(path)
  if stringStartsWith(path, "/") then return true end if
#if TARGET_OS == "windows"
  return stringStartsWith(path, "\\")
#else
  return false
#endif
end function

/// @internal
function _endsSeparator(path)
  if stringEndsWith(path, "/") then return true end if
#if TARGET_OS == "windows"
  return stringEndsWith(path, "\\")
#else
  return false
#endif
end function

/// Reports whether is absolute.
/// @param path Path to operate on.
function isAbsolute(path)
  if typeof(path) != "string" or len(path) == 0 then return false end if
#if TARGET_OS == "windows"
  if stringStartsWith(path, "//") or stringStartsWith(path, "\\\\") or stringStartsWith(path, "/\\") or stringStartsWith(path, "\\/") then return true end if
  if len(path) < 3 then return false end if
  prefix = bytes(stringSlice(path, 0, 3))
  if ((prefix[0] >= 65 and prefix[0] <= 90) or (prefix[0] >= 97 and prefix[0] <= 122)) and prefix[1] == 58 and _separatorByte(prefix[2]) then return true end if
  return false
#else
  return stringStartsWith(path, "/")
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
  leftEnds = _endsSeparator(left)
  rightStarts = _startsSeparator(right)
  if leftEnds and rightStarts then return left + stringSlice(right, 1, len(right) - 1) end if
  if leftEnds or rightStarts then return left + right end if
  return left + separator() + right
end function

/// Provide the file name operation for this standard-library module.
/// @param path Path to operate on.
function fileName(path)
  if typeof(path) != "string" then return _error("fileName expects string") end if
  if len(path) == 0 then return "" end if
  i = _lastSeparator(path)
  if i < 0 then return path end if
  if i == len(path) - 1 then return "" end if
  return stringSlice(path, i + 1, len(path) - i - 1)
end function

/// Provide the directory name operation for this standard-library module.
/// @param path Path to operate on.
function directoryName(path)
  if typeof(path) != "string" then return _error("directoryName expects string") end if
  if len(path) == 0 then return "" end if
  i = _lastSeparator(path)
  if i < 0 then return "" end if
  if i == 0 then return separator() end if
  return stringSlice(path, 0, i)
end function

/// Provide the extension operation for this standard-library module.
/// @param path Path to operate on.
function extension(path)
  name = fileName(path)
  if typeof(name) == "error" or len(name) == 0 then return "" end if
  i = stringLastIndexOf(name, ".")
  if i > 0 then return stringSlice(name, i, len(name) - i) end if
  return ""
end function

/// Provide the change extension operation for this standard-library module.
/// @param path Path to operate on.
/// @param newExtension Value supplied for `newExtension`.
function changeExtension(path, newExtension)
  if typeof(path) != "string" or typeof(newExtension) != "string" then return _error("changeExtension expects strings") end if
  ext = extension(path)
  prefix = path
  if len(ext) > 0 then prefix = stringSlice(path, 0, len(path) - len(ext)) end if
  if newExtension == "" then return prefix end if
  if stringStartsWith(newExtension, ".") then return prefix + newExtension end if
  return prefix + "." + newExtension
end function
