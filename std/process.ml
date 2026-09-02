/*
Copyright 2026 Nils Kopal

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Portable process metadata and environment helpers.  Mutating the current
// directory affects every thread and should therefore only happen at startup.
//! Provides the std process package.

package std.process

/// Track the process err value used by this standard-library module.
const PROCESS_ERR = 261
/// Track the max environment bytes value used by this standard-library module.
const MAX_ENVIRONMENT_BYTES = 1048576
/// Track the max path bytes value used by this standard-library module.
const MAX_PATH_BYTES = 32768

/// Provide the error operation for this standard-library module.
/// @internal
function _error(message)
  return error(PROCESS_ERR, message)
end function

#if TARGET_OS == "windows"
/// Returns get current process id.
/// @internal
extern function GetCurrentProcessId() from "kernel32.dll" returns u32
/// Returns get module file name w.
/// @internal
extern function GetModuleFileNameW(module as ptr, output as bytes, size as u32) from "kernel32.dll" returns u32
/// Returns get environment variable w.
/// @internal
extern function GetEnvironmentVariableW(name as wstr, output as bytes, size as u32) from "kernel32.dll" returns u32
/// Returns get current directory w.
/// @internal
extern function GetCurrentDirectoryW(size as u32, output as bytes) from "kernel32.dll" returns u32
/// Updates set current directory w.
/// @internal
extern function SetCurrentDirectoryW(path as wstr) from "kernel32.dll" returns bool
#else
/// Returns getpid.
/// @internal
extern function _getpid() from "libc.so.6" symbol "getpid" returns i32
/// Returns readlink.
/// @internal
extern function _readlink(path as cstr, output as ptr, size as u64) from "libc.so.6" symbol "readlink" returns i64
/// Returns getenv.
/// @internal
extern function _getenv(name as cstr) from "libc.so.6" symbol "getenv" returns ptr
/// Provide the strlen operation for this standard-library module.
/// @internal
extern function _strlen(value as ptr) from "libc.so.6" symbol "strlen" returns u64
/// Provide the copy from native operation for this standard-library module.
/// @internal
extern function _copyFromNative(output as bytes, value as ptr, count as u64) from "libc.so.6" symbol "memcpy" returns ptr
/// Returns getcwd.
/// @internal
extern function _getcwd(output as bytes, size as u64) from "libc.so.6" symbol "getcwd" returns ptr
/// Provide the chdir operation for this standard-library module.
/// @internal
extern function _chdir(path as cstr) from "libc.so.6" symbol "chdir" returns i32
#endif

/// Provide the id operation for this standard-library module.
function id()
#if TARGET_OS == "windows"
  return GetCurrentProcessId()
#else
  return _getpid()
#endif
end function

/// Return the absolute path of the currently running native image.
function executablePath()
#if TARGET_OS == "windows"
  raw = bytes(MAX_PATH_BYTES * 2, 0)
  actual = GetModuleFileNameW(0, raw, MAX_PATH_BYTES)
  if actual == 0 or actual >= MAX_PATH_BYTES then return _error("cannot read executable path") end if
  return decode16Z(raw)
#else
  raw = bytes(MAX_PATH_BYTES, 0)
  actual = _readlink("/proc/self/exe", nativeBytesPtr(raw), MAX_PATH_BYTES - 1)
  if actual <= 0 or actual >= MAX_PATH_BYTES then return _error("cannot read executable path") end if
  raw[actual] = 0
  return decodeZ(raw)
#endif
end function

/// Return an environment value, or void when the variable is absent.
/// @param name Name of the requested item.
function environment(name)
  if typeof(name) != "string" or len(name) == 0 then return _error("environment name must be non-empty") end if
#if TARGET_OS == "windows"
  required = GetEnvironmentVariableW(name, void, 0)
  if required == 0 then return end if
  if required > MAX_ENVIRONMENT_BYTES / 2 then return _error("environment value is too large") end if
  raw = bytes(required * 2, 0)
  actual = GetEnvironmentVariableW(name, raw, required)
  if actual == 0 or actual >= required then return _error("cannot read environment value") end if
  return decode16Z(raw)
#else
  value = _getenv(name)
  if value == 0 then return end if
  count = _strlen(value)
  if count > MAX_ENVIRONMENT_BYTES then return _error("environment value is too large") end if
  raw = bytes(count, 0)
  if count > 0 then _copyFromNative(raw, value, count) end if
  return decode(raw)
#endif
end function

/// Provide the current directory operation for this standard-library module.
function currentDirectory()
#if TARGET_OS == "windows"
  raw = bytes(MAX_PATH_BYTES * 2, 0)
  actual = GetCurrentDirectoryW(MAX_PATH_BYTES, raw)
  if actual == 0 or actual >= MAX_PATH_BYTES then return _error("cannot read current directory") end if
  return decode16Z(raw)
#else
  raw = bytes(MAX_PATH_BYTES, 0)
  result = _getcwd(raw, len(raw))
  if result == 0 then return _error("cannot read current directory") end if
  return decodeZ(raw)
#endif
end function

/// Updates set current directory.
/// @param path Path to operate on.
function setCurrentDirectory(path)
  if typeof(path) != "string" or len(path) == 0 then return _error("directory must be non-empty") end if
#if TARGET_OS == "windows"
  if not SetCurrentDirectoryW(path) then return _error("cannot change current directory") end if
#else
  if _chdir(path) != 0 then return _error("cannot change current directory") end if
#endif
  return true
end function
