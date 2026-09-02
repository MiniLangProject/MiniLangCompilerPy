/*
Copyright 2026 Nils Kopal

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Terminal helpers with echo-safe secret input.  Secrets are returned as UTF-8
// bytes so callers can erase them in place after use.
//! Provides the std console package.

package std.console

/// Stores the console err.
const CONSOLE_ERR = 262
/// Stores the std input handle.
const STD_INPUT_HANDLE = -10
/// Stores the std output handle.
const STD_OUTPUT_HANDLE = -11
/// Stores the enable echo input.
const ENABLE_ECHO_INPUT = 4
/// Stores the enable quick edit mode.
const ENABLE_QUICK_EDIT_MODE = 0x40
/// Stores the enable extended flags.
const ENABLE_EXTENDED_FLAGS = 0x80
/// Stores the cp utf8.
const CP_UTF8 = 65001
/// Stores the wc err invalid chars.
const WC_ERR_INVALID_CHARS = 0x80
/// Stores the max secret utf16 units.
const MAX_SECRET_UTF16_UNITS = 4096

/// Implements error.
/// @internal
function _error(message)
  return error(CONSOLE_ERR, message)
end function

/// Implements u32.
/// @internal
function _u32(buffer)
  return buffer[0] | (buffer[1] << 8) | (buffer[2] << 16) | (buffer[3] << 24)
end function

/// Implements u16.
/// @internal
function _u16(buffer, offset)
  return buffer[offset] | (buffer[offset + 1] << 8)
end function

/// Implements wipe.
/// @param buffer Buffer to process.
function wipe(buffer)
  if typeof(buffer) != "bytes" then return false end if
  if len(buffer) > 0 then fillBytes(buffer, 0, len(buffer), 0) end if
  return true
end function

#if TARGET_OS == "windows"
/// Returns get std handle.
/// @internal
extern function GetStdHandle(kind as i32) from "kernel32.dll" returns ptr
/// Returns get console mode.
/// @internal
extern function GetConsoleMode(handle as ptr, mode as bytes) from "kernel32.dll" returns bool
/// Updates set console mode.
/// @internal
extern function SetConsoleMode(handle as ptr, mode as u32) from "kernel32.dll" returns bool
/// Returns read console w.
/// @internal
extern function ReadConsoleW(handle as ptr, buffer as bytes, count as u32, readOut as bytes, control as ptr) from "kernel32.dll" returns bool
/// Updates write console w.
/// @internal
extern function WriteConsoleW(handle as ptr, text as wstr, count as u32, writtenOut as bytes, reserved as ptr) from "kernel32.dll" returns bool
/// Implements wide char to multi byte.
/// @internal
extern function WideCharToMultiByte(codePage as u32, flags as u32, wideText as bytes, wideCount as i32, output as bytes, outputCount as i32, defaultChar as ptr, usedDefault as ptr) from "kernel32.dll" returns i32
#else
/// Reports whether isatty.
/// @internal
extern function _isatty(fd as int) from "libc.so.6" symbol "isatty" returns i32
/// Returns getpass.
/// @internal
extern function _getpass(prompt as cstr) from "libc.so.6" symbol "getpass" returns ptr
/// Implements strlen.
/// @internal
extern function _strlen(value as ptr) from "libc.so.6" symbol "strlen" returns u64
/// Implements copy from native.
/// @internal
extern function _copyFromNative(output as bytes, value as ptr, count as u64) from "libc.so.6" symbol "memcpy" returns ptr
/// Implements wipe native.
/// @internal
extern function _wipeNative(value as ptr, count as u64) from "libc.so.6" symbol "explicit_bzero" returns void
#endif

/// Reports whether is interactive.
function isInteractive()
#if TARGET_OS == "windows"
  handle = GetStdHandle(STD_INPUT_HANDLE)
  if handle == 0 or handle == -1 then return false end if
  mode = bytes(4, 0)
  return GetConsoleMode(handle, mode)
#else
  return _isatty(0) == 1
#endif
end function

/// Prevent Windows QuickEdit from suspending a server process. Other targets have no equivalent mode and report success without changing terminal state.
function disableQuickEdit()
#if TARGET_OS == "windows"
  handle = GetStdHandle(STD_INPUT_HANDLE)
  if handle == 0 or handle == -1 then return true end if
  modeBytes = bytes(4, 0)
  if not GetConsoleMode(handle, modeBytes) then return true end if
  current = _u32(modeBytes)
  safe = (current | ENABLE_EXTENDED_FLAGS) & ~ENABLE_QUICK_EDIT_MODE
  if safe != current and not SetConsoleMode(handle, safe) then return _error("cannot disable QuickEdit") end if
#endif
  return true
end function

/// Returns read secret.
/// @param prompt Value supplied for `prompt`.
/// @param maximumBytes Value supplied for `maximumBytes`.
function readSecret(prompt, maximumBytes)
  if typeof(prompt) != "string" then return _error("prompt must be string") end if
  if typeof(maximumBytes) != "int" or maximumBytes < 0 or maximumBytes > 1048576 then return _error("invalid maximum secret length") end if
#if TARGET_OS == "windows"
  inputHandle = GetStdHandle(STD_INPUT_HANDLE)
  outputHandle = GetStdHandle(STD_OUTPUT_HANDLE)
  if inputHandle == 0 or inputHandle == -1 or outputHandle == 0 or outputHandle == -1 then return _error("console handles are unavailable") end if
  modeBytes = bytes(4, 0)
  if not GetConsoleMode(inputHandle, modeBytes) then return _error("standard input is not a console") end if
  oldMode = _u32(modeBytes)
  if not SetConsoleMode(inputHandle, oldMode & ~ENABLE_ECHO_INPUT) then return _error("cannot disable console echo") end if
  promptRaw = bytes(prompt)
  i = 0
  while i < len(promptRaw)
    if promptRaw[i] > 127 then SetConsoleMode(inputHandle, oldMode); return _error("prompt must be ASCII") end if
    i = i + 1
  end while
  written = bytes(4, 0)
  promptOk = WriteConsoleW(outputHandle, prompt, len(promptRaw), written, 0)
  wide = bytes((MAX_SECRET_UTF16_UNITS + 2) * 2, 0)
  readOut = bytes(4, 0)
  readOk = false
  if promptOk then readOk = ReadConsoleW(inputHandle, wide, MAX_SECRET_UTF16_UNITS + 1, readOut, 0) end if
  restored = SetConsoleMode(inputHandle, oldMode)
  ignoredNewline = WriteConsoleW(outputHandle, "\r\n", 2, written, 0)
  if not restored or not readOk then wipe(wide); return _error("secret input failed") end if
  units = _u32(readOut)
  while units > 0 and (_u16(wide, (units - 1) * 2) == 10 or _u16(wide, (units - 1) * 2) == 13)
    units = units - 1
  end while
  required = 0
  if units > 0 then required = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, units, void, 0, 0, 0) end if
  if required < 0 or required > maximumBytes then wipe(wide); return _error("secret exceeds configured limit") end if
  output = bytes(required, 0)
  if required > 0 and WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, units, output, required, 0, 0) != required then
    wipe(wide)
    wipe(output)
    return _error("secret UTF-8 conversion failed")
  end if
  wipe(wide)
  wipe(readOut)
  return output
#else
  value = _getpass(prompt)
  if value == 0 then return _error("secret input failed") end if
  count = _strlen(value)
  if count > maximumBytes then _wipeNative(value, count); return _error("secret exceeds configured limit") end if
  output = bytes(count, 0)
  if count > 0 then _copyFromNative(output, value, count) end if
  _wipeNative(value, count)
  return output
#endif
end function

/// Returns read password.
/// @param prompt Value supplied for `prompt`.
function readPassword(prompt)
  return readSecret(prompt, 4096)
end function

/// Returns read secret confirmed.
/// @param prompt Value supplied for `prompt`.
/// @param confirmationPrompt Value supplied for `confirmationPrompt`.
/// @param maximumBytes Value supplied for `maximumBytes`.
function readSecretConfirmed(prompt, confirmationPrompt, maximumBytes)
  first = readSecret(prompt, maximumBytes)
  if typeof(first) == "error" then return first end if
  second = readSecret(confirmationPrompt, maximumBytes)
  if typeof(second) == "error" then wipe(first); return second end if
  same = bytesConstantTimeEquals(first, second)
  wipe(second)
  if not same then wipe(first); return _error("secret confirmation does not match") end if
  return first
end function
