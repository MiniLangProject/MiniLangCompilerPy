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

package std.fs

// ------------------------------------------------------------
// Error helper (stdlib migrated to value-or-error)
// ------------------------------------------------------------
function _fsErr(msg)
  return error(1, msg)
end function

import std.result as r
import std.string as s

// ------------------------------------------------------------
// std.fs (native Win32)
// Declaration-only: only imports/externs/functions.
// ------------------------------------------------------------

// ------------------------------------------------------------
// Win32 constants (kept local to std.fs)
// ------------------------------------------------------------

const INVALID_HANDLE_VALUE = -1
const INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF

enum Access
  GENERIC_READ = 0x80000000
  GENERIC_WRITE = 0x40000000
end enum

enum Share
  NONE = 0
  FILE_SHARE_READ = 0x00000001
  FILE_SHARE_WRITE = 0x00000002
  FILE_SHARE_DELETE = 0x00000004
end enum

enum Creation
  CREATE_NEW = 1
  CREATE_ALWAYS = 2
  OPEN_EXISTING = 3
  OPEN_ALWAYS = 4
  TRUNCATE_EXISTING = 5
end enum

enum FileAttr
  FILE_ATTRIBUTE_READONLY = 0x00000001
  FILE_ATTRIBUTE_HIDDEN = 0x00000002
  FILE_ATTRIBUTE_SYSTEM = 0x00000004
  FILE_ATTRIBUTE_DIRECTORY = 0x00000010
  FILE_ATTRIBUTE_ARCHIVE = 0x00000020
  FILE_ATTRIBUTE_NORMAL = 0x00000080
  FILE_ATTRIBUTE_TEMPORARY = 0x00000100
  FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
  FILE_ATTRIBUTE_COMPRESSED = 0x00000800
  FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x00002000
  FILE_ATTRIBUTE_ENCRYPTED = 0x00004000
end enum

const DWORD_SIZE = 4
const IO_BUF_SIZE = 4096
const DELETE_RETRY_COUNT = 30
const DELETE_RETRY_SLEEP_MS = 5

extern function CreateFileW(
path as wstr,
access as int,
share as int,
security as ptr,
creation as int,
flags as int,
template as ptr
) from "kernel32.dll" returns ptr

extern function ReadFile(
h as ptr,
buf as bytes,
n as int,
bytesRead as bytes,
overlapped as ptr
) from "kernel32.dll" returns bool

extern function WriteFile(
h as ptr,
buf as bytes,
n as int,
bytesWritten as bytes,
overlapped as ptr
) from "kernel32.dll" returns bool

extern function WriteFileCStr(
h as ptr,
buf as cstr,
n as int,
bytesWritten as bytes,
overlapped as ptr
) from "kernel32.dll" symbol "WriteFile" returns bool

extern function CloseHandle(h as ptr) from "kernel32.dll" returns bool
extern function DeleteFileW(path as wstr) from "kernel32.dll" returns bool
extern function CopyFileW(existingPath as wstr, newPath as wstr, failIfExists as bool) from "kernel32.dll" returns bool
extern function MoveFileW(existingPath as wstr, newPath as wstr) from "kernel32.dll" returns bool
extern function GetFileAttributesW(path as wstr) from "kernel32.dll" returns u32
extern function GetFileSizeEx(h as ptr, sizeBuf as bytes) from "kernel32.dll" returns bool
extern function Sleep(ms as int) from "kernel32.dll" returns int

/*
decode a 32-bit little-endian unsigned integer from a bytes(4) buffer
input: bytes b4
returns: int value
*/
function _u32le4(b4)
  // b4 is bytes(4)
  return b4[0] + b4[1] * 256 + b4[2] * 65536 + b4[3] * 16777216
end function

/*
decode a 64-bit little-endian unsigned integer from a bytes(8) buffer
input: bytes b8
returns: int value
*/
function _u64le8(b8)
  return b8[0] + b8[1] * 256 + b8[2] * 65536 + b8[3] * 16777216 + b8[4] * 4294967296 + b8[5] * 1099511627776 + b8[6] * 281474976710656 + b8[7] * 72057594037927936
end function

/*
check whether a file or directory exists
input: string path
returns: bool exists
*/
function exists(path)
  a = GetFileAttributesW(path)
  if a == std.fs.INVALID_FILE_ATTRIBUTES then
    return false
  end if
  return true
end function

/*
delete a file (treats "already missing" as success)
input: string path
returns: bool success
*/
function delete(path)
  if typeof(path) != "string" then
    return false
  end if

  // Treat "already gone" as success.
  if exists(path) == false then
    return true
  end if

  // Some Windows components (AV/indexer) can briefly hold a handle after a write.
  // Retry a few times to make deletes reliable in tight test loops.
  i = 0
  while i < std.fs.DELETE_RETRY_COUNT
    ok = DeleteFileW(path)
    if ok == true then
      return true
    end if
    if exists(path) == false then
      return true
    end if
    Sleep(std.fs.DELETE_RETRY_SLEEP_MS)
    i = i + 1
  end while
  return false
end function

/*
write all bytes to a file (overwrites if it exists)
input: string path, bytes data
returns: Result<bool, string> ok
*/
function writeAllBytes(path, data)
  if typeof(path) != "string" or typeof(data) != "bytes" then
    return _fsErr("writeAllBytes: invalid args")
  end if

  h = CreateFileW(path, std.fs.Access.GENERIC_WRITE, std.fs.Share.NONE, 0, std.fs.Creation.CREATE_ALWAYS, std.fs.FileAttr.FILE_ATTRIBUTE_NORMAL, 0)
  if h == std.fs.INVALID_HANDLE_VALUE then
    return _fsErr("writeAllBytes: CreateFileW failed")
  end if

  n = len(data)
  bw4 = bytes(std.fs.DWORD_SIZE)
  ok = WriteFile(h, data, n, bw4, 0)
  CloseHandle(h)

  if ok == false then
    return _fsErr("writeAllBytes: WriteFile failed")
  end if

  return true
end function

/*
read all bytes from a file
input: string path
returns: Result<bytes, string> bytes
*/
function readAllBytes(path)
  if typeof(path) != "string" then
    return _fsErr("readAllBytes: invalid args")
  end if

  h = CreateFileW(
  path,
  std.fs.Access.GENERIC_READ,
  std.fs.Share.FILE_SHARE_READ,
  0,
  std.fs.Creation.OPEN_EXISTING,
  std.fs.FileAttr.FILE_ATTRIBUTE_NORMAL,
  0
)
  if h == std.fs.INVALID_HANDLE_VALUE then
    return _fsErr("readAllBytes: CreateFileW failed")
  end if

  // --- file size (u64) via GetFileSizeEx ---
  sz8 = bytes(8)
  ok = GetFileSizeEx(h, sz8)
  if ok == false then
    CloseHandle(h)
    return _fsErr("readAllBytes: GetFileSizeEx failed")
  end if

  lo = sz8[0] |(sz8[1] << 8) |(sz8[2] << 16) |(sz8[3] << 24)
  hi = sz8[4] |(sz8[5] << 8) |(sz8[6] << 16) |(sz8[7] << 24)

  if hi != 0 or lo > 0x7FFFFFFF then
    CloseHandle(h)
    return _fsErr("readAllBytes: file too large")
  end if

  size = lo

  // --- single big allocation ---
  output = bytes(size)

  // --- streaming read into temp buf + copy into output ---
  buf = bytes(std.fs.IO_BUF_SIZE)
  br4 = bytes(std.fs.DWORD_SIZE)

  pos = 0
  while pos < size
    toRead = size - pos
    if toRead > std.fs.IO_BUF_SIZE then
      toRead = std.fs.IO_BUF_SIZE
    end if

    ok = ReadFile(h, buf, toRead, br4, 0)
    if ok == false then
      CloseHandle(h)
      return _fsErr("readAllBytes: ReadFile failed")
    end if

    n = _u32le4(br4)
    if n <= 0 then
      break
    end if

    i = 0
    while i < n
      output[pos + i] = buf[i]
      i = i + 1
    end while

    pos = pos + n
  end while

  CloseHandle(h)

  if pos != size then
    output = slice(output, 0, pos)
  end if

  return output
end function

/*
write all text to a file (overwrites if it exists)
input: string path, string text
returns: Result<bool, string> ok
*/
function writeAllText(path, text)
  if typeof(path) != "string" or typeof(text) != "string" then
    return _fsErr("writeAllText: invalid args")
  end if

  h = CreateFileW(path, std.fs.Access.GENERIC_WRITE, std.fs.Share.NONE, 0, std.fs.Creation.CREATE_ALWAYS, std.fs.FileAttr.FILE_ATTRIBUTE_NORMAL, 0)
  if h == std.fs.INVALID_HANDLE_VALUE then
    return _fsErr("writeAllText: CreateFileW failed")
  end if

  n = len(text)
  bw4 = bytes(std.fs.DWORD_SIZE)
  ok = WriteFileCStr(h, text, n, bw4, 0)
  CloseHandle(h)

  if ok == false then
    return _fsErr("writeAllText: WriteFile failed")
  end if

  return true
end function

/*
read all text from a file (assumes UTF-8)
input: string path
returns: Result<string, string> text
*/
function readAllText(path)
  if typeof(path) != "string" then
    return _fsErr("readAllText: invalid args")
  end if

  h = CreateFileW(
  path,
  std.fs.Access.GENERIC_READ,
  std.fs.Share.FILE_SHARE_READ,
  0,
  std.fs.Creation.OPEN_EXISTING,
  std.fs.FileAttr.FILE_ATTRIBUTE_NORMAL,
  0
)
  if h == std.fs.INVALID_HANDLE_VALUE then
    return _fsErr("readAllText: CreateFileW failed")
  end if

  // --- file size (u64) via GetFileSizeEx ---
  sz8 = bytes(8)
  ok = GetFileSizeEx(h, sz8)
  if ok == false then
    CloseHandle(h)
    return _fsErr("readAllText: GetFileSizeEx failed")
  end if

  lo = sz8[0] |(sz8[1] << 8) |(sz8[2] << 16) |(sz8[3] << 24)
  hi = sz8[4] |(sz8[5] << 8) |(sz8[6] << 16) |(sz8[7] << 24)

  if hi != 0 or lo > 0x7FFFFFFF then
    CloseHandle(h)
    return _fsErr("readAllText: file too large")
  end if

  size = lo

  // Empty file -> empty string (avoid decode(bytes(0)) yielding void)
  if size == 0 then
    CloseHandle(h)
    return ""
  end if

  // --- single big allocation ---
  output = bytes(size)

  // --- streaming read into temp buf + copy into output ---
  buf = bytes(std.fs.IO_BUF_SIZE)
  br4 = bytes(std.fs.DWORD_SIZE)

  pos = 0
  while pos < size
    toRead = size - pos
    if toRead > std.fs.IO_BUF_SIZE then
      toRead = std.fs.IO_BUF_SIZE
    end if

    ok = ReadFile(h, buf, toRead, br4, 0)
    if ok == false then
      CloseHandle(h)
      return _fsErr("readAllText: ReadFile failed")
    end if

    n = _u32le4(br4)
    if n <= 0 then
      break
    end if

    i = 0
    while i < n
      output[pos + i] = buf[i]
      i = i + 1
    end while

    pos = pos + n
  end while

  CloseHandle(h)

  if pos != size then
    output = slice(output, 0, pos)
  end if

  t = decode(output)
  if typeof(t) == "void" then
    return _fsErr("readAllText: decode failed (not UTF-8?)")
  end if
  return t
end function

/*
copy a file
input: string sourcePath, string destPath, bool overwrite
returns: Result<bool, string> ok
*/
function copyFile(sourcePath, destPath, overwrite)
  if typeof(sourcePath) != "string" or typeof(destPath) != "string" then
    return _fsErr("copyFile: invalid args")
  end if
  if typeof(overwrite) != "bool" then
    overwrite = false
  end if
  if exists(sourcePath) == false then
    return _fsErr("copyFile: source not found")
  end if

  // CopyFileW uses a fail-if-exists flag.
  ok = CopyFileW(sourcePath, destPath, overwrite == false)
  if ok == false then
    return _fsErr("copyFile: CopyFileW failed")
  end if
  return true
end function

/*
move/rename a file
input: string sourcePath, string destPath, bool overwrite
returns: Result<bool, string> ok
*/
function moveFile(sourcePath, destPath, overwrite)
  if typeof(sourcePath) != "string" or typeof(destPath) != "string" then
    return _fsErr("moveFile: invalid args")
  end if
  if typeof(overwrite) != "bool" then
    overwrite = false
  end if
  if exists(sourcePath) == false then
    return _fsErr("moveFile: source not found")
  end if

  if overwrite and exists(destPath) then
    if delete(destPath) == false then
      return _fsErr("moveFile: failed to delete destination")
    end if
  end if

  ok = MoveFileW(sourcePath, destPath)
  if ok == false then
    return _fsErr("moveFile: MoveFileW failed")
  end if
  return true
end function

/*
get the size of a file in bytes
input: string path
returns: Result<int, string> size
*/
function fileSize(path)
  if typeof(path) != "string" then
    return _fsErr("fileSize: invalid args")
  end if

  h = CreateFileW(path, std.fs.Access.GENERIC_READ, std.fs.Share.FILE_SHARE_READ, 0, std.fs.Creation.OPEN_EXISTING, std.fs.FileAttr.FILE_ATTRIBUTE_NORMAL, 0)
  if h == std.fs.INVALID_HANDLE_VALUE then
    return _fsErr("fileSize: CreateFileW failed")
  end if

  sizeBuf = bytes(8)
  ok = GetFileSizeEx(h, sizeBuf)
  CloseHandle(h)
  if ok == false then
    return _fsErr("fileSize: GetFileSizeEx failed")
  end if

  return _u64le8(sizeBuf)
end function

/*
append bytes to a file (simple implementation: read + rewrite)
input: string path, bytes data
returns: Result<bool, string> ok
*/
function appendAllBytes(path, data)
  if typeof(path) != "string" or typeof(data) != "bytes" then
    return _fsErr("appendAllBytes: invalid args")
  end if

  if exists(path) == false then
    return writeAllBytes(path, data)
  end if

  prev = readAllBytes(path)
  if typeof(prev) == "error" then
    return prev
  end if

  return writeAllBytes(path, prev + data)
end function

/*
append text to a file (simple implementation: read + rewrite)
input: string path, string text
returns: Result<bool, string> ok
*/
function appendAllText(path, text)
  if typeof(path) != "string" or typeof(text) != "string" then
    return _fsErr("appendAllText: invalid args")
  end if

  if exists(path) == false then
    return writeAllText(path, text)
  end if

  prev = readAllText(path)
  if typeof(prev) == "error" then
    return prev
  end if

  return writeAllText(path, prev + text)
end function

/*
read a file as lines (split by '\n', trims a trailing '\r')
input: string path
returns: Result<array, string> lines
*/
function readAllLines(path)
  t = readAllText(path)
  if typeof(t) == "error" then
    return t
  end if

  // Keep empty trailing line behavior consistent with std.string.split.
  lines = s.split(t, "\n")
  if typeof(lines) == "void" then
    return []
  end if

  i = 0
  while i < len(lines)
    line = lines[i]
    // trim a single trailing CR
    if len(line) > 0 and s.endsWith(line, "\r") then
      lines[i] = s.substr(line, 0, len(line) - 1)
    end if
    i = i + 1
  end while

  return lines
end function

