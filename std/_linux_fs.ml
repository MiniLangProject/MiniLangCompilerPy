/*
Copyright 2026 Nils Kopal

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Internal POSIX/glibc implementation used by the public std.fs facade.
//! Provides the std _linux_fs package.

package std._linux_fs
import std.string as s

/// Track the fs err value used by this standard-library module.
/// @internal
const FS_ERR = 1
/// Track the io buf size value used by this standard-library module.
/// @internal
const IO_BUF_SIZE = 4096
/// These layout constants follow the Linux x86-64 glibc ABI. Revisit them when adding another CPU architecture or libc implementation.
/// @internal
const STAT_SIZE = 144
/// Track the stat mode offset value used by this standard-library module.
/// @internal
const STAT_MODE_OFFSET = 24
/// Track the stat file size offset value used by this standard-library module.
/// @internal
const STAT_FILE_SIZE_OFFSET = 48
/// Track the dirent size value used by this standard-library module.
/// @internal
const DIRENT_SIZE = 280
/// Track the dirent name offset value used by this standard-library module.
/// @internal
const DIRENT_NAME_OFFSET = 19

/// Track the o rdonly value used by this standard-library module.
/// @internal
const O_RDONLY = 0
/// Track the o wronly value used by this standard-library module.
/// @internal
const O_WRONLY = 1
/// Track the o creat value used by this standard-library module.
/// @internal
const O_CREAT = 64
/// Track the o trunc value used by this standard-library module.
/// @internal
const O_TRUNC = 512
/// Track the seek set value used by this standard-library module.
/// @internal
const SEEK_SET = 0
/// Track the seek end value used by this standard-library module.
/// @internal
const SEEK_END = 2
/// Track the default file mode value used by this standard-library module.
/// @internal
const DEFAULT_FILE_MODE = 0x1B6 // 0666, filtered by the process umask.
/// Track the s ifmt value used by this standard-library module.
/// @internal
const S_IFMT = 0xF000
/// Track the s ifdir value used by this standard-library module.
/// @internal
const S_IFDIR = 0x4000

/// Provide the open operation for this standard-library module.
/// @internal
extern function _open(path as cstr, flags as int, mode as u32) from "libc.so.6" symbol "open" returns i32
/// Returns read.
/// @internal
extern function _read(fd as int, output as bytes, count as u64) from "libc.so.6" symbol "read" returns i64
/// Updates write bytes.
/// @internal
extern function _writeBytes(fd as int, input as bytes, count as u64) from "libc.so.6" symbol "write" returns i64
/// Updates write text.
/// @internal
extern function _writeText(fd as int, input as cstr, count as u64) from "libc.so.6" symbol "write" returns i64
/// Releases or resets close.
/// @internal
extern function _close(fd as int) from "libc.so.6" symbol "close" returns i32
/// Provide the lseek operation for this standard-library module.
/// @internal
extern function _lseek(fd as int, offset as i64, whence as int) from "libc.so.6" symbol "lseek" returns i64
/// Provide the stat operation for this standard-library module.
/// @internal
extern function _stat(path as cstr, output as bytes) from "libc.so.6" symbol "stat" returns i32
/// Provide the unlink operation for this standard-library module.
/// @internal
extern function _unlink(path as cstr) from "libc.so.6" symbol "unlink" returns i32
/// Provide the rename operation for this standard-library module.
/// @internal
extern function _rename(source as cstr, destination as cstr) from "libc.so.6" symbol "rename" returns i32
/// Provide the opendir operation for this standard-library module.
/// @internal
extern function _opendir(path as cstr) from "libc.so.6" symbol "opendir" returns ptr
/// Returns readdir.
/// @internal
extern function _readdir(directory as ptr) from "libc.so.6" symbol "readdir" returns ptr
/// Releases or resets closedir.
/// @internal
extern function _closedir(directory as ptr) from "libc.so.6" symbol "closedir" returns i32
/// Provide the copy native operation for this standard-library module.
/// @internal
extern function _copyNative(destination as bytes, source as ptr, count as u64) from "libc.so.6" symbol "memcpy" returns ptr
/// Provide the usleep operation for this standard-library module.
/// @internal
extern function _usleep(microseconds as u32) from "libc.so.6" symbol "usleep" returns i32

/// Provide the err operation for this standard-library module.
/// @internal
function _err(message)
  return error(FS_ERR, message)
end function

/// Provide the u32le operation for this standard-library module.
/// @internal
function _u32le(buffer, offset)
  return buffer[offset] | (buffer[offset + 1] << 8) | (buffer[offset + 2] << 16) | (buffer[offset + 3] << 24)
end function

/// Provide the i64le operation for this standard-library module.
/// @internal
function _i64le(buffer, offset)
  value = buffer[offset + 7]
  if value >= 128 then value = value - 256 end if
  i = 6
  while i >= 0
    value = (value << 8) | buffer[offset + i]
    i = i - 1
  end while
  return value
end function

/// Provide the stat buffer operation for this standard-library module.
/// @internal
function _statBuffer(path)
  if typeof(path) != "string" then return end if
  buffer = bytes(STAT_SIZE, 0)
  if _stat(path, buffer) != 0 then return end if
  return buffer
end function

/// Provide the exists operation for this standard-library module.
/// @internal
function exists(path)
  return typeof(_statBuffer(path)) == "bytes"
end function

/// Reports whether is dir.
/// @internal
function isDir(path)
  buffer = _statBuffer(path)
  if typeof(buffer) != "bytes" then return false end if
  mode = _u32le(buffer, STAT_MODE_OFFSET)
  return (mode & S_IFMT) == S_IFDIR
end function

/// Reports whether is file.
/// @internal
function isFile(path)
  return exists(path) and not isDir(path)
end function

/// Provide the join path operation for this standard-library module.
/// @internal
function joinPath(base, name)
  if typeof(base) != "string" or typeof(name) != "string" then return end if
  if base == "" then return name end if
  if s.endsWith(base, "/") or s.endsWith(base, "\\") then return base + name end if
  return base + "/" + name
end function

/// Provide the grow operation for this standard-library module.
/// @internal
function _grow(items, need)
  newLength = len(items)
  if newLength < 8 then newLength = 8 end if
  while newLength < need newLength = newLength * 2 end while
  output = array(newLength)
  if len(items) > 0 then
    for i = 0 to len(items) - 1 output[i] = items[i] end for
  end if
  return output
end function

/// Provide the take operation for this standard-library module.
/// @internal
function _take(items, count)
  if count <= 0 then return [] end if
  output = array(count)
  for i = 0 to count - 1 output[i] = items[i] end for
  return output
end function

/// Provide the list dir operation for this standard-library module.
/// @internal
function listDir(path)
  if typeof(path) != "string" then return _err("listDir: invalid args") end if
  if not isDir(path) then return _err("listDir: not a directory") end if
  directory = _opendir(path)
  if directory == 0 then return _err("listDir: opendir failed") end if

  names = array(8)
  count = 0
  entryBuffer = bytes(DIRENT_SIZE, 0)
  while true
    entry = _readdir(directory)
    if entry == 0 then break end if
    _copyNative(entryBuffer, entry, DIRENT_SIZE)
    name = decodeZ(slice(entryBuffer, DIRENT_NAME_OFFSET, DIRENT_SIZE - DIRENT_NAME_OFFSET))
    if typeof(name) == "string" and name != "." and name != ".." then
      if count == len(names) then names = _grow(names, count + 1) end if
      names[count] = name
      count = count + 1
    end if
  end while
  _closedir(directory)
  return _take(names, count)
end function

/// Releases or resets delete.
/// @internal
function delete(path)
  if typeof(path) != "string" then return false end if
  if not exists(path) then return true end if
  i = 0
  while i < 30
    if _unlink(path) == 0 then return true end if
    if not exists(path) then return true end if
    _usleep(5000)
    i = i + 1
  end while
  return false
end function

/// Provide the open write operation for this standard-library module.
/// @internal
function _openWrite(path)
  fd = _open(path, O_WRONLY | O_CREAT | O_TRUNC, DEFAULT_FILE_MODE)
  if fd < 0 then return _err("open for writing failed") end if
  return fd
end function

/// Updates write all bytes.
/// @internal
function writeAllBytes(path, data)
  if typeof(path) != "string" or typeof(data) != "bytes" then return _err("writeAllBytes: invalid args") end if
  fd = _openWrite(path)
  if typeof(fd) == "error" then return fd end if
  position = 0
  while position < len(data)
    chunk = slice(data, position, len(data) - position)
    written = _writeBytes(fd, chunk, len(chunk))
    if written <= 0 then
      _close(fd)
      return _err("writeAllBytes: write failed")
    end if
    position = position + written
  end while
  _close(fd)
  return true
end function

/// Updates write all text.
/// @internal
function writeAllText(path, text)
  if typeof(path) != "string" or typeof(text) != "string" then return _err("writeAllText: invalid args") end if
  result = writeAllBytes(path, bytes(text))
  if typeof(result) == "error" then return _err("writeAllText: write failed") end if
  return result
end function

/// Returns read all bytes.
/// @internal
function readAllBytes(path)
  if typeof(path) != "string" then return _err("readAllBytes: invalid args") end if
  fd = _open(path, O_RDONLY, 0)
  if fd < 0 then return _err("readAllBytes: open failed") end if
  size = _lseek(fd, 0, SEEK_END)
  if size < 0 or size > 0x7FFFFFFF then
    _close(fd)
    return _err("readAllBytes: invalid file size")
  end if
  _lseek(fd, 0, SEEK_SET)
  output = bytes(size, 0)
  buffer = bytes(IO_BUF_SIZE, 0)
  position = 0
  while position < size
    wanted = size - position
    if wanted > IO_BUF_SIZE then wanted = IO_BUF_SIZE end if
    got = _read(fd, buffer, wanted)
    if got < 0 then
      _close(fd)
      return _err("readAllBytes: read failed")
    end if
    if got == 0 then break end if
    copyBytes(output, position, buffer, 0, got)
    position = position + got
  end while
  _close(fd)
  if position != size then output = slice(output, 0, position) end if
  return output
end function

/// Returns read all text.
/// @internal
function readAllText(path)
  data = readAllBytes(path)
  if typeof(data) == "error" then return data end if
  if len(data) == 0 then return "" end if
  text = decode(data)
  if typeof(text) != "string" then return _err("readAllText: invalid UTF-8") end if
  return text
end function

/// Provide the copy file operation for this standard-library module.
/// @internal
function copyFile(sourcePath, destinationPath, overwrite)
  if typeof(sourcePath) != "string" or typeof(destinationPath) != "string" then return _err("copyFile: invalid args") end if
  if not exists(sourcePath) then return _err("copyFile: source not found") end if
  if typeof(overwrite) != "bool" then overwrite = false end if
  if exists(destinationPath) and not overwrite then return _err("copyFile: destination exists") end if
  data = readAllBytes(sourcePath)
  if typeof(data) == "error" then return data end if
  return writeAllBytes(destinationPath, data)
end function

/// Provide the move file operation for this standard-library module.
/// @internal
function moveFile(sourcePath, destinationPath, overwrite)
  if typeof(sourcePath) != "string" or typeof(destinationPath) != "string" then return _err("moveFile: invalid args") end if
  if not exists(sourcePath) then return _err("moveFile: source not found") end if
  if typeof(overwrite) != "bool" then overwrite = false end if
  if exists(destinationPath) then
    if not overwrite then return _err("moveFile: destination exists") end if
    if not delete(destinationPath) then return _err("moveFile: destination delete failed") end if
  end if
  if _rename(sourcePath, destinationPath) != 0 then return _err("moveFile: rename failed") end if
  return true
end function

/// Provide the file size operation for this standard-library module.
/// @internal
function fileSize(path)
  buffer = _statBuffer(path)
  if typeof(buffer) != "bytes" then return _err("fileSize: stat failed") end if
  return _i64le(buffer, STAT_FILE_SIZE_OFFSET)
end function

/// Updates append all bytes.
/// @internal
function appendAllBytes(path, data)
  if typeof(path) != "string" or typeof(data) != "bytes" then return _err("appendAllBytes: invalid args") end if
  if not exists(path) then return writeAllBytes(path, data) end if
  previous = readAllBytes(path)
  if typeof(previous) == "error" then return previous end if
  return writeAllBytes(path, previous + data)
end function

/// Updates append all text.
/// @internal
function appendAllText(path, text)
  if typeof(path) != "string" or typeof(text) != "string" then return _err("appendAllText: invalid args") end if
  if not exists(path) then return writeAllText(path, text) end if
  previous = readAllText(path)
  if typeof(previous) == "error" then return previous end if
  return writeAllText(path, previous + text)
end function

/// Returns read all lines.
/// @internal
function readAllLines(path)
  text = readAllText(path)
  if typeof(text) == "error" then return text end if
  lines = s.split(text, "\n")
  if typeof(lines) == "void" then return [] end if
  i = 0
  while i < len(lines)
    if len(lines[i]) > 0 and s.endsWith(lines[i], "\r") then lines[i] = s.substr(lines[i], 0, len(lines[i]) - 1) end if
    i = i + 1
  end while
  return lines
end function
