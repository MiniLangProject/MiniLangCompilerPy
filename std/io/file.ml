/*
Copyright 2026 Nils Kopal

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Durable random-access file API for database engines and other stateful
// services.  One handle must not be repositioned concurrently on Windows;
// callers that need parallel reads should open one handle per worker.
//! Provides the std io file package.

package std.io.file
import std.fs as fs
import std.path as path_api

/// Stores the file err.
const FILE_ERR = 263
/// Stores the lock conflict.
const LOCK_CONFLICT = 264
/// Stores the closed handle.
const CLOSED_HANDLE = 265
/// Stores the max io count.
const MAX_IO_COUNT = 0x7FFFFFFF

/// Represents file handle.
struct FileHandle
  /// Stores the path member of `FileHandle`.
  path
  /// Stores the native handle member of `FileHandle`.
  nativeHandle
  /// Stores the readable member of `FileHandle`.
  readable
  /// Stores the writable member of `FileHandle`.
  writable
  /// Stores the durable member of `FileHandle`.
  durable
  /// Stores the closed member of `FileHandle`.
  closed
  /// Stores the lock mode member of `FileHandle`.
  lockMode
end struct

/// Implements error.
/// @internal
function _error(code, operation, message)
  return error(code, "std.io.file." + operation + ": " + message)
end function

/// Implements u32.
/// @internal
function _u32(buffer, offset)
  return buffer[offset] | (buffer[offset + 1] << 8) | (buffer[offset + 2] << 16) | (buffer[offset + 3] << 24)
end function

/// Implements i64.
/// @internal
function _i64(buffer, offset)
  value = buffer[offset + 7]
  if value >= 128 then value = value - 256 end if
  i = 6
  while i >= 0
    value = (value << 8) | buffer[offset + i]
    i = i - 1
  end while
  return value
end function

/// Implements valid slice.
/// @internal
function _validSlice(buffer, offset, count, operation)
  if typeof(buffer) != "bytes" then return _error(FILE_ERR, operation, "buffer must be bytes") end if
  if typeof(offset) != "int" or typeof(count) != "int" or offset < 0 or count < 0 or offset > len(buffer) or count > len(buffer) - offset then
    return _error(FILE_ERR, operation, "buffer range is invalid")
  end if
  if count > MAX_IO_COUNT then return _error(FILE_ERR, operation, "I/O count is too large") end if
  return true
end function

/// Implements validate open.
/// @internal
function _validateOpen(file, operation)
  if file is not FileHandle then return _error(FILE_ERR, operation, "value must be FileHandle") end if
  if file.closed then return _error(CLOSED_HANDLE, operation, "file handle is closed") end if
  return true
end function

#if TARGET_OS == "windows"
/// Stores the generic read.
const GENERIC_READ = 0x80000000
/// Stores the generic write.
const GENERIC_WRITE = 0x40000000
/// Stores the file share all.
const FILE_SHARE_ALL = 7
/// Stores the create new.
const CREATE_NEW = 1
/// Stores the create always.
const CREATE_ALWAYS = 2
/// Stores the open existing.
const OPEN_EXISTING = 3
/// Stores the open always.
const OPEN_ALWAYS = 4
/// Stores the file attribute normal.
const FILE_ATTRIBUTE_NORMAL = 0x80
/// Stores the file flag write through.
const FILE_FLAG_WRITE_THROUGH = 0x80000000
/// Stores the file flag backup semantics.
const FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
/// Stores the file begin.
const FILE_BEGIN = 0
/// Stores the lockfile fail immediately.
const LOCKFILE_FAIL_IMMEDIATELY = 1
/// Stores the lockfile exclusive lock.
const LOCKFILE_EXCLUSIVE_LOCK = 2
/// Stores the error lock violation.
const ERROR_LOCK_VIOLATION = 33
/// Stores the movefile replace existing.
const MOVEFILE_REPLACE_EXISTING = 1
/// Stores the movefile write through.
const MOVEFILE_WRITE_THROUGH = 8

/// Creates create file w.
/// @internal
extern function CreateFileW(path as wstr, access as u32, share as u32, security as ptr, creation as u32, flags as u32, template as ptr) from "kernel32.dll" returns ptr
/// Returns read file.
/// @internal
extern function ReadFile(handle as ptr, output as bytes, count as u32, actual as bytes, overlapped as ptr) from "kernel32.dll" returns bool
/// Updates write file.
/// @internal
extern function WriteFile(handle as ptr, input as bytes, count as u32, actual as bytes, overlapped as ptr) from "kernel32.dll" returns bool
/// Updates set file pointer ex.
/// @internal
extern function SetFilePointerEx(handle as ptr, distance as i64, newPosition as ptr, method as u32) from "kernel32.dll" returns bool
/// Returns get file size ex.
/// @internal
extern function GetFileSizeEx(handle as ptr, output as bytes) from "kernel32.dll" returns bool
/// Updates set end of file.
/// @internal
extern function SetEndOfFile(handle as ptr) from "kernel32.dll" returns bool
/// Implements flush file buffers.
/// @internal
extern function FlushFileBuffers(handle as ptr) from "kernel32.dll" returns bool
/// Implements lock file ex.
/// @internal
extern function LockFileEx(handle as ptr, flags as u32, reserved as u32, lowCount as u32, highCount as u32, overlapped as bytes) from "kernel32.dll" returns bool
/// Implements unlock file ex.
/// @internal
extern function UnlockFileEx(handle as ptr, reserved as u32, lowCount as u32, highCount as u32, overlapped as bytes) from "kernel32.dll" returns bool
/// Releases or resets close handle.
/// @internal
extern function CloseHandle(handle as ptr) from "kernel32.dll" returns bool
/// Returns get last error.
/// @internal
extern function GetLastError() from "kernel32.dll" returns u32
/// Creates create directory w.
/// @internal
extern function CreateDirectoryW(path as wstr, security as ptr) from "kernel32.dll" returns bool
/// Releases or resets remove directory w.
/// @internal
extern function RemoveDirectoryW(path as wstr) from "kernel32.dll" returns bool
/// Implements move file ex w.
/// @internal
extern function MoveFileExW(source as wstr, destination as wstr, flags as u32) from "kernel32.dll" returns bool
#else
/// Stores the o rdonly.
const O_RDONLY = 0
/// Stores the o wronly.
const O_WRONLY = 1
/// Stores the o rdwr.
const O_RDWR = 2
/// Stores the o creat.
const O_CREAT = 64
/// Stores the o excl.
const O_EXCL = 128
/// Stores the o trunc.
const O_TRUNC = 512
/// Stores the o dsync.
const O_DSYNC = 4096
/// Stores the o directory.
const O_DIRECTORY = 65536
/// Stores the o cloexec.
const O_CLOEXEC = 524288
/// Stores the default file mode.
const DEFAULT_FILE_MODE = 0x1B6
/// Stores the default directory mode.
const DEFAULT_DIRECTORY_MODE = 0x1FF
/// Stores the lock shared.
const LOCK_SHARED = 1
/// Stores the lock exclusive.
const LOCK_EXCLUSIVE = 2
/// Stores the lock nonblocking.
const LOCK_NONBLOCKING = 4
/// Stores the lock unlock.
const LOCK_UNLOCK = 8
/// Stores the ewouldblock.
const EWOULDBLOCK = 11
/// These offsets follow the Linux x86-64 glibc stat ABI. Revisit them for another CPU architecture or libc implementation.
const STAT_SIZE = 144
/// Stores the stat file size offset.
const STAT_FILE_SIZE_OFFSET = 48

/// Implements open.
/// @internal
extern function _open(path as cstr, flags as int, mode as u32) from "libc.so.6" symbol "open" returns i32
/// Implements pread.
/// @internal
extern function _pread(handle as int, output as bytes, count as u64, offset as i64) from "libc.so.6" symbol "pread" returns i64
/// Implements pwrite.
/// @internal
extern function _pwrite(handle as int, input as bytes, count as u64, offset as i64) from "libc.so.6" symbol "pwrite" returns i64
/// Implements fstat.
/// @internal
extern function _fstat(handle as int, output as bytes) from "libc.so.6" symbol "fstat" returns i32
/// Implements ftruncate.
/// @internal
extern function _ftruncate(handle as int, size as i64) from "libc.so.6" symbol "ftruncate" returns i32
/// Implements fsync.
/// @internal
extern function _fsync(handle as int) from "libc.so.6" symbol "fsync" returns i32
/// Implements flock.
/// @internal
extern function _flock(handle as int, operation as int) from "libc.so.6" symbol "flock" returns i32
/// Releases or resets close.
/// @internal
extern function _close(handle as int) from "libc.so.6" symbol "close" returns i32
/// Implements mkdir.
/// @internal
extern function _mkdir(path as cstr, mode as u32) from "libc.so.6" symbol "mkdir" returns i32
/// Implements rmdir.
/// @internal
extern function _rmdir(path as cstr) from "libc.so.6" symbol "rmdir" returns i32
/// Implements rename.
/// @internal
extern function _rename(source as cstr, destination as cstr) from "libc.so.6" symbol "rename" returns i32
/// Implements errno location.
/// @internal
extern function _errnoLocation() from "libc.so.6" symbol "__errno_location" returns ptr
/// Implements copy errno.
/// @internal
extern function _copyErrno(output as bytes, source as ptr, count as u64) from "libc.so.6" symbol "memcpy" returns ptr
#endif

/// Implements native error code.
/// @internal
function _nativeErrorCode()
#if TARGET_OS == "windows"
  return GetLastError()
#else
  location = _errnoLocation()
  if location == 0 then return 0 end if
  raw = bytes(4, 0)
  _copyErrno(raw, location, 4)
  return _u32(raw, 0)
#endif
end function

/// Implements native failure.
/// @internal
function _nativeFailure(operation)
  return _error(FILE_ERR, operation, "native error " + _nativeErrorCode())
end function

/// Creation: 0=open existing, 1=open or create, 2=create/truncate, 3=create new.
/// @internal
function _openFile(path, readable, writable, creation, durable)
  if typeof(path) != "string" or len(path) == 0 then return _error(FILE_ERR, "open", "path must be non-empty") end if
#if TARGET_OS == "windows"
  access = 0
  if readable then access = access | GENERIC_READ end if
  if writable then access = access | GENERIC_WRITE end if
  disposition = OPEN_EXISTING
  if creation == 1 then disposition = OPEN_ALWAYS end if
  if creation == 2 then disposition = CREATE_ALWAYS end if
  if creation == 3 then disposition = CREATE_NEW end if
  flags = FILE_ATTRIBUTE_NORMAL
  if durable then flags = flags | FILE_FLAG_WRITE_THROUGH end if
  handle = CreateFileW(path, access, FILE_SHARE_ALL, 0, disposition, flags, 0)
  if handle == -1 then return _nativeFailure("open") end if
#else
  flags = O_CLOEXEC
  if readable and writable then flags = flags | O_RDWR else if writable then flags = flags | O_WRONLY else flags = flags | O_RDONLY end if
  if creation == 1 then flags = flags | O_CREAT end if
  if creation == 2 then flags = flags | O_CREAT | O_TRUNC end if
  if creation == 3 then flags = flags | O_CREAT | O_EXCL end if
  if durable then flags = flags | O_DSYNC end if
  handle = _open(path, flags, DEFAULT_FILE_MODE)
  if handle < 0 then return _nativeFailure("open") end if
#endif
  return FileHandle(path, handle, readable, writable, durable, false, 0)
end function

/// Implements open read.
/// @param path Path to operate on.
function openRead(path)
  return _openFile(path, true, false, 0, false)
end function

/// Implements open read write.
/// @param path Path to operate on.
/// @param createIfMissing Value supplied for `createIfMissing`.
function openReadWrite(path, createIfMissing)
  if typeof(createIfMissing) != "bool" then return _error(FILE_ERR, "openReadWrite", "createIfMissing must be bool") end if
  creation = 0
  if createIfMissing then creation = 1 end if
  return _openFile(path, true, true, creation, false)
end function

/// Implements open read write durable.
/// @param path Path to operate on.
/// @param createIfMissing Value supplied for `createIfMissing`.
function openReadWriteDurable(path, createIfMissing)
  if typeof(createIfMissing) != "bool" then return _error(FILE_ERR, "openReadWriteDurable", "createIfMissing must be bool") end if
  creation = 0
  if createIfMissing then creation = 1 end if
  return _openFile(path, true, true, creation, true)
end function

/// Creates create.
/// @param path Path to operate on.
function create(path)
  return _openFile(path, true, true, 2, false)
end function

/// Creates create new.
/// @param path Path to operate on.
function createNew(path)
  return _openFile(path, true, true, 3, false)
end function

/// Creates create durable.
/// @param path Path to operate on.
function createDurable(path)
  return _openFile(path, true, true, 2, true)
end function

/// Creates create new durable.
/// @param path Path to operate on.
function createNewDurable(path)
  return _openFile(path, true, true, 3, true)
end function

/// Returns read at.
/// @param file Value supplied for `file`.
/// @param fileOffset Value supplied for `fileOffset`.
/// @param destination Value supplied for `destination`.
/// @param destinationOffset Value supplied for `destinationOffset`.
/// @param count Number of items to process.
function readAt(file, fileOffset, destination, destinationOffset, count)
  state = _validateOpen(file, "readAt")
  if typeof(state) == "error" then return state end if
  if not file.readable then return _error(FILE_ERR, "readAt", "file is not readable") end if
  valid = _validSlice(destination, destinationOffset, count, "readAt")
  if typeof(valid) == "error" then return valid end if
  if typeof(fileOffset) != "int" or fileOffset < 0 then return _error(FILE_ERR, "readAt", "file offset is invalid") end if
  if count == 0 then return 0 end if
  temporary = bytes(count, 0)
#if TARGET_OS == "windows"
  if not SetFilePointerEx(file.nativeHandle, fileOffset, 0, FILE_BEGIN) then return _nativeFailure("readAt.seek") end if
  actualRaw = bytes(4, 0)
  if not ReadFile(file.nativeHandle, temporary, count, actualRaw, 0) then return _nativeFailure("readAt.read") end if
  actual = _u32(actualRaw, 0)
#else
  actual = _pread(file.nativeHandle, temporary, count, fileOffset)
  if actual < 0 then return _nativeFailure("readAt") end if
#endif
  if actual > 0 then copyBytes(destination, destinationOffset, temporary, 0, actual) end if
  return actual
end function

/// Returns read exact at.
/// @param file Value supplied for `file`.
/// @param fileOffset Value supplied for `fileOffset`.
/// @param destination Value supplied for `destination`.
/// @param destinationOffset Value supplied for `destinationOffset`.
/// @param count Number of items to process.
function readExactAt(file, fileOffset, destination, destinationOffset, count)
  total = 0
  while total < count
    actual = readAt(file, fileOffset + total, destination, destinationOffset + total, count - total)
    if typeof(actual) == "error" then return actual end if
    if actual == 0 then return _error(FILE_ERR, "readExactAt", "unexpected end of file") end if
    total = total + actual
  end while
  return total
end function

/// Updates write at.
/// @param file Value supplied for `file`.
/// @param fileOffset Value supplied for `fileOffset`.
/// @param source Source value to process.
/// @param sourceOffset Value supplied for `sourceOffset`.
/// @param count Number of items to process.
function writeAt(file, fileOffset, source, sourceOffset, count)
  state = _validateOpen(file, "writeAt")
  if typeof(state) == "error" then return state end if
  if not file.writable then return _error(FILE_ERR, "writeAt", "file is not writable") end if
  valid = _validSlice(source, sourceOffset, count, "writeAt")
  if typeof(valid) == "error" then return valid end if
  if typeof(fileOffset) != "int" or fileOffset < 0 then return _error(FILE_ERR, "writeAt", "file offset is invalid") end if
  if count == 0 then return 0 end if
  total = 0
  while total < count
    payload = slice(source, sourceOffset + total, count - total)
#if TARGET_OS == "windows"
    if not SetFilePointerEx(file.nativeHandle, fileOffset + total, 0, FILE_BEGIN) then return _nativeFailure("writeAt.seek") end if
    actualRaw = bytes(4, 0)
    if not WriteFile(file.nativeHandle, payload, len(payload), actualRaw, 0) then return _nativeFailure("writeAt.write") end if
    actual = _u32(actualRaw, 0)
#else
    actual = _pwrite(file.nativeHandle, payload, len(payload), fileOffset + total)
    if actual < 0 then return _nativeFailure("writeAt") end if
#endif
    if actual <= 0 then return _error(FILE_ERR, "writeAt", "write made no progress") end if
    total = total + actual
  end while
  return total
end function

/// Updates append.
/// @param file Value supplied for `file`.
/// @param source Source value to process.
/// @param sourceOffset Value supplied for `sourceOffset`.
/// @param count Number of items to process.
function append(file, source, sourceOffset, count)
  offset = size(file)
  if typeof(offset) == "error" then return offset end if
  written = writeAt(file, offset, source, sourceOffset, count)
  if typeof(written) == "error" then return written end if
  return offset
end function

/// Implements size.
/// @param file Value supplied for `file`.
function size(file)
  state = _validateOpen(file, "size")
  if typeof(state) == "error" then return state end if
  raw = bytes(144, 0)
#if TARGET_OS == "windows"
  if not GetFileSizeEx(file.nativeHandle, raw) then return _nativeFailure("size") end if
  return _i64(raw, 0)
#else
  if _fstat(file.nativeHandle, raw) != 0 then return _nativeFailure("size") end if
  return _i64(raw, STAT_FILE_SIZE_OFFSET)
#endif
end function

/// Implements truncate.
/// @param file Value supplied for `file`.
/// @param newSize Value supplied for `newSize`.
function truncate(file, newSize)
  state = _validateOpen(file, "truncate")
  if typeof(state) == "error" then return state end if
  if not file.writable or typeof(newSize) != "int" or newSize < 0 then return _error(FILE_ERR, "truncate", "invalid writable file or size") end if
#if TARGET_OS == "windows"
  if not SetFilePointerEx(file.nativeHandle, newSize, 0, FILE_BEGIN) or not SetEndOfFile(file.nativeHandle) then return _nativeFailure("truncate") end if
#else
  if _ftruncate(file.nativeHandle, newSize) != 0 then return _nativeFailure("truncate") end if
#endif
  return true
end function

/// Implements flush.
/// @param file Value supplied for `file`.
function flush(file)
  state = _validateOpen(file, "flush")
  if typeof(state) == "error" then return state end if
  if not file.writable then return true end if
#if TARGET_OS == "windows"
  if not FlushFileBuffers(file.nativeHandle) then return _nativeFailure("flush") end if
#else
  if _fsync(file.nativeHandle) != 0 then return _nativeFailure("flush") end if
#endif
  return true
end function

/// Acquire a whole-file advisory lock. mode is "shared" or "exclusive".
/// @param file Value supplied for `file`.
/// @param mode Value supplied for `mode`.
/// @param wait Value supplied for `wait`.
function lock(file, mode, wait)
  state = _validateOpen(file, "lock")
  if typeof(state) == "error" then return state end if
  if mode != "shared" and mode != "exclusive" then return _error(FILE_ERR, "lock", "mode must be shared or exclusive") end if
  if typeof(wait) != "bool" then return _error(FILE_ERR, "lock", "wait must be bool") end if
  if file.lockMode != 0 then return _error(FILE_ERR, "lock", "file is already locked by this handle") end if
#if TARGET_OS == "windows"
  flags = 0
  if mode == "exclusive" then flags = flags | LOCKFILE_EXCLUSIVE_LOCK end if
  if not wait then flags = flags | LOCKFILE_FAIL_IMMEDIATELY end if
  overlapped = bytes(32, 0)
  if not LockFileEx(file.nativeHandle, flags, 0, 0xFFFFFFFF, 0x7FFFFFFF, overlapped) then
    code = _nativeErrorCode()
    if code == ERROR_LOCK_VIOLATION then return _error(LOCK_CONFLICT, "lock", "file is locked by another process") end if
    return _error(FILE_ERR, "lock", "native error " + code)
  end if
#else
  operation = LOCK_SHARED
  if mode == "exclusive" then operation = LOCK_EXCLUSIVE end if
  if not wait then operation = operation | LOCK_NONBLOCKING end if
  if _flock(file.nativeHandle, operation) != 0 then
    code = _nativeErrorCode()
    if code == EWOULDBLOCK then return _error(LOCK_CONFLICT, "lock", "file is locked by another process") end if
    return _error(FILE_ERR, "lock", "native error " + code)
  end if
#endif
  file.lockMode = mode
  return true
end function

/// Implements unlock.
/// @param file Value supplied for `file`.
function unlock(file)
  state = _validateOpen(file, "unlock")
  if typeof(state) == "error" then return state end if
  if file.lockMode == 0 then return true end if
#if TARGET_OS == "windows"
  overlapped = bytes(32, 0)
  if not UnlockFileEx(file.nativeHandle, 0, 0xFFFFFFFF, 0x7FFFFFFF, overlapped) then return _nativeFailure("unlock") end if
#else
  if _flock(file.nativeHandle, LOCK_UNLOCK) != 0 then return _nativeFailure("unlock") end if
#endif
  file.lockMode = 0
  return true
end function

/// Releases or resets close.
/// @param file Value supplied for `file`.
function close(file)
  state = _validateOpen(file, "close")
  if typeof(state) == "error" then return state end if
  if file.lockMode != 0 then
    released = unlock(file)
    if typeof(released) == "error" then return released end if
  end if
#if TARGET_OS == "windows"
  if not CloseHandle(file.nativeHandle) then return _nativeFailure("close") end if
#else
  if _close(file.nativeHandle) != 0 then return _nativeFailure("close") end if
#endif
  file.nativeHandle = -1
  file.closed = true
  return true
end function

/// Creates create directory.
/// @param path Path to operate on.
function createDirectory(path)
  if typeof(path) != "string" or len(path) == 0 then return _error(FILE_ERR, "createDirectory", "path must be non-empty") end if
  if fs.isDir(path) then return true end if
#if TARGET_OS == "windows"
  if not CreateDirectoryW(path, 0) then return _nativeFailure("createDirectory") end if
#else
  if _mkdir(path, DEFAULT_DIRECTORY_MODE) != 0 then return _nativeFailure("createDirectory") end if
#endif
  return true
end function

/// Releases or resets remove directory.
/// @param path Path to operate on.
function removeDirectory(path)
  if typeof(path) != "string" or len(path) == 0 then return _error(FILE_ERR, "removeDirectory", "path must be non-empty") end if
#if TARGET_OS == "windows"
  if not RemoveDirectoryW(path) then return _nativeFailure("removeDirectory") end if
#else
  if _rmdir(path) != 0 then return _nativeFailure("removeDirectory") end if
#endif
  return true
end function

/// Implements path exists.
/// @param path Path to operate on.
function pathExists(path)
  return fs.exists(path)
end function

/// Implements file exists.
/// @param path Path to operate on.
function fileExists(path)
  return fs.isFile(path)
end function

/// Implements directory exists.
/// @param path Path to operate on.
function directoryExists(path)
  return fs.isDir(path)
end function

/// Releases or resets delete path.
/// @param path Path to operate on.
function deletePath(path)
  if typeof(path) != "string" or len(path) == 0 then return _error(FILE_ERR, "deletePath", "path must be non-empty") end if
  if not fs.exists(path) then return true end if
  if not fs.delete(path) then return _error(FILE_ERR, "deletePath", "delete failed") end if
  return true
end function

/// Implements join path.
/// @param left Left input value.
/// @param right Right input value.
function joinPath(left, right)
  return path_api.join(left, right)
end function

/// Returns read all bytes.
/// @param path Path to operate on.
/// @param maximumBytes Value supplied for `maximumBytes`.
function readAllBytes(path, maximumBytes)
  if typeof(maximumBytes) != "int" or maximumBytes < 0 then return _error(FILE_ERR, "readAllBytes", "maximumBytes is invalid") end if
  file = openRead(path)
  if typeof(file) == "error" then return file end if
  count = size(file)
  if typeof(count) == "error" then ignoredClose = close(file); return count end if
  if count > maximumBytes then ignoredClose = close(file); return _error(FILE_ERR, "readAllBytes", "file exceeds configured limit") end if
  output = bytes(count, 0)
  if count > 0 then
    actual = readExactAt(file, 0, output, 0, count)
    if typeof(actual) == "error" then ignoredClose = close(file); return actual end if
  end if
  closed = close(file)
  if typeof(closed) == "error" then return closed end if
  return output
end function

/// Returns read all text.
/// @param path Path to operate on.
/// @param maximumBytes Value supplied for `maximumBytes`.
function readAllText(path, maximumBytes)
  raw = readAllBytes(path, maximumBytes)
  if typeof(raw) == "error" then return raw end if
  text = decode(raw)
  if typeof(text) != "string" then return _error(FILE_ERR, "readAllText", "file is not valid UTF-8") end if
  return text
end function

/// Rename within one filesystem. With replaceExisting this is the primitive for publishing a fully flushed temporary file atomically.
/// @param source Source value to process.
/// @param destination Value supplied for `destination`.
/// @param replaceExisting Value supplied for `replaceExisting`.
function atomicMove(source, destination, replaceExisting)
  if typeof(source) != "string" or len(source) == 0 or typeof(destination) != "string" or len(destination) == 0 then return _error(FILE_ERR, "atomicMove", "paths must be non-empty") end if
  if typeof(replaceExisting) != "bool" then return _error(FILE_ERR, "atomicMove", "replaceExisting must be bool") end if
  if not replaceExisting and fs.exists(destination) then return _error(FILE_ERR, "atomicMove", "destination exists") end if
#if TARGET_OS == "windows"
  flags = MOVEFILE_WRITE_THROUGH
  if replaceExisting then flags = flags | MOVEFILE_REPLACE_EXISTING end if
  if not MoveFileExW(source, destination, flags) then return _nativeFailure("atomicMove") end if
#else
  if _rename(source, destination) != 0 then return _nativeFailure("atomicMove") end if
#endif
  return true
end function

/// Implements move path.
/// @param source Source value to process.
/// @param destination Value supplied for `destination`.
/// @param replaceExisting Value supplied for `replaceExisting`.
function movePath(source, destination, replaceExisting)
  return atomicMove(source, destination, replaceExisting)
end function

/// Persist directory-entry updates after an atomic rename on POSIX. Windows MoveFileExW with MOVEFILE_WRITE_THROUGH already provides the matching fence.
/// @param path Path to operate on.
function syncDirectory(path)
  if typeof(path) != "string" or len(path) == 0 then return _error(FILE_ERR, "syncDirectory", "path must be non-empty") end if
#if TARGET_OS == "linux"
  handle = _open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0)
  if handle < 0 then return _nativeFailure("syncDirectory.open") end if
  result = _fsync(handle)
  closeResult = _close(handle)
  if result != 0 or closeResult != 0 then return _nativeFailure("syncDirectory") end if
#endif
  return true
end function
