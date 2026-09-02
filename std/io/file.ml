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

/// Track the file err value used by this standard-library module.
const FILE_ERR = 263
/// Track the lock conflict value used by this standard-library module.
const LOCK_CONFLICT = 264
/// Track the closed handle value used by this standard-library module.
const CLOSED_HANDLE = 265
/// Track the max io count value used by this standard-library module.
const MAX_IO_COUNT = 0x7FFFFFFF

/// Represents file handle.
struct FileHandle
  /// Path associated with `FileHandle`.
  path
  /// Native handle associated with `FileHandle`.
  nativeHandle
  /// Readable associated with `FileHandle`.
  readable
  /// Writable associated with `FileHandle`.
  writable
  /// Durable associated with `FileHandle`.
  durable
  /// Closed associated with `FileHandle`.
  closed
  /// Lock mode associated with `FileHandle`.
  lockMode
end struct

/// Provide the error operation for this standard-library module.
/// @internal
function _error(code, operation, message)
  return error(code, "std.io.file." + operation + ": " + message)
end function

/// Provide the u32 operation for this standard-library module.
/// @internal
function _u32(buffer, offset)
  return buffer[offset] | (buffer[offset + 1] << 8) | (buffer[offset + 2] << 16) | (buffer[offset + 3] << 24)
end function

/// Provide the i64 operation for this standard-library module.
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

/// Provide the valid slice operation for this standard-library module.
/// @internal
function _validSlice(buffer, offset, count, operation)
  if typeof(buffer) != "bytes" then return _error(FILE_ERR, operation, "buffer must be bytes") end if
  if typeof(offset) != "int" or typeof(count) != "int" or offset < 0 or count < 0 or offset > len(buffer) or count > len(buffer) - offset then
    return _error(FILE_ERR, operation, "buffer range is invalid")
  end if
  if count > MAX_IO_COUNT then return _error(FILE_ERR, operation, "I/O count is too large") end if
  return true
end function

/// Provide the validate open operation for this standard-library module.
/// @internal
function _validateOpen(file, operation)
  if file is not FileHandle then return _error(FILE_ERR, operation, "value must be FileHandle") end if
  if file.closed then return _error(CLOSED_HANDLE, operation, "file handle is closed") end if
  return true
end function

#if TARGET_OS == "windows"
/// Track the generic read value used by this standard-library module.
const GENERIC_READ = 0x80000000
/// Track the generic write value used by this standard-library module.
const GENERIC_WRITE = 0x40000000
/// Track the file share all value used by this standard-library module.
const FILE_SHARE_ALL = 7
/// Track the create new value used by this standard-library module.
const CREATE_NEW = 1
/// Track the create always value used by this standard-library module.
const CREATE_ALWAYS = 2
/// Track the open existing value used by this standard-library module.
const OPEN_EXISTING = 3
/// Track the open always value used by this standard-library module.
const OPEN_ALWAYS = 4
/// Track the file attribute normal value used by this standard-library module.
const FILE_ATTRIBUTE_NORMAL = 0x80
/// Track the file flag write through value used by this standard-library module.
const FILE_FLAG_WRITE_THROUGH = 0x80000000
/// Track the file flag backup semantics value used by this standard-library module.
const FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
/// Track the file begin value used by this standard-library module.
const FILE_BEGIN = 0
/// Track the lockfile fail immediately value used by this standard-library module.
const LOCKFILE_FAIL_IMMEDIATELY = 1
/// Track the lockfile exclusive lock value used by this standard-library module.
const LOCKFILE_EXCLUSIVE_LOCK = 2
/// Track the error lock violation value used by this standard-library module.
const ERROR_LOCK_VIOLATION = 33
/// Track the movefile replace existing value used by this standard-library module.
const MOVEFILE_REPLACE_EXISTING = 1
/// Track the movefile write through value used by this standard-library module.
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
/// Provide the flush file buffers operation for this standard-library module.
/// @internal
extern function FlushFileBuffers(handle as ptr) from "kernel32.dll" returns bool
/// Provide the lock file ex operation for this standard-library module.
/// @internal
extern function LockFileEx(handle as ptr, flags as u32, reserved as u32, lowCount as u32, highCount as u32, overlapped as bytes) from "kernel32.dll" returns bool
/// Provide the unlock file ex operation for this standard-library module.
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
/// Provide the move file ex w operation for this standard-library module.
/// @internal
extern function MoveFileExW(source as wstr, destination as wstr, flags as u32) from "kernel32.dll" returns bool
#else
/// Track the o rdonly value used by this standard-library module.
const O_RDONLY = 0
/// Track the o wronly value used by this standard-library module.
const O_WRONLY = 1
/// Track the o rdwr value used by this standard-library module.
const O_RDWR = 2
/// Track the o creat value used by this standard-library module.
const O_CREAT = 64
/// Track the o excl value used by this standard-library module.
const O_EXCL = 128
/// Track the o trunc value used by this standard-library module.
const O_TRUNC = 512
/// Track the o dsync value used by this standard-library module.
const O_DSYNC = 4096
/// Track the o directory value used by this standard-library module.
const O_DIRECTORY = 65536
/// Track the o cloexec value used by this standard-library module.
const O_CLOEXEC = 524288
/// Track the default file mode value used by this standard-library module.
const DEFAULT_FILE_MODE = 0x1B6
/// Track the default directory mode value used by this standard-library module.
const DEFAULT_DIRECTORY_MODE = 0x1FF
/// Track the lock shared value used by this standard-library module.
const LOCK_SHARED = 1
/// Track the lock exclusive value used by this standard-library module.
const LOCK_EXCLUSIVE = 2
/// Track the lock nonblocking value used by this standard-library module.
const LOCK_NONBLOCKING = 4
/// Track the lock unlock value used by this standard-library module.
const LOCK_UNLOCK = 8
/// Track the ewouldblock value used by this standard-library module.
const EWOULDBLOCK = 11
/// These offsets follow the Linux x86-64 glibc stat ABI. Revisit them for another CPU architecture or libc implementation.
const STAT_SIZE = 144
/// Track the stat file size offset value used by this standard-library module.
const STAT_FILE_SIZE_OFFSET = 48

/// Provide the open operation for this standard-library module.
/// @internal
extern function _open(path as cstr, flags as int, mode as u32) from "libc.so.6" symbol "open" returns i32
/// Provide the pread operation for this standard-library module.
/// @internal
extern function _pread(handle as int, output as bytes, count as u64, offset as i64) from "libc.so.6" symbol "pread" returns i64
/// Provide the pwrite operation for this standard-library module.
/// @internal
extern function _pwrite(handle as int, input as bytes, count as u64, offset as i64) from "libc.so.6" symbol "pwrite" returns i64
/// Provide the fstat operation for this standard-library module.
/// @internal
extern function _fstat(handle as int, output as bytes) from "libc.so.6" symbol "fstat" returns i32
/// Provide the ftruncate operation for this standard-library module.
/// @internal
extern function _ftruncate(handle as int, size as i64) from "libc.so.6" symbol "ftruncate" returns i32
/// Provide the fsync operation for this standard-library module.
/// @internal
extern function _fsync(handle as int) from "libc.so.6" symbol "fsync" returns i32
/// Provide the flock operation for this standard-library module.
/// @internal
extern function _flock(handle as int, operation as int) from "libc.so.6" symbol "flock" returns i32
/// Releases or resets close.
/// @internal
extern function _close(handle as int) from "libc.so.6" symbol "close" returns i32
/// Provide the mkdir operation for this standard-library module.
/// @internal
extern function _mkdir(path as cstr, mode as u32) from "libc.so.6" symbol "mkdir" returns i32
/// Provide the rmdir operation for this standard-library module.
/// @internal
extern function _rmdir(path as cstr) from "libc.so.6" symbol "rmdir" returns i32
/// Provide the rename operation for this standard-library module.
/// @internal
extern function _rename(source as cstr, destination as cstr) from "libc.so.6" symbol "rename" returns i32
/// Provide the errno location operation for this standard-library module.
/// @internal
extern function _errnoLocation() from "libc.so.6" symbol "__errno_location" returns ptr
/// Provide the copy errno operation for this standard-library module.
/// @internal
extern function _copyErrno(output as bytes, source as ptr, count as u64) from "libc.so.6" symbol "memcpy" returns ptr
#endif

/// Provide the native error code operation for this standard-library module.
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

/// Provide the native failure operation for this standard-library module.
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

/// Provide the open read operation for this standard-library module.
/// @param path Path to operate on.
function openRead(path)
  return _openFile(path, true, false, 0, false)
end function

/// Provide the open read write operation for this standard-library module.
/// @param path Path to operate on.
/// @param createIfMissing Value supplied for `createIfMissing`.
function openReadWrite(path, createIfMissing)
  if typeof(createIfMissing) != "bool" then return _error(FILE_ERR, "openReadWrite", "createIfMissing must be bool") end if
  creation = 0
  if createIfMissing then creation = 1 end if
  return _openFile(path, true, true, creation, false)
end function

/// Provide the open read write durable operation for this standard-library module.
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

/// Provide the size operation for this standard-library module.
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

/// Provide the truncate operation for this standard-library module.
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

/// Provide the flush operation for this standard-library module.
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

/// Provide the unlock operation for this standard-library module.
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

/// Provide the path exists operation for this standard-library module.
/// @param path Path to operate on.
function pathExists(path)
  return fs.exists(path)
end function

/// Provide the file exists operation for this standard-library module.
/// @param path Path to operate on.
function fileExists(path)
  return fs.isFile(path)
end function

/// Provide the directory exists operation for this standard-library module.
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

/// Provide the join path operation for this standard-library module.
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

/// Provide the move path operation for this standard-library module.
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
