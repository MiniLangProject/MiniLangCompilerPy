/*
   Copyright 2026 Nils Kopal
   Licensed under the Apache License, Version 2.0.
*/

//! Provides the std concurrent shared_value package.

package std.concurrent.shared_value

/// Legacy native-value codec retained for compatibility. The managed concurrent collections no longer need it because every thread shares the same GC heap. It remains useful for explicit snapshots passed to unmanaged native memory.
const MEM_COMMIT_RESERVE = 0x3000
/// Track the mem release value used by this standard-library module.
const MEM_RELEASE = 0x8000
/// Track the page readwrite value used by this standard-library module.
const PAGE_READWRITE = 0x04
/// Track the record size value used by this standard-library module.
const RECORD_SIZE = 24

/// Track the type void value used by this standard-library module.
const TYPE_VOID = 0
/// Track the type int value used by this standard-library module.
const TYPE_INT = 1
/// Track the type bool value used by this standard-library module.
const TYPE_BOOL = 2
/// Track the type string value used by this standard-library module.
const TYPE_STRING = 3
/// Track the type bytes value used by this standard-library module.
const TYPE_BYTES = 4

#if TARGET_OS == "windows"
/// Provide the virtual alloc operation for this standard-library module.
/// @internal
extern function VirtualAlloc(address as ptr, size as int, allocationType as u32, protect as u32) from "kernel32.dll" returns ptr
/// Provide the virtual free operation for this standard-library module.
/// @internal
extern function VirtualFree(address as ptr, size as int, freeType as u32) from "kernel32.dll" returns bool
/// Provide the move from bytes operation for this standard-library module.
/// @internal
extern function MoveFromBytes(destination as ptr, source as bytes, count as int) from "kernel32.dll" symbol "RtlMoveMemory" returns ptr
/// Provide the move pointers operation for this standard-library module.
/// @internal
extern function MovePointers(destination as ptr, source as ptr, count as int) from "kernel32.dll" symbol "RtlMoveMemory" returns ptr
#else
/// Provide the native allocate operation for this standard-library module.
/// @internal
extern function NativeAllocate(size as u64) from "libc.so.6" symbol "malloc" returns ptr
/// Provide the native free operation for this standard-library module.
/// @internal
extern function NativeFree(address as ptr) from "libc.so.6" symbol "free" returns void
/// Provide the move from bytes operation for this standard-library module.
/// @internal
extern function MoveFromBytes(destination as ptr, source as bytes, count as u64) from "libc.so.6" symbol "memmove" returns ptr
/// Provide the move pointers operation for this standard-library module.
/// @internal
extern function MovePointers(destination as ptr, source as ptr, count as u64) from "libc.so.6" symbol "memmove" returns ptr
#endif

/// Allocate a writable unmanaged block and return its native address.
/// @param size Value supplied for `size`.
function allocate(size)
  if typeof(size) != "int" or size <= 0 then return 0 end if
#if TARGET_OS == "windows"
  return VirtualAlloc(void, size, MEM_COMMIT_RESERVE, PAGE_READWRITE)
#else
  return NativeAllocate(size)
#endif
end function

/// Release a block previously returned by allocate().
/// @param address Value supplied for `address`.
function free(address)
  if typeof(address) != "int" or address == 0 then return false end if
#if TARGET_OS == "windows"
  return VirtualFree(address, 0, MEM_RELEASE)
#else
  NativeFree(address)
  return true
#endif
end function

/// Copy count bytes between two unmanaged addresses.
/// @param destination Value supplied for `destination`.
/// @param source Source value to process.
/// @param count Number of items to process.
function move(destination, source, count)
  if count <= 0 then return true end if
  MovePointers(destination, source, count)
  return true
end function

/// Encode one signed 64-bit integer in little-endian order.
/// @internal
function _writeI64(buffer, offset, value)
  i = 0
  while i < 8
    buffer[offset + i] = (value >> (i * 8)) & 0xFF
    i = i + 1
  end while
end function

/// Decode one signed little-endian 64-bit integer without unsigned overflow.
/// @internal
function _readI64(buffer, offset)
  // Seed with a signed high byte so the final value is sign-extended without
  // ever constructing an out-of-range unsigned 64-bit MiniLang integer.
  value = buffer[offset + 7]
  if value >= 128 then value = value - 256 end if
  i = 6
  while i >= 0
    value = (value << 8) | buffer[offset + i]
    i = i - 1
  end while
  return value
end function

/// Store a signed 64-bit integer at an unmanaged address.
/// @param address Value supplied for `address`.
/// @param value Value to process.
function writeI64At(address, value)
  buffer = bytes(8, 0)
  _writeI64(buffer, 0, value)
  MoveFromBytes(address, buffer, 8)
end function

/// Read a signed 64-bit integer from an unmanaged address.
/// @param address Value supplied for `address`.
function readI64At(address)
  buffer = bytes(8, 0)
  MovePointers(nativeBytesPtr(buffer), address, 8)
  return _readI64(buffer, 0)
end function

/// Report whether the legacy snapshot codec supports this value category.
/// @param value Value to process.
function isShareable(value)
  t = typeof(value)
  return t == "void" or t == "int" or t == "bool" or t == "string" or t == "bytes"
end function

/// Returns [ok, type, payload, length]. For string/bytes payload owns a native block which must either be written into a record or released.
/// @param value Value to process.
function encode(value)
  t = typeof(value)
  if t == "void" then return [true, TYPE_VOID, 0, 0] end if
  if t == "int" then return [true, TYPE_INT, value, 0] end if
  if t == "bool" then
    if value then return [true, TYPE_BOOL, 1, 0] end if
    return [true, TYPE_BOOL, 0, 0]
  end if

  data = value
  valueType = TYPE_BYTES
  if t == "string" then
    data = bytes(value)
    valueType = TYPE_STRING
  else
    if t != "bytes" then return [false, 0, 0, 0] end if
  end if

  n = len(data)
  pointer = 0
  if n > 0 then
    pointer = allocate(n)
    if pointer == 0 then return [false, 0, 0, 0] end if
    MoveFromBytes(pointer, data, n)
  end if
  return [true, valueType, pointer, n]
end function

/// Release the payload owned by an encoded string or bytes snapshot.
/// @param encoded Value supplied for `encoded`.
function releaseEncoded(encoded)
  if typeof(encoded) != "array" or len(encoded) < 4 then return false end if
  t = encoded[1]
  if (t == TYPE_STRING or t == TYPE_BYTES) and encoded[2] != 0 then
    return free(encoded[2])
  end if
  return true
end function

/// Write encoded metadata into a RECORD_SIZE native record.
/// @param address Value supplied for `address`.
/// @param encoded Value supplied for `encoded`.
function writeEncodedAt(address, encoded)
  if typeof(encoded) != "array" or len(encoded) < 4 or not encoded[0] then
    return false
  end if
  buffer = bytes(RECORD_SIZE, 0)
  _writeI64(buffer, 0, encoded[1])
  _writeI64(buffer, 8, encoded[2])
  _writeI64(buffer, 16, encoded[3])
  MoveFromBytes(address, buffer, RECORD_SIZE)
  return true
end function

/// Zero a native record without releasing any referenced payload.
/// @param address Value supplied for `address`.
function clearRecordAt(address)
  buffer = bytes(RECORD_SIZE, 0)
  MoveFromBytes(address, buffer, RECORD_SIZE)
end function

/// Read the type, payload pointer and length fields from a native record.
/// @internal
function _metadataAt(address)
  buffer = bytes(RECORD_SIZE, 0)
  MovePointers(nativeBytesPtr(buffer), address, RECORD_SIZE)
  return [_readI64(buffer, 0), _readI64(buffer, 8), _readI64(buffer, 16)]
end function

/// Materialize a managed value from one native snapshot record.
/// @param address Value supplied for `address`.
function readAt(address)
  metadata = _metadataAt(address)
  t = metadata[0]
  payload = metadata[1]
  n = metadata[2]
  if t == TYPE_VOID then return end if
  if t == TYPE_INT then return payload end if
  if t == TYPE_BOOL then return payload != 0 end if
  if t != TYPE_STRING and t != TYPE_BYTES then return end if

  output = bytes(n, 0)
  if n > 0 then MovePointers(nativeBytesPtr(output), payload, n) end if
  if t == TYPE_STRING then return decode(output) end if
  return output
end function

/// Release an owned payload and clear its native record.
/// @param address Value supplied for `address`.
function destroyAt(address)
  metadata = _metadataAt(address)
  t = metadata[0]
  if (t == TYPE_STRING or t == TYPE_BYTES) and metadata[1] != 0 then
    free(metadata[1])
  end if
  clearRecordAt(address)
end function
