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

//! Provides the std checksum crc32c package.

package std.checksum.crc32c

// CRC-32C uses the Castagnoli polynomial 0x1EDC6F41.  The generated runtime
// uses its reflected form 0x82F63B78, an initial value of 0xFFFFFFFF and a
// final XOR of 0xFFFFFFFF.  update() accepts and returns finalized CRC values,
// so arbitrary chunk boundaries produce exactly the same result as compute().

/// Compute CRC-32C over an entire bytes value.
/// @param buffer Buffer to process.
function compute(buffer)
  if typeof(buffer) != "bytes" then return end if
  return nativeCrc32c(0, buffer, 0, len(buffer))
end function

/// Compute CRC-32C over one validated byte range.
/// @param buffer Buffer to process.
/// @param offset Zero-based starting offset.
/// @param length Number of elements or bytes to process.
function computeRange(buffer, offset, length)
  if typeof(buffer) != "bytes" then return end if
  return nativeCrc32c(0, buffer, offset, length)
end function

/// Continue a finalized CRC-32C value over one byte range.
/// @param previous Value supplied for `previous`.
/// @param buffer Buffer to process.
/// @param offset Zero-based starting offset.
/// @param length Number of elements or bytes to process.
function update(previous, buffer, offset, length)
  if typeof(buffer) != "bytes" then return end if
  return nativeCrc32c(previous, buffer, offset, length)
end function

/// Compare the CRC-32C of an entire buffer with expected.
/// @param buffer Buffer to process.
/// @param expected Value supplied for `expected`.
function verify(buffer, expected)
  actual = compute(buffer)
  if typeof(actual) != "int" or typeof(expected) != "int" then return false end if
  return actual == expected
end function

/// Compare the CRC-32C of one range with expected.
/// @param buffer Buffer to process.
/// @param offset Zero-based starting offset.
/// @param length Number of elements or bytes to process.
/// @param expected Value supplied for `expected`.
function verifyRange(buffer, offset, length, expected)
  actual = computeRange(buffer, offset, length)
  if typeof(actual) != "int" or typeof(expected) != "int" then return false end if
  return actual == expected
end function
