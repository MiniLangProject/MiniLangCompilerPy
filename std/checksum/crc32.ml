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

package std.checksum.crc32

// CRC-32/IEEE uses polynomial 0x04C11DB7 (reflected 0xEDB88320), initial
// 0xFFFFFFFF and final XOR 0xFFFFFFFF.  It is intentionally separate from
// CRC-32C: the x86 CRC32 instruction computes CRC-32C and cannot implement
// this format.

// Compute CRC-32/IEEE over an entire bytes value.
function compute(buffer)
  if typeof(buffer) != "bytes" then return end if
  return nativeCrc32(0, buffer, 0, len(buffer))
end function

// Compute CRC-32/IEEE over one validated byte range.
function computeRange(buffer, offset, length)
  if typeof(buffer) != "bytes" then return end if
  return nativeCrc32(0, buffer, offset, length)
end function

// Continue a finalized CRC-32/IEEE value over one byte range.
function update(previous, buffer, offset, length)
  if typeof(buffer) != "bytes" then return end if
  return nativeCrc32(previous, buffer, offset, length)
end function

// Compare the CRC-32/IEEE of an entire buffer with expected.
function verify(buffer, expected)
  actual = compute(buffer)
  if typeof(actual) != "int" or typeof(expected) != "int" then return false end if
  return actual == expected
end function

// Compare the CRC-32/IEEE of one range with expected.
function verifyRange(buffer, offset, length, expected)
  actual = computeRange(buffer, offset, length)
  if typeof(actual) != "int" or typeof(expected) != "int" then return false end if
  return actual == expected
end function
