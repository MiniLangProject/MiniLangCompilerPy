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

import std.assert as t
import std.checksum.crc32c as c32c
import std.checksum.crc32 as c32
import std.cpu as cpu

function referenceCrc(buffer, offset, length, polynomial)
  crc = 0xFFFFFFFF
  if length > 0 then
    for i = 0 to length - 1
      crc = crc ^ buffer[offset + i]
      for bit = 0 to 7
        if (crc & 1) != 0 then
          crc = (crc >> 1) ^ polynomial
        else
          crc = crc >> 1
        end if
      end for
      crc = crc & 0xFFFFFFFF
    end for
  end if
  return (crc ^ 0xFFFFFFFF) & 0xFFFFFFFF
end function

function main(args)
  vector = bytes("123456789")
  t.assertEq(c32c.compute(vector), 0xE3069283, "CRC-32C check value")
  t.assertEq(c32.compute(vector), 0xCBF43926, "CRC-32/IEEE check value")
  t.assertEq(c32c.compute(bytes(0)), 0, "CRC-32C empty")
  t.assertEq(c32.compute(bytes(0)), 0, "CRC-32 empty")

  padded = bytes("xx123456789yy")
  t.assertEq(c32c.computeRange(padded, 2, 9), 0xE3069283, "CRC-32C range")
  t.assertEq(c32.computeRange(padded, 2, 9), 0xCBF43926, "CRC-32 range")
  t.assertTrue(c32c.verifyRange(padded, 2, 9, 0xE3069283), "CRC-32C verify range")
  t.assertTrue(c32.verify(vector, 0xCBF43926), "CRC-32 verify")
  t.assertEq(typeof(c32c.computeRange(vector, -1, 1)), "void", "CRC negative offset")
  t.assertEq(typeof(c32.computeRange(vector, 0, 10)), "void", "CRC oversized range")

  expectedC = c32c.compute(vector)
  expectedI = c32.compute(vector)
  for split = 0 to len(vector)
    partC = c32c.update(0, vector, 0, split)
    partC = c32c.update(partC, vector, split, len(vector) - split)
    t.assertEq(partC, expectedC, "CRC-32C incremental split " + split)
    partI = c32.update(0, vector, 0, split)
    partI = c32.update(partI, vector, split, len(vector) - split)
    t.assertEq(partI, expectedI, "CRC-32 incremental split " + split)
  end for

  randomData = bytes(4097, 0)
  state = 0x12345678
  for i = 0 to len(randomData) - 1
    state = ((state * 1103515245) + 12345) & 0x7FFFFFFF
    randomData[i] = state & 0xFF
  end for
  refC = referenceCrc(randomData, 0, len(randomData), 0x82F63B78)
  refI = referenceCrc(randomData, 0, len(randomData), 0xEDB88320)
  t.assertEq(c32c.compute(randomData), refC, "CRC-32C independent reference")
  t.assertEq(c32.compute(randomData), refI, "CRC-32 independent reference")

  detected = cpu.features()
  previous = cpu.setDispatchMaskForTesting(detected ^ (detected & cpu.SSE42))
  t.assertEq(c32c.compute(randomData), refC, "CRC-32C software fallback")
  cpu.setDispatchMaskForTesting(previous)
  t.assertEq(c32c.compute(randomData), refC, "CRC-32C restored dispatch")

  print "[OK] checksum runtime"
end function
