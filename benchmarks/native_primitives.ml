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

// Reproducible throughput benchmark for native checksum, search, and CNG paths.
import std.checksum.crc32c as crc32c
import std.crypto as crypto
import std.crypto.aes_gcm as aes
import std.cpu as cpu
import std.string as s
import std.bytes as b
import std.time as tm

function elapsedAtLeastOne(start)
  elapsed = tm.ticks() - start
  if elapsed < 1 then return 1 end if
  return elapsed
end function

function report(label, byteCount, iterations, elapsed, heapBefore, committedBefore)
  mib = (byteCount * iterations) / 1048576.0
  throughput = (mib * 1000.0) / elapsed
  heapGrowth = heap_bytes_used() - heapBefore
  committedGrowth = heap_bytes_committed() - committedBefore
  print label + ": " + elapsed + " ms, " + throughput + " MiB/s, heap_delta=" + heapGrowth + ", committed_delta=" + committedGrowth
end function

function benchCrc(label, mask, data)
  cpu.setDispatchMaskForTesting(mask)
  heapBefore = heap_bytes_used()
  committedBefore = heap_bytes_committed()
  start = tm.ticks()
  result = 0
  for i = 0 to 3
    result = crc32c.compute(data)
  end for
  elapsed = elapsedAtLeastOne(start)
  report(label + " result=" + result, len(data), 4, elapsed, heapBefore, committedBefore)
end function

function benchByteSearch(label, mask, data, needle, iterations)
  cpu.setDispatchMaskForTesting(mask)
  heapBefore = heap_bytes_used()
  committedBefore = heap_bytes_committed()
  start = tm.ticks()
  result = -1
  for i = 0 to iterations - 1
    result = b.indexOf(data, needle, 0)
  end for
  elapsed = elapsedAtLeastOne(start)
  report(label + " result=" + result, len(data), iterations, elapsed, heapBefore, committedBefore)
end function

function benchStringSearch(label, mask, data, needle, iterations)
  cpu.setDispatchMaskForTesting(mask)
  heapBefore = heap_bytes_used()
  committedBefore = heap_bytes_committed()
  start = tm.ticks()
  result = -1
  for i = 0 to iterations - 1
    result = s.indexOf(data, needle, 0)
  end for
  elapsed = elapsedAtLeastOne(start)
  report(label + " result=" + result, len(data), iterations, elapsed, heapBefore, committedBefore)
end function

function benchAes(size, iterations)
  key = bytes(32, 0x42)
  nonce = bytes(12, 0x17)
  aad = bytes("MiniLang AES-GCM benchmark")
  input = bytes(size, 0x61)
  heapBefore = heap_bytes_used()
  committedBefore = heap_bytes_committed()
  start = tm.ticks()
  result = bytes(0)
  for i = 0 to iterations - 1
    result = aes.seal(key, nonce, input, aad, 16)
  end for
  elapsed = elapsedAtLeastOne(start)
  report("AES-256-GCM " + size + " bytes tag0=" + result[len(result) - 16], size, iterations, elapsed, heapBefore, committedBefore)
  crypto.secureZero(key)
end function

function benchHash(label, size, iterations, useSha384)
  input = bytes(size, 0x5A)
  heapBefore = heap_bytes_used()
  committedBefore = heap_bytes_committed()
  start = tm.ticks()
  digest = bytes(0)
  for i = 0 to iterations - 1
    if useSha384 then digest = crypto.sha384(input) else digest = crypto.sha256(input) end if
  end for
  elapsed = elapsedAtLeastOne(start)
  report(label + " digest0=" + digest[0], size, iterations, elapsed, heapBefore, committedBefore)
end function

function main(args)
  detected = cpu.features()
  previous = cpu.activeFeatures()
  print "MiniLang native primitive benchmark"
  print "cpu_detected=" + detected

  crcData = bytes(64 * 1024 * 1024, 0xA5)
  benchCrc("CRC-32C scalar fallback", 0, crcData)
  benchCrc("CRC-32C detected dispatch", detected, crcData)

  searchData = bytes(32 * 1024 * 1024, 0x61)
  searchData[len(searchData) - 1] = 0x7A
  benchByteSearch("byte found scalar", 0, searchData, bytes("z"), 32)
  benchByteSearch("byte found SIMD", detected, searchData, bytes("z"), 32)
  benchByteSearch("byte miss scalar", 0, searchData, bytes("q"), 32)
  benchByteSearch("byte miss SIMD", detected, searchData, bytes("q"), 32)

  searchText = s.repeat("a", 8 * 1024 * 1024) + "needle-at-end"
  benchStringSearch("short substring scalar", 0, searchText, "needle", 512)
  benchStringSearch("short substring SIMD", detected, searchText, "needle", 512)
  benchStringSearch("long substring scalar", 0, searchText, "needle-at-end", 512)
  benchStringSearch("long substring SIMD", detected, searchText, "needle-at-end", 512)

  benchAes(1024, 4096)
  benchAes(65536, 8192)
  benchAes(1048576, 1024)
  benchHash("SHA-256", 1048576, 128, false)
  benchHash("SHA-384", 1048576, 64, true)

  cpu.setDispatchMaskForTesting(previous)
end function
