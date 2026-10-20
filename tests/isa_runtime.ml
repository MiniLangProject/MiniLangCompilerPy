/// Differential copy/fill and CRC dispatch boundaries, shared by both compilers.
import std.cpu as cpu
import std.checksum.crc32 as crc

failures = 0

/// Keep bulk checks quiet while making every failure affect the exit status.
function checkEq(actual, expected, label)
  global failures
  if actual != expected then
    failures += 1
    print "[FAIL] " + label
  end if
end function

function main(args)
  source = bytes(65560)
  for i = 0 to len(source) - 1
    source[i] = ((i * 71) ^ (i div 7)) & 255
  end for
  expected = crc.compute(source)
  detected = cpu.features()
  for each mask in [0, cpu.SSE2, 127, -1]
    cpu.setDispatchMaskForTesting(mask)
    checkEq(cpu.activeFeatures() & detected, cpu.activeFeatures(), "cannot enable unsupported features")
    checkEq(crc.compute(source), expected, "CRC32 dispatch")
    for size = 0 to 280
      copied = slice(source, 3, size)
      filled = bytes(size, 165)
      checkEq(len(copied), size, "copy length")
      checkEq(len(filled), size, "fill length")
      if size > 0 then
        for i = 0 to size - 1
          checkEq(copied[i], source[i + 3], "unaligned copy")
          checkEq(filled[i], 165, "fill contents")
        end for
      end if
      first = crc.update(0, source, 0, size)
      checkEq(crc.update(first, source, size, len(source) - size), expected, "CRC32 incremental")
    end for
    for each size in [511, 512, 513, 1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096, 4097, 8191, 16383, 16385, 32767, 32768, 32769, 65535]
      copied = slice(source, 5, size)
      filled = bytes(size, 90)
      for i = 0 to size - 1
        checkEq(copied[i], source[i + 5], "large copy contents")
        checkEq(filled[i], 90, "large fill contents")
      end for
    end for
  end for
  cpu.setDispatchMaskForTesting(-1)
  checkEq(cpu.activeFeatures(), detected, "restore CPU features")
  if failures != 0 then return 1 end if
  print "[OK] ISA runtime"
end function
