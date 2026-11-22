/// Exercise repeated reclamation of mixed small, medium, and large objects.
/// Prints a post-collection sample after every cycle for leak trend analysis.
#if TARGET_OS == "windows"
extern function process() from "kernel32.dll" symbol "GetCurrentProcess" returns ptr
extern function memoryInfo(handle as ptr, output as bytes, size as u32) from "psapi.dll" symbol "GetProcessMemoryInfo" returns i32
#endif

function read64(buffer, offset as int) returns int
  value = 0
  for i = 0 to 7
    value = value | (buffer[offset + i] << (8 * i))
  end for
  return value
end function

function flushHandoffs()
  sum = 0
  for i = 0 to 15
    value = bytes(8, i)
    sum += value[0]
  end for
  return sum
end function

function churn(seed)
  ring = array(128, void)
  sum = 0
  for i = 0 to 39999
    fill = (i + seed) % 251
    if i % 17 == 0 then
      ring[i % 128] = bytes(8192, fill)
    else
      ring[i % 128] = [i, bytes(96, fill)]
    end if
    if i % 997 == 0 then
      value = ring[i % 128]
      if typeof(value) == "bytes" then sum += value[8191]
      else sum += value[1][0]
      end if
    end if
  end for
  large = bytes(4 * 1024 * 1024, seed % 251)
  return sum + large[0] + large[len(large) - 1]
end function

function sample(cycle, memory)
  flushHandoffs()
  gc_collect()
  privateCommit = 0
#if TARGET_OS == "windows"
  if memoryInfo(process(), memory, 80) == 0 then return false end if
  privateCommit = read64(memory, 72)
#endif
  print "cycle=" + cycle + " live=" + gc_stat(1) + " reclaimed=" + gc_stat(2) + " committed=" + heap_bytes_committed() + " frontier=" + heap_bytes_used() + " free=" + heap_free_bytes() + " private=" + privateCommit
  return true
end function

function main(args)
  gc_set_limit(0)
  memory = bytes(80)
  if not sample(0, memory) then return 2 end if
  checksum = 0
  for cycle = 1 to 24
    checksum += churn(cycle)
    if not sample(cycle, memory) then return 3 end if
  end for
  if checksum <= 0 then return 1 end if
  print "MEMORY LONG CHURN [OK] checksum=" + checksum
  return 0
end function
