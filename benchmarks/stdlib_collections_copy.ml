/*
Copyright 2026 Nils Kopal

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Diagnostic timings for stable sorting, map churn, channel deadlines and
// whole-file copying. Run repeated independent processes on the same host.
import std.concurrent.channel as channel
import std.ds.hashmap as hashmap
import std.fs as fs
import std.process as process
import std.sort as sort
import std.time as time

function lessInteger(left, right)
  return left < right
end function

// Reproduce the previous stable insertion-sort loop on the same reversed
// input; this is a benchmark baseline, not a production sort implementation.
function previousStableSort(values)
  index = 1
  while index < len(values)
    key = values[index]
    previous = index - 1
    while previous >= 0 and lessInteger(key, values[previous])
      values[previous + 1] = values[previous]
      previous = previous - 1
    end while
    values[previous + 1] = key
    index = index + 1
  end while
end function

function main(args)
  pairedValues = array(8192)
  for index = 0 to 8191 pairedValues[index] = 8192 - index end for
  started = time.ticks()
  previousStableSort(pairedValues)
  oldSortMs = time.ticks() - started
  if pairedValues[0] != 1 or pairedValues[8191] != 8192 then return 12 end if
  for index = 0 to 8191 pairedValues[index] = 8192 - index end for
  started = time.ticks()
  sort.sortBy(pairedValues, lessInteger)
  newSortMs = time.ticks() - started
  if pairedValues[0] != 1 or pairedValues[8191] != 8192 then return 13 end if

  values = array(16384)
  sortMs = 0
  for pass = 0 to 9
    for index = 0 to 16383
      values[index] = 16384 - index
    end for
    started = time.ticks()
    sort.sortBy(values, lessInteger)
    sortMs = sortMs + time.ticks() - started
    if values[0] != 1 or values[16383] != 16384 then return 1 end if
  end for

  map = hashmap.HashMap.withCapacity(16)
  started = time.ticks()
  for index = 0 to 99999
    if not map.set(index, index) or not map.remove(index) then return 2 end if
  end for
  mapMs = time.ticks() - started
  if map.count() != 0 or map.tombstones * 2 > map.cap then return 3 end if

  queue = channel.Channel.new(1)
  started = time.ticks()
  result = queue.ReceiveFor(50)
  timeoutMs = time.ticks() - started
  if result.received or not queue.close() or not queue.Dispose() then return 4 end if

  sourcePath = "stdlib-copy-source-" + process.id() + ".bin"
  targetPath = "stdlib-copy-target-" + process.id() + ".bin"
  if fs.exists(sourcePath) or fs.exists(targetPath) then return 5 end if
  source = bytes(33554432, 0x5A)
  if fs.writeAllBytes(sourcePath, source) != true then return 6 end if
  source = void
  oldCopyMs = -1
#if TARGET_OS == "linux"
  // The previous Linux copyFile implementation was readAllBytes followed
  // by writeAllBytes. Keep an exact local baseline for paired measurements.
  started = time.ticks()
  oldContent = fs.readAllBytes(sourcePath)
  if typeof(oldContent) != "bytes" or fs.writeAllBytes(targetPath, oldContent) != true then return 10 end if
  oldCopyMs = time.ticks() - started
  oldContent = void
  if not fs.delete(targetPath) then return 11 end if
#endif
  started = time.ticks()
  if fs.copyFile(sourcePath, targetPath, false) != true then return 7 end if
  copyMs = time.ticks() - started
  if fs.fileSize(targetPath) != 33554432 then return 8 end if
  if not fs.delete(sourcePath) or not fs.delete(targetPath) then return 9 end if

  print "old_sort_8192_ms=" + oldSortMs + " new_sort_8192_ms=" + newSortMs + " sort_10x16384_ms=" + sortMs + " hashmap_churn_100k_ms=" + mapMs + " channel_50ms_actual=" + timeoutMs + " copy_32mib_ms=" + copyMs + " old_linux_copy_ms=" + oldCopyMs
  return 0
end function
