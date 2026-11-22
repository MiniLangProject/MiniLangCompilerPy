function readAt(values as array, index as int)
  return values[index]
end function

function writeAt(values as array, index as int, value as int)
  values[index] = value
end function

function readAny(target, index as int)
  return target[index]
end function

function writeAny(target, index as int, value as int)
  target[index] = value
end function

function isBoundsError(value)
  return typeof(value) == "error" and value.code == 1300
end function

function readLocal(index as int)
  values = [10, 20, 30]
  return values[index]
end function

function writeLocal(index as int)
  values = [10, 20, 30]
  values[index] = 25
  return values[1]
end function

function loopRead(values as array, count as int) returns int
  total = 0
  for i = 0 to count - 1
    total += values[i & 3]
  end for
  return total
end function

function loopWrite(values as array, count as int)
  for i = 0 to count - 1
    values[i & 3] = i
  end for
end function

function main(args)
  values = [10, 20, 30]
  if readAt(values, -1) != 30 or readAt(values, -3) != 10 then return 1 end if
  writeAt(values, -2, 25)
  if values[1] != 25 then return 2 end if

  if not isBoundsError(try(readAt(values, -4))) then return 3 end if
  if not isBoundsError(try(readAt(values, 3))) then return 4 end if
  if not isBoundsError(try(readAt(values, -4294967296))) then return 5 end if
  if not isBoundsError(try(readAt(values, 4294967296))) then return 6 end if
  if not isBoundsError(try(writeAt(values, -4, 99))) then return 7 end if
  if not isBoundsError(try(writeAt(values, 3, 99))) then return 8 end if
  if not isBoundsError(try(writeAt(values, -4294967296, 99))) then return 9 end if
  if not isBoundsError(try(writeAt(values, 4294967296, 99))) then return 10 end if
  if values != [10, 25, 30] then return 11 end if

  empty = []
  if not isBoundsError(try(readAt(empty, -1))) then return 12 end if
  if not isBoundsError(try(writeAt(empty, 0, 99))) then return 13 end if
  if readLocal(-1) != 30 or readLocal(-3) != 10 then return 14 end if
  if writeLocal(-2) != 25 then return 15 end if
  if not isBoundsError(try(readLocal(-4))) then return 16 end if
  if not isBoundsError(try(readLocal(3))) then return 17 end if
  if not isBoundsError(try(readLocal(-4294967296))) then return 18 end if
  if not isBoundsError(try(readLocal(4294967296))) then return 19 end if
  if not isBoundsError(try(writeLocal(-4))) then return 20 end if
  if not isBoundsError(try(writeLocal(3))) then return 21 end if
  if not isBoundsError(try(writeLocal(-4294967296))) then return 22 end if
  if not isBoundsError(try(writeLocal(4294967296))) then return 23 end if
  if loopRead([1, 2, 3, 4], 8) != 20 then return 24 end if
  if not isBoundsError(try(loopRead([1, 2, 3], 8))) then return 25 end if
  written = [0, 0, 0, 0]
  loopWrite(written, 8)
  if written != [4, 5, 6, 7] then return 26 end if
  if not isBoundsError(try(loopWrite([0, 0, 0], 8))) then return 27 end if
  if readAny("abc", -1) != "c" or readAny("abc", -3) != "a" then return 28 end if
  if not isBoundsError(try(readAny("abc", -4))) then return 29 end if
  if not isBoundsError(try(readAny("abc", 4294967296))) then return 30 end if
  buffer = bytes(2)
  writeAny(buffer, -1, 42)
  if readAny(buffer, 1) != 42 then return 31 end if
  if not isBoundsError(try(readAny(buffer, -3))) then return 32 end if
  if not isBoundsError(try(writeAny(buffer, 2, 17))) then return 33 end if
  if not isBoundsError(try(writeAny(buffer, -4294967296, 17))) then return 34 end if
  print "FAST INDEX BOUNDS [OK]"
  return 0
end function
