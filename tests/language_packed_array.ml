import std.ds.packed_array

function writeTo(values, offset, value)
  values.set(offset, value)
end function

function main(args)
  values = std.ds.packed_array.Int32Array(3)
  aliasValues = values
  if values.len() != 3 or values.get(0) != 0 then return 1 end if
  writeTo(aliasValues, 0, -2147483648)
  writeTo(aliasValues, -1, 2147483647)
  if values.get(0) != -2147483648 or values.get(2) != 2147483647 then return 2 end if
  overflow = try(writeTo(aliasValues, 0, 2147483648))
  wrongType = try(writeTo(aliasValues, 0, "invalid"))
  bounds = try(writeTo(aliasValues, 3, 100))
  if overflow.code != 1308 or wrongType.code != 1308 or bounds.code != 1300 then return 3 end if
  gc_collect()
  if values.get(0) != -2147483648 or values.get(-1) != 2147483647 then return 4 end if
  if try(values.get(4294967296)).code != 1300 then return 5 end if
  if try(values.get(-4294967296)).code != 1300 then return 6 end if
  if try(values.get("invalid")).code != 1308 then return 7 end if
  if try(values.set(-1, -2147483649)).code != 1308 then return 8 end if
  if try(values.set(-4, 10)).code != 1300 or values.get(-1) != 2147483647 then return 9 end if
  values.set(value = -7, index = -3)
  if values.get(0) != -7 then return 10 end if
  empty = std.ds.packed_array.Int32Array(0)
  if empty.len() != 0 or try(empty.get(0)).code != 1300 then return 11 end if
  if try(std.ds.packed_array.Int32Array(-1)).code != 1307 then return 12 end if
  print "PACKED ARRAY [OK]"
  return 0
end function
