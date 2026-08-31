function restCount(first, rest...)
  return [first, len(rest), rest[0], rest[1]]
end function

function main(args)
  result = restCount(7, 8, 9)
  if result[0] != 7 or result[1] != 2 then return 1 end if
  if result[2] != 8 or result[3] != 9 then return 2 end if
  return 0
end function
