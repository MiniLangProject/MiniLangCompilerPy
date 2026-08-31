iterator function numbers(limit as int) returns int
  for i = 0 to limit
    yield i
  end for
end function

function main(args)
  values = numbers(4)
  if len(values) != 5 then return 1 end if
  return values[4] - 4
end function
