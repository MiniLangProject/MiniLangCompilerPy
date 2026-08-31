async function doubled(value as int) returns int
  return value * 2
end function

function main(args)
  one = doubled(10)
  two = doubled(value = 11)
  winner = select(one, two)
  if winner < 0 or winner > 1 then return 1 end if
  if await one != 20 or await two != 22 then return 2 end if
  return 0
end function
