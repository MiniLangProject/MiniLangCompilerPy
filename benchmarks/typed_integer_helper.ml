function step(x as int) returns int
  y = x + 3
  return y * 2
end function

function main(args)
  total = 0
  for i = 1 to 30000000
    total = total + step(i)
  end for
  print total
end function
