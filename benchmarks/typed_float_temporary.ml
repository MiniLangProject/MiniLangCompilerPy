function step(x as float) returns float
  y = x * 0.999999
  return y + 0.00001
end function
function main(args)
  total = 0.125
  for i = 1 to 10000000
    total = total + step(0.125)
  end for
  if total < 0 then return 1 end if
  print "FLOAT [OK]"
end function
