// Preserve user-defined typeof effects across fused inline calls.
calls = 0
function typeof(value, label = "float")
  global calls
  calls = calls + 1
  return label
end function
function floatStep(x as float) returns float
  intermediate = x * 0.5
  return intermediate + 0.125
end function
function main(args)
  if floatStep(0.5) != 0.375 then return 1 end if
  if calls != 2 then return 2 end if
  print "TYPED FLOAT TEMPORARY TYPEOF [OK]"
end function
