// A user-defined typeof has observable effects at each type contract.
calls = 0
function typeof(value, label = "int")
  global calls
  calls = calls + 1
  return label
end function
function typedLocalStep(x as int) returns int
  intermediate as int = x + 3
  return intermediate * 2
end function
function main(args)
  if typedLocalStep(4) != 14 then return 1 end if
  if calls != 2 then return 2 end if
  print "TYPED LOCAL CUSTOM TYPEOF [OK]"
end function
