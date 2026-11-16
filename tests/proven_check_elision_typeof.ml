// A declared global typeof with a default parameter retains its normal call ABI.
// Even a literal guard must keep this observable call; the value alone cannot
// prove that eliminating the guard also preserves the declaration's effects.
calls = 0

function typeof(value, label = "int")
  global calls
  calls = calls + 1
  return label
end function

function guarded()
  value as int = 7
  return value
end function

function main(args)
  if typeof(args) != "int" then return 1 end if
  if guarded() != 7 then return 2 end if
  if calls != 2 then return 3 end if
  print "PROVEN CHECK TYPEOF [OK]"
  return 0
end function
