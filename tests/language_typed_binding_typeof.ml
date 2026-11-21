// The old assignment contract observes this function. A fixed declaration
// and its writes check the actual runtime type even when typeof is shadowed.
calls = 0

function typeof(value, label = "int")
  global calls
  calls += 1
  return label
end function

function dynamicCheck(value)
  checked as int = value
  return checked
end function

function fixedCheck(value)
  var checked as int = 1
  checked = value
  return checked
end function

function main(args)
  if dynamicCheck("accepted") != "accepted" or calls != 1 then return 1 end if
  invalid = try(fixedCheck("rejected"))
  if invalid.code != 1308 or calls != 1 then return 2 end if
  if fixedCheck(9) != 9 or calls != 1 then return 3 end if
  print "TYPED BINDING TYPEOF [OK]"
  return 0
end function
