// Same spelling does not make a user callable the builtin conversion.
function toFloat(value, replacement = 9007199254740993)
  return replacement
end function

function converted(value as int)
  number = toFloat(value)
  return number + 1
end function

function replacement(value, unused = 0)
  return "changed"
end function

function main(args)
  global toFloat
  if converted(1) != 9007199254740994 then return 1 end if
  toFloat = replacement
  if converted(1) != "changed1" then return 2 end if
  print "NUMERIC TYPEFLOW TOFLOAT [OK]"
  return 0
end function
