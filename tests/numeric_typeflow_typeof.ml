// A custom typeof may approve values that do not have the declared tag.
// New parameter facts and return-guard elision must respect its resolution.
calls = 0

function typeof(value, label = "float")
  global calls
  calls = calls + 1
  return label
end function

function shadowedParameter(value as float)
  return value + 1
end function

function nestedReturn(first) returns float
  if first then
    result = 0.25
    return result
  end if
  return 0.5
end function

function main(args)
  global calls
  // An explicit use also keeps the custom callable live in older compilers.
  if typeof(args) != "float" then return 1 end if
  calls = 0
  if shadowedParameter("x") != "x1" then return 2 end if
  if shadowedParameter(9007199254740993) != 9007199254740994 then return 3 end if
  if calls != 2 then return 4 end if
  if nestedReturn(true) != 0.25 then return 5 end if
  if calls != 3 then return 6 end if
  // The old literal return already omits this guard. Preserve that behavior
  // while retaining the formerly observable nested-variable return check.
  if nestedReturn(false) != 0.5 then return 7 end if
  if calls != 3 then return 8 end if
  print "NUMERIC TYPEFLOW TYPEOF [OK]"
  return 0
end function
