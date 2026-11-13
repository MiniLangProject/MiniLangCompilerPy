/// A declared function with this spelling still uses its normalized call ABI.
calls = 0
function typeof(value, label = "custom")
  global calls
  calls += 1
  return label
end function
function check(value)
  if typeof(value) == "int" then return 1 end if
  if "string" == typeof(value) then return 2 end if
  if not (typeof(value) != "array") then return 3 end if
  if not ("bool" != typeof(value)) then return 4 end if
  actual = typeof(value)
  if actual != "custom" then return 5 end if
  if typeof(value = value) != "custom" then return 6 end if
  if typeof(label = "int", value = value) != "int" then return 7 end if
  return 0
end function
function main(args)
  if check(7) != 0 then return 1 end if
  if calls != 7 then return 2 end if
  print "[OK] declared typeof calls preserve defaults, names, arguments and effects"
  return 0
end function
