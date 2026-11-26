package regression.namespace_builtins.module

function slice(source, start = 0, count = 2)
  return [191, 192]
end function

function len(value)
  return 193
end function

function decode(value)
  return "module-decode"
end function

function typeof(value)
  return "module-type"
end function

function slicingFunction()
  return slice
end function

function check(value)
  direct = slice(value, 0, 2)
  if direct[0] != 191 or direct[1] != 192 then return 21 end if
  omitted = slice(value)
  if omitted[0] != 191 or omitted[1] != 192 then return 22 end if
  named = slice(count = 2, source = value)
  if named[0] != 191 or named[1] != 192 then return 23 end if
  if len(value) != 193 or len("Grüße 🌍") != 193 then return 24 end if
  if decode(value) != "module-decode" then return 25 end if
  if decode(slice(value, 0, 2)) != "module-decode" then return 26 end if
  if typeof(value) != "module-type" or typeof(123) != "module-type" then return 27 end if
  stored = slice
  indirect = stored(value, 0, 2)
  if indirect[0] != 191 or indirect[1] != 192 then return 28 end if
  return 0
end function
