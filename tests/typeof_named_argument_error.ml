/// A comparison fast path must preserve the builtin's call-shape diagnostic.
function check(value)
  return typeof(value = value) == "int"
end function
function main(args)
  print check(1)
  return 0
end function
