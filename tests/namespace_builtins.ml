import "namespace_builtins_support/ops.ml" as imported

namespace LocalBuiltins
  function slice(source, start = 0, count = 2)
    return [91, 92]
  end function

  function len(value)
    return 93
  end function

  function decode(value)
    return "namespace-decode"
  end function

  function typeof(value)
    return "namespace-type"
  end function

  function slicingFunction()
    return slice
  end function

  function check(value)
    direct = slice(value, 0, 2)
    if direct[0] != 91 or direct[1] != 92 then return 11 end if
    omitted = slice(value)
    if omitted[0] != 91 or omitted[1] != 92 then return 12 end if
    named = slice(count = 2, source = value)
    if named[0] != 91 or named[1] != 92 then return 13 end if
    if len(value) != 93 or len("Grüße 🌍") != 93 then return 14 end if
    if decode(value) != "namespace-decode" then return 15 end if
    if decode(slice(value, 0, 2)) != "namespace-decode" then return 16 end if
    if typeof(value) != "namespace-type" or typeof(123) != "namespace-type" then return 17 end if
    stored = slice
    indirect = stored(value, 0, 2)
    if indirect[0] != 91 or indirect[1] != 92 then return 18 end if
    return 0
  end function
end namespace

function main(args)
  value = bytes("abcd")
  status = LocalBuiltins.check(value)
  if status != 0 then return status end if
  status = imported.check(value)
  if status != 0 then return status end if

  // Explicit qualification and returned function values keep their target.
  direct = LocalBuiltins.slice(value, 0, 2)
  if direct[0] != 91 or direct[1] != 92 then return 41 end if
  aliased = imported.slice(value, 0, 2)
  if aliased[0] != 191 or aliased[1] != 192 then return 42 end if
  first = LocalBuiltins.slicingFunction()
  second = imported.slicingFunction()
  firstValue = first(value, 0, 2)
  secondValue = second(value, 0, 2)
  if firstValue[0] != 91 or secondValue[0] != 191 then return 43 end if
  if LocalBuiltins.len(value) != 93 or imported.len(value) != 193 then return 44 end if
  if LocalBuiltins.decode(value) != "namespace-decode" or imported.decode(value) != "module-decode" then return 45 end if
  if LocalBuiltins.typeof(value) != "namespace-type" or imported.typeof(value) != "module-type" then return 46 end if

  // The root scope still resolves the real builtins, including their fusion.
  if len(value) != 4 or len("Grüße 🌍") != 12 then return 51 end if
  if decode(value) != "abcd" then return 52 end if
  if decode(slice(value, 1, 2)) != "bc" then return 53 end if
  if typeof(value) != "bytes" or typeof(123) != "int" then return 54 end if
  builtinLength = len
  if builtinLength(value) != 4 then return 55 end if

  print "[OK] namespace functions with builtin names"
  return 0
end function
