struct Box
  value
end struct
enum State are
  Ready
end enum
function identity(value)
  return value
end function
function worker()
  return 9
end function
function check(value)
  actual = typeof(value)
  if (typeof(value) == "int") != (actual == "int") then
    print "[FAIL] int == reverse=False; actual=" + actual
    return 1
  end if
  if (typeof(value) != "int") != (actual != "int") then
    print "[FAIL] int != reverse=False; actual=" + actual
    return 1
  end if
  if ("int" == typeof(value)) != (actual == "int") then
    print "[FAIL] int == reverse=True; actual=" + actual
    return 1
  end if
  if ("int" != typeof(value)) != (actual != "int") then
    print "[FAIL] int != reverse=True; actual=" + actual
    return 1
  end if
  if (typeof(value) == "bool") != (actual == "bool") then
    print "[FAIL] bool == reverse=False; actual=" + actual
    return 2
  end if
  if (typeof(value) != "bool") != (actual != "bool") then
    print "[FAIL] bool != reverse=False; actual=" + actual
    return 2
  end if
  if ("bool" == typeof(value)) != (actual == "bool") then
    print "[FAIL] bool == reverse=True; actual=" + actual
    return 2
  end if
  if ("bool" != typeof(value)) != (actual != "bool") then
    print "[FAIL] bool != reverse=True; actual=" + actual
    return 2
  end if
  if (typeof(value) == "float") != (actual == "float") then
    print "[FAIL] float == reverse=False; actual=" + actual
    return 3
  end if
  if (typeof(value) != "float") != (actual != "float") then
    print "[FAIL] float != reverse=False; actual=" + actual
    return 3
  end if
  if ("float" == typeof(value)) != (actual == "float") then
    print "[FAIL] float == reverse=True; actual=" + actual
    return 3
  end if
  if ("float" != typeof(value)) != (actual != "float") then
    print "[FAIL] float != reverse=True; actual=" + actual
    return 3
  end if
  if (typeof(value) == "string") != (actual == "string") then
    print "[FAIL] string == reverse=False; actual=" + actual
    return 4
  end if
  if (typeof(value) != "string") != (actual != "string") then
    print "[FAIL] string != reverse=False; actual=" + actual
    return 4
  end if
  if ("string" == typeof(value)) != (actual == "string") then
    print "[FAIL] string == reverse=True; actual=" + actual
    return 4
  end if
  if ("string" != typeof(value)) != (actual != "string") then
    print "[FAIL] string != reverse=True; actual=" + actual
    return 4
  end if
  if (typeof(value) == "array") != (actual == "array") then
    print "[FAIL] array == reverse=False; actual=" + actual
    return 5
  end if
  if (typeof(value) != "array") != (actual != "array") then
    print "[FAIL] array != reverse=False; actual=" + actual
    return 5
  end if
  if ("array" == typeof(value)) != (actual == "array") then
    print "[FAIL] array == reverse=True; actual=" + actual
    return 5
  end if
  if ("array" != typeof(value)) != (actual != "array") then
    print "[FAIL] array != reverse=True; actual=" + actual
    return 5
  end if
  if (typeof(value) == "bytes") != (actual == "bytes") then
    print "[FAIL] bytes == reverse=False; actual=" + actual
    return 6
  end if
  if (typeof(value) != "bytes") != (actual != "bytes") then
    print "[FAIL] bytes != reverse=False; actual=" + actual
    return 6
  end if
  if ("bytes" == typeof(value)) != (actual == "bytes") then
    print "[FAIL] bytes == reverse=True; actual=" + actual
    return 6
  end if
  if ("bytes" != typeof(value)) != (actual != "bytes") then
    print "[FAIL] bytes != reverse=True; actual=" + actual
    return 6
  end if
  if (typeof(value) == "function") != (actual == "function") then
    print "[FAIL] function == reverse=False; actual=" + actual
    return 7
  end if
  if (typeof(value) != "function") != (actual != "function") then
    print "[FAIL] function != reverse=False; actual=" + actual
    return 7
  end if
  if ("function" == typeof(value)) != (actual == "function") then
    print "[FAIL] function == reverse=True; actual=" + actual
    return 7
  end if
  if ("function" != typeof(value)) != (actual != "function") then
    print "[FAIL] function != reverse=True; actual=" + actual
    return 7
  end if
  if (typeof(value) == "thread") != (actual == "thread") then
    print "[FAIL] thread == reverse=False; actual=" + actual
    return 8
  end if
  if (typeof(value) != "thread") != (actual != "thread") then
    print "[FAIL] thread != reverse=False; actual=" + actual
    return 8
  end if
  if ("thread" == typeof(value)) != (actual == "thread") then
    print "[FAIL] thread == reverse=True; actual=" + actual
    return 8
  end if
  if ("thread" != typeof(value)) != (actual != "thread") then
    print "[FAIL] thread != reverse=True; actual=" + actual
    return 8
  end if
  if (typeof(value) == "struct") != (actual == "struct") then
    print "[FAIL] struct == reverse=False; actual=" + actual
    return 9
  end if
  if (typeof(value) != "struct") != (actual != "struct") then
    print "[FAIL] struct != reverse=False; actual=" + actual
    return 9
  end if
  if ("struct" == typeof(value)) != (actual == "struct") then
    print "[FAIL] struct == reverse=True; actual=" + actual
    return 9
  end if
  if ("struct" != typeof(value)) != (actual != "struct") then
    print "[FAIL] struct != reverse=True; actual=" + actual
    return 9
  end if
  if (typeof(value) == "enum") != (actual == "enum") then
    print "[FAIL] enum == reverse=False; actual=" + actual
    return 10
  end if
  if (typeof(value) != "enum") != (actual != "enum") then
    print "[FAIL] enum != reverse=False; actual=" + actual
    return 10
  end if
  if ("enum" == typeof(value)) != (actual == "enum") then
    print "[FAIL] enum == reverse=True; actual=" + actual
    return 10
  end if
  if ("enum" != typeof(value)) != (actual != "enum") then
    print "[FAIL] enum != reverse=True; actual=" + actual
    return 10
  end if
  if (typeof(value) == "void") != (actual == "void") then
    print "[FAIL] void == reverse=False; actual=" + actual
    return 11
  end if
  if (typeof(value) != "void") != (actual != "void") then
    print "[FAIL] void != reverse=False; actual=" + actual
    return 11
  end if
  if ("void" == typeof(value)) != (actual == "void") then
    print "[FAIL] void == reverse=True; actual=" + actual
    return 11
  end if
  if ("void" != typeof(value)) != (actual != "void") then
    print "[FAIL] void != reverse=True; actual=" + actual
    return 11
  end if
  return 0
end function
calls = 0
function effect(value)
  global calls
  calls += 1
  return value
end function
function effectProbe(value)
  return typeof(effect(value)) == "int"
end function
function reverseEffectProbe(value)
  return "int" != typeof(effect(value))
end function
function main(args)
  captured = 3
  closure = function(x) => x + captured
  thread = Thread(worker)
  mutable = array(2, 7)
  values = [0, -1, true, false, 1.5, toFloat("1.23456789012345"), "", "text", [], [1, 2], mutable, bytes(0), bytes(2), identity, closure, len, thread, Box(1), Box, State.Ready, void, try(error(1700, "probe")), nativeValueFromRaw(7)]
  for i = 0 to len(values) - 1
    value = try(values[i])
    if check(value) != 0 then return 1 end if
  end for
  if typeof(Box) != "struct" then return 2 end if
  if typeof(State.Ready) != "enum" then return 3 end if
  if not thread.Start() or not thread.Join(10000) then return 4 end if
  if thread.Result() != 9 or not thread.Close() then return 5 end if
  if typeof(State) != "enum" then return 6 end if
  if not effectProbe(7) or not reverseEffectProbe("x") then return 7 end if
  if calls != 2 then return 8 end if
  print "[OK] 1012 direct typeof truth-table comparisons; nominal names and thread lifecycle"
  return 0
end function
