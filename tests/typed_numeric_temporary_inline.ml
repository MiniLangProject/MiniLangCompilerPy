// A typed helper with one temporary must retain the public Value ABI.
function integerStep(x as int) returns int
  intermediate = x + 3
  return intermediate * 2
end function

// A checked local initializer can reuse a guarded integer parameter.
function typedLocalStep(x as int) returns int
  intermediate as int = x + 3
  return intermediate * 2
end function

function floatStep(x as float) returns float
  intermediate = x * 0.5
  return intermediate + 0.125
end function

function main(args)
  if integerStep(4) != 14 then return 1 end if
  fn = integerStep
  if fn(5) != 16 then return 2 end if
  wrong = try(integerStep("bad"))
  if typeof(wrong) != "error" or wrong.code != 1308 then return 3 end if
  wrong = try(fn("bad"))
  if typeof(wrong) != "error" or wrong.code != 1308 then return 4 end if
  if typedLocalStep(4) != 14 then return 7 end if
  typedFn = typedLocalStep
  if typedFn(5) != 16 then return 8 end if
  wrong = try(typedLocalStep("bad"))
  if typeof(wrong) != "error" or wrong.code != 1308 then return 9 end if
  wrong = try(typedFn("bad"))
  if typeof(wrong) != "error" or wrong.code != 1308 then return 10 end if
  if floatStep(0.5) != 0.375 then return 5 end if
  if typeof(floatStep(0.5)) != "float" then return 6 end if
  print "TYPED NUMERIC TEMPORARY INLINE [OK]"
end function
