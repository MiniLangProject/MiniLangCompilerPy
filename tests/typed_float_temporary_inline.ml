// Verify private float-temp fusion and its normalization fallback.
function floatStep(x as float) returns float
  intermediate = x * 0.5
  return intermediate + 0.125
end function
function main(args)
  if floatStep(0.5) != 0.375 then return 1 end if
  if typeof(floatStep(0.5)) != "float" then return 2 end if
  if floatStep(2.0) != 1.125 then return 3 end if
  if floatStep(0.0) != 0.125 then return 4 end if
  result = try(floatStep(-0.25))
  if typeof(result) != "error" or result.code != 1308 then return 5 end if
  if result.func != "floatStep" then return 8 end if
  alias = floatStep
  if alias(0.5) != 0.375 then return 6 end if
  bad = try(floatStep("bad"))
  if typeof(bad) != "error" or bad.code != 1308 then return 7 end if
  gc_set_limit(1)
  for i = 1 to 16
    if floatStep(0.1) != 0.175 then return 9 end if
  end for
  gc_set_limit(0)
  print "TYPED FLOAT TEMPORARY INLINE [OK]"
end function
