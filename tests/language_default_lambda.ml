// Modern expressions in default parameters must pass through language lowering.
function applyDefault(value, callback = function(x) => x + 1)
  return callback(value)
end function

struct Transformer
  function apply(value, callback = function(x) => x * 2)
    return callback(value)
  end function
end struct

function main(args)
  custom = function(x) => x - 3
  if applyDefault(41) != 42 or applyDefault(10, custom) != 7 then return 1 end if
  transformer = Transformer()
  if transformer.apply(21) != 42 or transformer.apply(10, custom) != 7 then return 2 end if
  print "[OK] lowered lambda default arguments"
  return 0
end function
