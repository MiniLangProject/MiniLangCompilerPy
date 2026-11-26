// Same arity hides the collision: baseline compilers print 11 instead of 22.
import "modules/model.ml" as model

struct Record
  right
  left
end struct

function main(args)
  value = model.make()
  print value.right
  if value.right != 22 then return 1 end if
  return 0
end function
