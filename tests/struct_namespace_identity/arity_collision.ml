// MiniQuake3's constructor-arity failure: the imported Record has two fields.
import "modules/model.ml" as model

struct Record
  left
  right
  extra
end struct

function main(args)
  value = model.make()
  print value.right
  if value.right != 22 then return 1 end if
  return 0
end function
