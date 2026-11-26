import "modules/typed.ml" as typed

struct Record
  right
  left
end struct

function main(args)
  value = typed.make()
  if value.right != 22 then
    print "[FAIL] stored annotated return uses caller field layout"
    print value.right
    return 1
  end if
  if typed.make().right != 22 then return 2 end if
  if typed.identity(value).right != 22 then return 3 end if
  if typed.rightOf(value) != 22 then return 4 end if
  copied = value.copy()
  if copied.right != 22 or copied.left != 11 then return 5 end if
  if typeName(copied) != "regression.struct_identity.typed.Record" then return 6 end if
  entry = Record(33, 44)
  if entry.right != 33 or entry.left != 44 then return 7 end if
  print "[OK] struct namespace declared type context"
  return 0
end function
