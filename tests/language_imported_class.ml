import "imported_class_lib.ml"

class Derived extends imported_class_lib.Base
  override function label() returns string
    return super.label() + "!"
  end function
end class

function main(args)
  value = Derived(value = "import")
  if value.label() != "import!" then return 1 end if
  if not (value is imported_class_lib.Base) then return 2 end if
  if not (value is imported_class_lib.Named) then return 3 end if
  print "[OK] imported class inheritance"
  return 0
end function
