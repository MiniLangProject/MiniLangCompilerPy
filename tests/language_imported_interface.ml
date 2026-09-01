import "imported_interface_lib.ml"

function main(args)
  box = imported_interface_lib.Box(value = 42)
  if box.get() != 42 then return 1 end if
  print "[OK] imported interface declarations"
  return 0
end function
