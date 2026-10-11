import "type_flow_context_lib.ml" as encoded

function main(args)
  if encoded.unpack(0) != 0 then return 1 end if
  if encoded.unpack(515) != 2 then return 2 end if
  if typeof(encoded.unpack(515)) != "int" then return 3 end if
  print("[OK] type-flow function context")
  return 0
end function
