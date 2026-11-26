import "modules/builtins.ml" as measured

function main(args)
  instance = measured.InstanceMeasure("Grüße 🌍")
  if instance.len() != 12 then return 1 end if
  if instance.lengthOf("ä") != 2 then return 2 end if
  if instance.lengthOf([10, 20, 30]) != 3 then return 3 end if
  if measured.StaticMeasure.lengthOf("Grüße 🌍") != 12 then return 4 end if
  if measured.StaticMeasure.len("anything") != 700 then return 5 end if
  if measured.StaticMeasure.throughSibling(40) != 41 then return 6 end if
  print "[OK] struct namespace builtin and method precedence"
  return 0
end function
