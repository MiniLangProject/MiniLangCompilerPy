import "modules/fallback.ml" as imported

struct EntryOnly
  value
end struct

function main(args)
  first = imported.entryValue()
  constructor = imported.entryConstructor()
  second = constructor(99)
  if first.value != 88 or second.value != 99 then return 1 end if
  if typeName(first) != "EntryOnly" or typeName(second) != "EntryOnly" then return 2 end if
  print "[OK] struct namespace entry fallback"
  return 0
end function
