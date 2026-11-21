// Compare checks on hot copies between two bindings of the same type.
function copyRepeatedly(limit, text)
  var source as string = text
  var destination as string = ""
  for i = 1 to limit
    if (i & 1) == 0 then
      destination = source
    end if
  end for
  return destination
end function

print copyRepeatedly(30000000, "MiniLang")
