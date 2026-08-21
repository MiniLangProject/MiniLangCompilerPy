order = []

function remember(value)
  global order
  order = order + [value]
end function

function exercise(flag)
  value = 10
  defer remember(value)
  value = 20
  if flag then
    defer remember(30)
  end if
  defer remember(value)
  return 77
end function

result = exercise(true)
print result
print order[0]
print order[1]
print order[2]
print "defer features [OK]"
