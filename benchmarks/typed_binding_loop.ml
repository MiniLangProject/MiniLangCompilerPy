// Exercise persistent int assignments on both sides of a loop branch.
function count(limit as int) returns int
  var value as int = 1
  for i = 1 to limit
    if (i & 1) == 0 then
      value += i
    else
      value += 1
    end if
  end for
  return value
end function

print count(30000000)
