// Small, simple constant-trip loops may be unrolled, while a larger
// statement/expression tree must retain its loop to avoid code-size blowups.
function complexCondition(a, b, c, d)
  return a * b > c + d
end function

function budgetedLoop()
  result = 0
  for k = 1 to(2)
    if complexCondition(k + 1, k + 2, k + 3, k + 4) then
      result = result + k
    end if
  end for
  return result
end function

function main(args)
  sum1 = 0
  for i = 1 to(4)
    sum1 = sum1 + i
  end for

  sum2 = 0
  for j = 3 to(1)
    sum2 = sum2 + j
  end for

  sum3 = budgetedLoop()
  print(sum1)
  print(sum2)
  print(sum3)
  if sum1 != 10 or sum2 != 6 or sum3 != 2 then
    return 1
  end if
  return 0
end function
