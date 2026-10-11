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
  if nestedCondition(5, 6, 7, 8) != 6 then return 2 end if
  if literalBudget(1) != 16 or literalBudget(0) != 0 then return 3 end if
  return 0
end function

// Every Bin child counts, including another Bin. This short source used to
// produce a 14 KiB larger image with Python than with the native compiler.
function nestedCondition(a, b, c, d)
  value = 0
  for side = 0 to 3
    if a > side and b > side and c > side and d > side then
      value = value + side
    end if
  end for
  return value
end function

// Twelve AST nodes exactly: If + Bin + Var + Num + eight assignments.
// The numeric literal's payload is not an extra expression node.
function literalBudget(a)
  value = 0
  for side = 0 to 1
    if a > 0 then
      value = value + 1
      value = value + 1
      value = value + 1
      value = value + 1
      value = value + 1
      value = value + 1
      value = value + 1
      value = value + 1
    end if
  end for
  return value
end function
