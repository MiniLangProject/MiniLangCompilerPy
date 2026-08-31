// Runtime contracts for the optimized forms of the modern language features.

function typedAdd(left as int, right as int) returns int
  return left + right
end function

function checkedDynamicReturn(value) returns int
  return value
end function

function sumTail(values...)
  total = 0
  for each value in values
    total = total + value
  end for
  return total
end function

function keepTail(values...)
  return values
end function

lazy iterator function lazyNumbers(limit as int) returns int
  for i = 0 to limit - 1
    if i % 2 == 0 then
      yield typedAdd(i, 1)
    end if
  end for
end function

async function pooledDouble(value as int) returns int
  return value * 2
end function

function fail(message)
  print "[FAIL] " + message
  return 1
end function

function main(args)
if typedAdd(20, 22) != 42 then return fail("typed automatic inline") end if
badReturn = try(checkedDynamicReturn("not an int"))
if typeof(badReturn) != "error" then return fail("dynamic return contract was elided") end if

heapBefore = heap_bytes_used()
if sumTail(1, 2, 3, 4, 5) != 15 then return fail("variadic stack view result") end if
heapAfter = heap_bytes_used()
if heapAfter != heapBefore then return fail("non-escaping variadic tail allocated") end if

kept = keepTail(6, 7, 8)
if len(kept) != 3 or kept[0] != 6 or kept[2] != 8 then return fail("escaping variadic heap fallback") end if

pull = lazyNumbers(6)
if typeof(pull) != "function" then return fail("lazy iterator pull handle") end if
if pull() != 1 or pull() != 3 or pull() != 5 or typeof(pull()) != "void" then
  return fail("lazy iterator pull sequence")
end if

sum = 0
for each value in lazyNumbers(100000)
  sum = sum + value
end for
if sum != 2500000000 then return fail("lazy iterator foreach") end if

jobs = []
for i = 0 to 31
  jobs = jobs + [pooledDouble(i)]
end for
for i = 0 to 31
  if typeof(jobs[i]) != "struct" or await jobs[i] != i * 2 then
    return fail("pooled async result")
  end if
end for

print "[OK] optimized language features"
return 0
end function
