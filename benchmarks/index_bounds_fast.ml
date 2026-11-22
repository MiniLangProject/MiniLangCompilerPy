// Exercise a dynamic index in a hot loop; bounds cannot be proven at compile time.
// Build with -DSTORE=true to measure the corresponding indexed write path.
#option STORE: bool = false
#option GENERIC: bool = false

#if GENERIC
function work(values, limit as int) returns int
#else
function work(values as array, limit as int) returns int
#endif
#if STORE
  for i = 0 to limit - 1
    values[i & 255] = i
  end for
  return values[0] + values[255]
#else
  total = 0
  for i = 0 to limit - 1
    total += values[i & 255]
  end for
  return total
#endif
end function

function main(args)
#if STORE
  values = array(256, 0)
#else
  values = array(256, 1)
#endif
  print work(values, 30000000)
end function
