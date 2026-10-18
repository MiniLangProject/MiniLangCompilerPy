// Optimizer safety: rooted scalar fields, escapes, calls and register lifetimes.
import "optimizer_support/defer_scope.ml" as deferred
struct Pair
  x,
  y,
end struct

struct TypedPair
  x as int,
  y as int,
end struct

function makeText(value)
  gc_collect()
  return "value:" + value
end function

function scalarLocal(n as int)
  p = Pair(2, 3)
  total = 0
  for i = 0 to n - 1
    p.x = p.x + 1
    total = total + p.x + p.y
  end for
  return total
end function

function scalarRoots()
  p = Pair(makeText(1), makeText(2))
  gc_collect()
  p.y = makeText(3)
  gc_collect()
  return p.x + "/" + p.y
end function

function escaped()
  p = Pair(2, 3)
  q = p
  q.x = 9
  return p.x
end function

function returnObject()
  p = Pair(2, 3)
  return p
end function

function rebound()
  p = Pair(2, 3)
  p = Pair(5, 7)
  return p.x + p.y
end function

function typed()
  p = TypedPair("wrong", 3)
  return p.x
end function

function deliberatelyUnreferencedLeaf()
  return 918273
end function

function registers(n as int)
  aa = 1
  bb = 2
  cc = 3
  dd = 4
  ee = 5
  ff = 6
  for i = 1 to n
    aa = aa + i
    bb = bb + aa
    cc = cc + bb
    dd = dd + cc
    ee = ee + dd
    ff = ff + ee
    // Repeated reads make all six mirrors profitable; the GC call must
    // preserve even XMM8-XMM11. The bounded test inputs keep this positive.
    check = aa + bb + cc + dd + ee + ff
    if check + ff < 0 then return -1 end if
    if i % 3 == 0 then gc_collect() end if
  end for
  first = aa + bb + cc + dd + ee + ff
  gg = 10
  hh = 20
  ii = 30
  for j = 1 to n
    gg = gg + j
    hh = hh + gg
    ii = ii + hh
  end for
  return first + gg + hh + ii
end function

// The second loop may reuse the first loop's two physical register homes.
function reuseLifetimes(n as int)
  a = 1
  b = 2
  for i = 1 to n
    a = (a + a + a + i) % 1009
    b = (b + b + b + a) % 1013
  end for
  first = a + b
  c = 3
  d = 4
  for j = 1 to n
    c = (c + c + c + j) % 1019
    d = (d + d + d + c) % 1021
  end for
  return first + c + d
end function

function main(args)
  if reuseLifetimes(20) != 2054 then return 8 end if
  if deferred.exercise() != 1 or deferred.result() != "module" then return 7 end if
  if scalarLocal(4) != 30 then return 1 end if
  if scalarRoots() != "value:1/value:3" then return 2 end if
  if escaped() != 9 then return 3 end if
  if returnObject().y != 3 then return 4 end if
  if rebound() != 12 then return 5 end if
  failure = try(typed())
  if typeof(failure) != "error" then return 6 end if
  print registers(20)
  print "OPTIMIZER SAFETY [OK]"
  return 0
end function
