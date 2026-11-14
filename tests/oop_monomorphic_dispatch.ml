class Solo
  function calc(a, b, c, d, e, f, g, h) returns int
    return a + b + c + d + e + f + g + h
  end function
end class

class Other
  value as int = 0
end class

class PairA
  function pick(value as int) returns int
    return value + 10
  end function
end class

class PairB
  function pick(value as int) returns int
    return value + 20
  end function
end class

final class Exact
  function identify() returns int
    return 73
  end function
end class

calls = 0
function argument(value as int) returns int
  global calls
  calls += 1
  return value
end function

/// Receiver type is unknown here; a single candidate still needs a runtime check.
function probe(receiver)
  return receiver.calc(argument(1), argument(2), argument(3), argument(4),
                       argument(5), argument(6), argument(7), argument(8))
end function

/// Two implementations use ordered type-ID checks rather than a cache.
function probePair(receiver)
  return receiver.pick(argument(4))
end function

function typedProbe(receiver as Exact)
  return receiver.identify()
end function

function main(args)
  global calls
  if probe(Solo()) != 36 then return 1 end if
  if calls != 8 then return 2 end if
  if typeof(try(probe(Other()))) != "error" then return 3 end if
  if calls != 16 then return 4 end if
  if typeof(try(probe(7))) != "error" then return 5 end if
  if calls != 24 then return 6 end if
  if probePair(PairA()) != 14 then return 7 end if
  if probePair(PairB()) != 24 then return 8 end if
  if typeof(try(probePair(Other()))) != "error" then return 9 end if
  if calls != 27 then return 10 end if
  if typedProbe(Exact()) != 73 then return 11 end if
  if typeof(try(typedProbe(Other()))) != "error" then return 12 end if
  print "[OK] monomorphic dispatch"
  return 0
end function
