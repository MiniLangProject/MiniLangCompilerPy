// This deterministic-only program must not need the platform crypto provider.
import std.random as random

function main(args)
  rng = random.seeded(123)
  expected = [31682556, 4018661298, 2101636938, 3842487452, 1628673942]
  for i = 0 to len(expected) - 1
    if rng.nextU32() != expected[i] then return 1 end if
  end for
  print "[OK] seeded-only random"
  return 0
end function
