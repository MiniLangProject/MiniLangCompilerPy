// The async wrapper packs a variadic tail exactly once.
async function tailCount(first, rest...)
  return len(rest)
end function

function main(args)
  job = tailCount(10, 20, 30)
  if await job != 2 then return 1 end if
  print "[OK] async variadic arguments"
  return 0
end function
