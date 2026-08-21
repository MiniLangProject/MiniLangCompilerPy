import std.assert as t

function leaf_frame()
  x = 41
  return x + 1
end function

function main(args)
  t.assertEq(leaf_frame(), 42, "small root-frame prologue")
  return 0
end function
