function add_pair(a, b)
  return a + b
end function

struct CallableBox
  fn
end struct

function main(args)
  box = CallableBox(add_pair)
  if box.fn(20, 22) != 42 then return 1 end if
  print "[OK] callable struct member"
  return 0
end function
