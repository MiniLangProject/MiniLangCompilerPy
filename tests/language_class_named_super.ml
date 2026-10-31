class Parent
  function value(x as int, y as int = 2) returns int
    return x * 10 + y
  end function
end class

class Child extends Parent
  override function value(x as int, y as int = 2) returns int
    return super.value(y = y, x = x) + 1
  end function
end class

function main(args)
  instance = Child()
  if instance.value(3) != 33 then return 1 end if
  print "[OK] named super arguments"
  return 0
end function
