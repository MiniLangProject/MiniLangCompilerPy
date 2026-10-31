class Parent
  function value(x as int) returns int
    return x
  end function
end class

class Child extends Parent
  override function value(x as string) returns int
    return 0
  end function
end class
