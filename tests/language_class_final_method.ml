class Parent
  final function value() returns int
    return 1
  end function
end class

class Child extends Parent
  override function value() returns int
    return 2
  end function
end class
