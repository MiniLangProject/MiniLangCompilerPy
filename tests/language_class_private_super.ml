class Parent
  private function value() returns int
    return 1
  end function
end class

class Child extends Parent
  function read() returns int
    return super.value()
  end function
end class
