class Parent
  private secret as int = 4
end class

class Child extends Parent
  function reveal() returns int
    return this.secret
  end function
end class
