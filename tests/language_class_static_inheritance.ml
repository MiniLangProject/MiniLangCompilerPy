class Parent
  protected static function answer() returns int
    return 41
  end function
end class

class Child extends Parent
  static function next() returns int
    return Child.answer() + 1
  end function
end class

function main(args)
  if Child.next() != 42 then return 1 end if
  print "[OK] inherited protected static method"
  return 0
end function
