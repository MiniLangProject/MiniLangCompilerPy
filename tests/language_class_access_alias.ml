class Base
  private secret as int = 2
  protected value as int = 3

  function reveal(other as Base) returns int
    alias = this
    return alias.secret + other.secret
  end function
end class

class Child extends Base
  function valueFrom(other as Base) returns int
    alias = this
    return alias.value + other.value
  end function
end class

function main(args)
  first = Base()
  second = Child()
  if first.reveal(first) != 4 then return 1 end if
  if second.valueFrom(first) != 6 then return 2 end if
  print "[OK] lexical class access through aliases"
  return 0
end function
