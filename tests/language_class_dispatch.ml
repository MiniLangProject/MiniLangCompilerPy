class A
  function kind() returns int
    return 1
  end function
end class

class B
  function kind() returns int
    return 2
  end function
end class

class C
  function kind() returns int
    return 3
  end function
end class

class D
  function kind() returns int
    return 4
  end function
end class

class E
  function kind() returns int
    return 5
  end function
end class

class F
  function kind() returns int
    return 6
  end function
end class

class G
  function kind() returns int
    return 7
  end function
end class

function check(value, expected as int) returns bool
  return value.kind() == expected
end function

function main(args)
  if not check(A(), 1) then return 1 end if
  if not check(B(), 2) then return 2 end if
  if not check(C(), 3) then return 3 end if
  if not check(D(), 4) then return 4 end if
  if not check(E(), 5) then return 5 end if
  if not check(F(), 6) then return 6 end if
  if not check(G(), 7) then return 7 end if
  if not check(A(), 1) then return 8 end if
  if not check(G(), 7) then return 9 end if
  print "[OK] polymorphic class dispatch"
  return 0
end function
