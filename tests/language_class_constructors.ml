class Person
  private secret as string = ""
  public name as string = ""

  function init(name as string, secret as string = "default")
    this.name = name
    this.secret = secret
  end function

  function reveal() returns string
    return this.name + ":" + this.secret
  end function
end class

class Box
  private code as int = 9
  public label as string = "empty"

  function codeValue() returns int
    return this.code
  end function
end class

function main(args)
  first = Person("Ada")
  if first.reveal() != "Ada:default" then return 1 end if
  second = Person(secret = "hidden", name = "Bea")
  if second.reveal() != "Bea:hidden" then return 2 end if
  makePerson = Person
  third = makePerson("Cal")
  if third.reveal() != "Cal:default" then return 3 end if
  fourth = makePerson("Dee", "explicit")
  if fourth.reveal() != "Dee:explicit" then return 4 end if
  box = Box()
  if box.label != "empty" or box.codeValue() != 9 then return 5 end if
  makeBox = Box
  other = makeBox("full")
  if other.label != "full" or other.codeValue() != 9 then return 6 end if
  print "[OK] class constructor parity and private fields"
  return 0
end function
