interface Named
  function name() returns string
end interface

interface Described extends Named
  function description() returns string
end interface

interface Ranked
  function rank() returns int
end interface

interface Labeled extends Described, Ranked
  function label() returns string
end interface

class Item implements Labeled
  text as string = "ok"

  function name() returns string
    return this.text
  end function

  function description() returns string
    return "item"
  end function

  function label() returns string
    return this.description() + ":" + this.name()
  end function

  function rank() returns int
    return 1
  end function
end class

function main(args)
  item = Item()
  if not (item is Named) then return 1 end if
  if not (item is Described) then return 2 end if
  if not (item is Labeled) then return 3 end if
  if item.label() != "item:ok" then return 4 end if
  if not (item is Ranked) or item.rank() != 1 then return 5 end if
  print "[OK] interface inheritance"
  return 0
end function
