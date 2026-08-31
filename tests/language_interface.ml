interface Named
  function name() returns string
end interface

struct Person implements Named
  value as string

  function name() returns string
    return this.value
  end function
end struct

function main(args)
  person = Person(value = "MiniLang")
  if person.name() != "MiniLang" then return 1 end if
  return 0
end function
