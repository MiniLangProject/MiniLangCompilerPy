struct Box
  value as string

  function get() returns string
    return this.value
  end function
end struct

function main(args)
  maybe as Box? = void
  if (maybe?.value ?? "fallback") != "fallback" then return 1 end if
  maybe = Box(value = "ok")
  if maybe?.get() != "ok" then return 2 end if
  return 0
end function
