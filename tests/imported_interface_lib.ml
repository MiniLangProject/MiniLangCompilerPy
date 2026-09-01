namespace imported_interface_lib

interface ValueProvider
  function get() returns int
end interface

struct Box implements ValueProvider
  value as int

  function get() returns int
    return this.value
  end function
end struct

end namespace
