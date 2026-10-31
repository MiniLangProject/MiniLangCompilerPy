namespace imported_class_lib

interface Named
  function label() returns string
end interface

class Base implements Named
  value as string

  function label() returns string
    return this.value
  end function
end class

end namespace
