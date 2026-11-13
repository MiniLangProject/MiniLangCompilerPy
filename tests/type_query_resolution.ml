/// Type-query folding must share the builtin's lexical and package lookup.
import "type_query_resolution_lib.ml" as imported
namespace Outer
  namespace Inner
    struct Box
      value
    end struct
    enum State are
      Ready
    end enum
  end namespace
  function check()
    if typeof(Inner.Box) != "struct" then return false end if
    if typeof(Inner.State) != "enum" then return false end if
    if typeof(Inner.State.Ready) != "enum" then return false end if
    return true
  end function
end namespace
namespace Imported
  struct Box
    value
  end struct
end namespace
struct Object
  Box
  Nested
end struct
struct Box
  value
end struct
enum State are
  Ready
end enum
struct EnumValue
  Ready
end struct
function shadowEnum(State)
  if typeof(State.Ready) != "int" or typeName(State.Ready) != "int" then return false end if
  return State.Ready == 11
end function
function shadow(Imported, imported, Box)
  if typeof(Imported.Box) != "int" or typeName(Imported.Box) != "int" then return 1 end if
  if typeof(imported.Nested.Box) != "int" or typeName(imported.Nested.Box) != "int" then return 2 end if
  if typeof(Box) != "int" or typeName(Box) != "int" then return 3 end if
  if not ("int" == typeof(Imported.Box)) or "struct" == typeof(Imported.Box) then return 4 end if
  return 0
end function
function builtinShadow(value, typeof)
  // Builtins are special forms even when a parameter shares their spelling.
  return typeof(value) == "int"
end function
function main(args)
  if not Outer.check() or not imported.check() then return 1 end if
  if typeof(imported.Nested.Box) != "struct" or typeof(imported.Nested.State.Ready) != "enum" then return 2 end if
  if typeName(imported.Nested.State) != typeName(imported.Nested.State.Ready) then return 3 end if
  if shadow(Object(7, void), Object(0, Object(8, void)), 9) != 0 then return 4 end if
  if not builtinShadow(1, false) or builtinShadow("x", false) then return 5 end if
  if not shadowEnum(EnumValue(11)) then return 6 end if
  print "[OK] qualified and shadowed type queries"
  return 0
end function
