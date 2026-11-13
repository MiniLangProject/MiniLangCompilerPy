/// Imported nominal types exercise package prefixes and alias resolution.
package type_query_resolution_lib
namespace Nested
  struct Box
    value
  end struct
  enum State are
    Ready
  end enum
end namespace
function check()
  if typeof(Nested.Box) != "struct" then return false end if
  if typeof(Nested.State) != "enum" then return false end if
  if typeof(Nested.State.Ready) != "enum" then return false end if
  return true
end function
