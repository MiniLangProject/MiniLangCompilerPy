// Imported type checks must preserve package aliases and all dotted segments.
package qualified_type_lib

struct Point
  x
  y
end struct

namespace nested
  struct Box
    value
  end struct
end namespace
