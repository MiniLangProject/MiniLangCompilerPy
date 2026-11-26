package regression.struct_identity.model

struct Record
  left
  right
end struct

/// Construct the Record belonging to this package, not the entry module.
function make()
  return Record(11, 22)
end function
