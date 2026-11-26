package regression.struct_identity.beta

// A second imported package owns a distinct, differently laid-out Record.
struct Record
  right
  left
end struct

function make()
  return Record(21, 32)
end function

function constructor()
  return Record
end function
