package regression.struct_identity.defaults

import "model.ml" as default_model

struct Record
  left
  right
end struct

struct Holder
  value = Record(31, 41)
end struct

/// A default expression belongs to this declaration, even when inserted at a call.
function withDefault(value = Record(11, 22))
  return value
end function

function defaultRecord()
  return Record(111, 121)
end function

function withHelper(value = defaultRecord())
  return value
end function

function withAlias(value = default_model.Record(131, 141))
  return value
end function

/// Root declarations also retain their context when called from a package.
function callRootDefault()
  return rootDefault()
end function
