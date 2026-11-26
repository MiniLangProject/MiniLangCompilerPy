package regression.struct_identity.typed

struct Record
  left
  right

  /// Resolve the returned type and constructor in the method's package.
  function copy() returns Record
    return Record(this.left, this.right)
  end function
end struct

/// The annotation must keep its declaration context when used by a caller.
function make() returns Record
  return Record(11, 22)
end function

/// Both inline argument facts and the return fact refer to this package.
function inline identity(value as Record) returns Record
  return value
end function

/// Inlined field reads must use the callee's parameter type layout.
function inline rightOf(value as Record) returns int
  return value.right
end function
