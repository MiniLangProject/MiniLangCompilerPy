import "modules/alpha.ml" as alpha
import "modules/beta.ml" as beta

struct Record
  right
  left

  static function make(right, left)
    return Record(right, left)
  end function
end struct

namespace entry_scope
  struct Record
    right
    left
  end struct
end namespace

failures = 0

/// Check concrete identity as well as values, including cases with equal layouts.
function expectRecord(value, expectedType, left, right, label)
  global failures
  if typeName(value) != expectedType or value.left != left or value.right != right then
    failures += 1
    print "[FAIL] " + label
    print typeName(value)
    print [value.left, value.right]
  end if
end function

/// A user function can shadow a package constructor through a lexical parameter.
function entryFactory(left, right)
  return entry_scope.Record(right, left)
end function

function main(args)
  first = alpha.make()
  expectRecord(first, "regression.struct_identity.alpha.Record", 11, 22, "package alpha")
  expectRecord(beta.make(), "regression.struct_identity.beta.Record", 32, 21, "package beta")
  expectRecord(alpha.makeNamed(), "regression.struct_identity.alpha.Record", 13, 24, "named fields")
  expectRecord(alpha.makeStatic(), "regression.struct_identity.alpha.Record", 71, 81, "package static call")
  expectRecord(first.reverse(), "regression.struct_identity.alpha.Record", 22, 11, "instance method")
  expectRecord(alpha.Record.make(7, 8), "regression.struct_identity.alpha.Record", 7, 8, "aliased static call")
  expectRecord(Record.make(7, 8), "Record", 8, 7, "entry static call")
  expectRecord(Record(5, 6), "Record", 6, 5, "entry constructor")
  expectRecord(alpha.Record(3, 4), "regression.struct_identity.alpha.Record", 3, 4, "aliased constructor")
  expectRecord(regression.struct_identity.beta.Record(5, 6), "regression.struct_identity.beta.Record", 6, 5, "qualified constructor")
  holder = alpha.makeHolder()
  expectRecord(holder.value, "regression.struct_identity.alpha.Record", 31, 41, "default field initializer")
  directHolder = alpha.Holder()
  expectRecord(directHolder.value, "regression.struct_identity.alpha.Record", 31, 41, "caller-side default field initializer")
  constructor = alpha.constructor()
  gc_collect()
  expectRecord(constructor(15, 16), "regression.struct_identity.alpha.Record", 15, 16, "returned constructor value")
  constructors = [alpha.Record, beta.constructor(), Record]
  expectRecord(constructors[0](17, 18), "regression.struct_identity.alpha.Record", 17, 18, "aliased constructor value")
  expectRecord(constructors[1](19, 20), "regression.struct_identity.beta.Record", 20, 19, "second constructor value")
  expectRecord(constructors[2](23, 24), "Record", 24, 23, "entry constructor value")
  expectRecord(alpha.parameterFactory(entryFactory), "entry_scope.Record", 101, 102, "parameter shadows struct")
  expectRecord(alpha.localFactory(entryFactory), "entry_scope.Record", 103, 104, "local shadows struct")
  captured = alpha.capturedFactory(entryFactory)
  expectRecord(captured(105, 106), "entry_scope.Record", 105, 106, "capture shadows struct")
  expectRecord(alpha.qualifiedGlobal(), "entry_scope.Record", 61, 51, "explicit global namespace")
  expectRecord(alpha.child.parentRecord(), "regression.struct_identity.alpha.Record", 95, 96, "parent package fallback")
  expectRecord(alpha.inner.make(), "regression.struct_identity.alpha.inner.Record", 92, 91, "nearest nested namespace")
  expectRecord(alpha.inner.parentRecord(), "regression.struct_identity.alpha.Record", 93, 94, "explicit parent type")
  expectRecord(alpha.inner.makeStatic(), "regression.struct_identity.alpha.inner.Record", 98, 97, "nested static method")
  nested = alpha.inner.make()
  expectRecord(nested.clone(), "regression.struct_identity.alpha.inner.Record", 92, 91, "nested instance method")
  if alpha.leftFromLocalFactory(entryFactory) != 107 then
    print "[FAIL] local constructor shadow inherits hidden type layout"
    return 2
  end if
  if alpha.rightFromParameterFactory(entryFactory) != 110 then
    print "[FAIL] parameter constructor shadow inherits hidden type layout"
    return 3
  end if
  if failures != 0 then return 1 end if
  print "[OK] struct namespace lexical identity"
  return 0
end function
