import "modules/defaults.ml" as defaults

struct Record
  left
  right
  extra
end struct

function rootDefault(value = Record(81, 91, 101))
  return value
end function

function callerLocals()
  Record = 17
  defaultRecord = 18
  default_model = 19
  value = defaults.withDefault()
  helper = defaults.withHelper()
  aliased = defaults.withAlias()
  holder = defaults.Holder()
  if typeName(value) != "regression.struct_identity.defaults.Record" then return 11 end if
  if value.left != 11 or value.right != 22 then return 12 end if
  if helper.left != 111 or helper.right != 121 then return 13 end if
  if typeName(aliased) != "regression.struct_identity.model.Record" then return 14 end if
  if aliased.left != 131 or aliased.right != 141 then return 15 end if
  if holder.value.left != 31 or holder.value.right != 41 then return 16 end if
  if Record != 17 or defaultRecord != 18 or default_model != 19 then return 17 end if
  return 0
end function

function callerParameters(Record, defaultRecord, default_model)
  value = defaults.withDefault()
  helper = defaults.withHelper()
  aliased = defaults.withAlias()
  if typeName(value) != "regression.struct_identity.defaults.Record" then return 21 end if
  if value.left != 11 or value.right != 22 then return 22 end if
  if helper.left != 111 or helper.right != 121 then return 23 end if
  if typeName(aliased) != "regression.struct_identity.model.Record" then return 24 end if
  if aliased.left != 131 or aliased.right != 141 then return 25 end if
  if Record != 27 or defaultRecord != 28 or default_model != 29 then return 26 end if
  return 0
end function

function main(args)
  value = defaults.withDefault()
  if typeName(value) != "regression.struct_identity.defaults.Record" then return 1 end if
  if value.left != 11 or value.right != 22 then return 2 end if
  holder = defaults.Holder()
  if typeName(holder.value) != "regression.struct_identity.defaults.Record" then return 3 end if
  if holder.value.left != 31 or holder.value.right != 41 then return 4 end if
  // Explicit arguments still belong to the caller and must not be rebound.
  entry = Record(51, 61, 71)
  explicit = defaults.withDefault(entry)
  if typeName(explicit) != "Record" or explicit.extra != 71 then return 5 end if
  root = defaults.callRootDefault()
  if typeName(root) != "Record" then return 6 end if
  if root.left != 81 or root.right != 91 or root.extra != 101 then return 7 end if
  status = callerLocals()
  if status != 0 then return status end if
  status = callerParameters(27, 28, 29)
  if status != 0 then return status end if
  print "[OK] struct namespace default declaration context"
  return 0
end function
