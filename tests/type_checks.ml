/*
   Copyright 2026 Nils Kopal
   Licensed under the Apache License, Version 2.0.
*/

struct TypeProbe
  value
end struct

enum TypeProbeEnum are
  Item
end enum

function identity(value)
  return value
end function

function typeCheckThreadEntry()
  return 99
end function

function main(args)
  // Every public typeof category accepted by `is`, plus the documented aliases.
  if not (1 is int) or not (1 is integer) or (1 is string) then return 1 end if
  if not (1.5 is float) or (1.5 is int) then return 2 end if
  if not (true is bool) or not (false is boolean) then return 3 end if
  if not ("value" is string) or not ("value" is str) then return 4 end if
  if not ([1, 2] is array) or (bytes(2) is array) then return 5 end if
  if not (bytes(2) is bytes) or ("value" is bytes) then return 6 end if
  if not (identity is function) or (1 is function) then return 7 end if

  probe = TypeProbe(42)
  if not (probe is struct) or not (probe is TypeProbe) then return 8 end if
  if not (TypeProbe is struct) or not (TypeProbe is TypeProbe) then return 9 end if
  if probe is TypeProbeEnum or TypeProbe is not TypeProbe then return 10 end if

  enumValue = TypeProbeEnum.Item
  if not (enumValue is enum) or not (enumValue is TypeProbeEnum) then return 11 end if
  if enumValue is TypeProbe or enumValue is not TypeProbeEnum then return 12 end if

  caught = try(error(1650, "type check probe"))
  if not (caught is error) or (caught is struct) then return 13 end if
  if not (void is void) or (void is not void) then return 14 end if
  // `unknown` is the documented fallback name, but no public value currently
  // has that category. It must still parse and compare false.
  if 1 is unknown or void is unknown then return 15 end if

  // Thread is a case-insensitive primitive category for `is`; both the public
  // constructor spelling and the typeof spelling are supported.
  worker = Thread(typeCheckThreadEntry, "type-check-worker")
  if not (worker is Thread) or not (worker is thread) then return 16 end if
  if worker is not Thread or worker is not thread or (probe is Thread) then return 17 end if
  if typeof(worker) != "thread" or typeName(worker) != "thread" then return 18 end if
  if not worker.Start() or not worker.Join(10000) then return 19 end if
  if worker.Result() != 99 or not worker.Close() then return 20 end if

  print "[OK] exhaustive public is-type categories"
  return 0
end function
