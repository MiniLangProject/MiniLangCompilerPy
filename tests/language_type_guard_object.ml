// Object-pipeline regression: annotated assignments must retain runtime guards.

struct TypedBox
  value as string
end struct

function invalidBox()
  return TypedBox(value = 9)
end function

function main(args)
  count as int = 1
  count = 2
  box as TypedBox? = void
  box = TypedBox(value = "ok")
  if count != 2 or box?.value != "ok" then return 1 end if
  invalid = try(invalidBox())
  if typeof(invalid) != "error" or invalid.code != 1308 then return 2 end if
  print "[OK] typed struct field guards"
  return 0
end function
