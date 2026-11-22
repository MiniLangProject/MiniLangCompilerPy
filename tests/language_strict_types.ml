function consume(value as int) returns int
  return value
end function

function produce() returns string
  return "wrong type"
end function

function main(args)
  result = try(consume(produce()))
  if typeof(result) != "error" or result.code != 1308 then return 1 end if
  print "STRICT TYPES RUNTIME FALLBACK [OK]"
  return 0
end function
