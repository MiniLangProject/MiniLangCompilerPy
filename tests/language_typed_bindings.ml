// A dynamic value must be checked before replacement of an existing slot.
function dynamicValue(value)
  return value
end function

var sharedValue as int = 4
blockOK = false
if sharedValue == 4 then
  var scoped as int = 1
  scoped += sharedValue
  blockOK = scoped == 5
end if

namespace typeFixture
  var shared as string? = void
end namespace

function writeShared(value)
  global sharedValue
  sharedValue = value
end function

function writeQualified(value)
  typeFixture.shared = value
end function

function updateParameter(value as int, replacement) returns int
  value = replacement
  return value
end function

function inline bypassable(value as int, replacement) returns int
  var localValue as int = value
  localValue = replacement
  return localValue
end function

function localLoop(replacement)
  var value as int = 0
  for i = 1 to 5
    value += i
  end for
  if value != 15 then return -1 end if
  for each value in ["shadow"]
    if value != "shadow" then return -2 end if
  end for
  value = replacement
  return value
end function

function closureProbe()
  var value as int = 12
  function intermediate()
    function write(replacement)
      // Read before the first write to target the outer binding.
      if value == 0 then return false end if
      value = replacement
      return true
    end function
    return write
  end function
  write = intermediate()
  if not write(15) then return -1 end if
  invalid = try(write("wrong"))
  if not isContractError(invalid) then return -2 end if
  return value
end function

lazy iterator function values(replacement) returns int
  var value as int = 2
  yield value
  value = replacement
  yield value
end function

function isContractError(result)
  return typeof(result) == "error" and result.code == 1308
end function

function storeError(value)
  var caught as error? = void
  caught = try(value())
  return caught.code
end function

function raiseError()
  return error(42, "caught payload")
end function

function copyText(left, right)
  var source as string = left
  var destination as string = right
  if len(source) > 0 then
    destination = source
  end if
  return destination
end function

function main(args)
  if updateParameter(1, 3) != 3 then return 1 end if
  if not isContractError(try(updateParameter("wrong", 1))) then return 2 end if
  if bypassable(1, 3) != 3 then return 3 end if
  if not isContractError(try(bypassable(1, "wrong"))) then return 4 end if
  if localLoop(99) != 99 then return 5 end if
  if not isContractError(try(localLoop("wrong"))) then return 6 end if
  if closureProbe() != 15 then return 7 end if
  writeShared(8)
  if not isContractError(try(writeShared("wrong"))) or sharedValue != 8 then return 8 end if
  writeQualified("ok")
  if not isContractError(try(writeQualified(42))) or typeFixture.shared != "ok" then return 9 end if
  writeQualified(void)
  if typeFixture.shared != void then return 10 end if
  nextValue = values("wrong")
  if nextValue() != 2 then return 11 end if
  if not isContractError(try(nextValue())) then return 12 end if
  if dynamicValue(9) != 9 then return 13 end if
  if not blockOK then return 14 end if
  if storeError(raiseError) != 42 then return 15 end if
  if not isContractError(try(storeError(function() => 1))) then return 16 end if
  if copyText("new", "old") != "new" or copyText("", "old") != "old" then return 17 end if
  print "TYPED BINDINGS [OK]"
  return 0
end function
