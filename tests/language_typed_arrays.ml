function writeAt(target, index, value)
  target[index] = value
end function

function readAt(target, index)
  return target[index]
end function

function sum(values as array<int>) returns int
  total = 0
  for each value in values
    total += value
  end for
  return total
end function

function asArray(source) returns array<int>
  return array<int>(source)
end function

function isContractError(result)
  return typeof(result) == "error" and result.code == 1308
end function

function main(args)
  source = [2, 3]
  var values as array<int> = asArray(source)
  if not (values is array<int>) or values is array<string> then return 1 end if
  if typeof(values) != "array" or len(values) != 2 or sum(values) != 5 then return 2 end if
  writeAt(values, 0, 7)
  if not isContractError(try(writeAt(values, 1, "bad"))) then return 3 end if
  if values[0] != 7 or values[1] != 3 or source[0] != 2 then return 4 end if
  if not isContractError(try(asArray([1, "bad"]))) then return 5 end if
  if not isContractError(try(sum(source))) then return 6 end if
  copyArray(values, 0, array<int>([9, 8]), 0, 2)
  copyArray(values, 0, ["bad"], 0, 1)
  if values != [9, 8] then return 7 end if
  concat = values + [6]
  if len(concat) != 3 or concat[2] != 6 then return 8 end if
  labels = array<string?>([void, "text"])
  writeAt(labels, 0, "keep")
  if not isContractError(try(writeAt(labels, 1, 3))) then return 9 end if
  gc_collect()
  if labels[0] != "keep" or labels[1] != "text" then return 10 end if
  flags = array<bool>([true, false])
  decimals = array<float>([0.5, 0.12345678901234567])
  buffers = array<bytes>([bytes(4)])
  if flags[1] != false or decimals[1] != 0.12345678901234567 or len(buffers[0]) != 4 then return 11 end if
  tooFar = try(writeAt(values, 4294967296, 1))
  beforeStart = try(readAt(values, -4294967296))
  if tooFar.code != 1300 or beforeStart.code != 1300 or values[0] != 9 then return 12 end if
  var assumed as array<int> = array<int>([0])
  assumed[0] = 8
  if assumed[0] != 8 then return 13 end if
  print "TYPED ARRAYS [OK]"
  return 0
end function
