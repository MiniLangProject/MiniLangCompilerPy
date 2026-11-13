/// Inlined bodies must retain the same error boundary as physical calls.
effects = 0
bodyReached = 0
synchronized shared = 0
function mark(value)
  global effects
  effects += 1
  return value
end function
function inline sum3(a as int, b as int = 2, c as int = 3) returns int
  return a + b + c
end function
function inline badBody(values)
  global bodyReached
  value = values[99]
  bodyReached += 1
  return value + 1
end function
function inline badReturn() returns int
  return "wrong"
end function
function inline innerCatch(values)
  value = try(badBody(values))
  if typeof(value) == "error" then return value.code end if
  return -1
end function
function inline nested(value)
  return sum3(value) + 1
end function
function inline observe(value)
  return typeof(value)
end function
function writeShared(value)
  global shared
  shared = sum3(value)
  return 0
end function
function worker()
  global shared
  shared = 77
  return 99
end function
function main(args)
  cold = try(sum3("wrong"))
  if typeof(cold) != "error" or cold.code != 1308 then return 1 end if
  if sum3(4) != 9 or sum3(c = 8, a = 1, b = 2) != 11 then return 2 end if
  problem = try(sum3(mark("wrong"), mark(2), mark(3)))
  if typeof(problem) != "error" or problem.code != 1308 or effects != 3 then return 3 end if
  body = try(badBody([1]))
  if typeof(body) != "error" or body.code != 1300 or bodyReached != 0 then return 4 end if
  result = try(badReturn())
  if typeof(result) != "error" or result.code != 1308 then return 5 end if
  nestedError = try(nested("wrong"))
  if typeof(nestedError) != "error" or nestedError.code != 1308 then return 6 end if
  if innerCatch([1]) != 1300 or try(innerCatch([1])) != 1300 then return 7 end if
  if try(observe(error(1720, "argument error value"))) != "error" then return 8 end if
  monitorError = try(writeShared("wrong"))
  if typeof(monitorError) != "error" or monitorError.code != 1308 then return 9 end if
  workerThread = Thread(worker)
  if not workerThread.Start() or not workerThread.Join(5000) then return 10 end if
  if workerThread.Result() != 99 or not workerThread.Close() or shared != 77 then return 11 end if
  if sum3(1) != 6 then return 12 end if
  if sum3(1) != 6 then return 12 end if
  if sum3(1) != 6 then return 12 end if
  if sum3(1) != 6 then return 12 end if
  if sum3(1) != 6 then return 12 end if
  if sum3(1) != 6 then return 12 end if
  if sum3(1) != 6 then return 12 end if
  if sum3(1) != 6 then return 12 end if
  if sum3(1) != 6 then return 12 end if
  if sum3(1) != 6 then return 12 end if
  if sum3(1) != 6 then return 12 end if
  if sum3(1) != 6 then return 12 end if
  if sum3(1) != 6 then return 12 end if
  if sum3(1) != 6 then return 12 end if
  if sum3(1) != 6 then return 12 end if
  if sum3(1) != 6 then return 12 end if
  if sum3(1) != 6 then return 12 end if
  if sum3(1) != 6 then return 12 end if
  if sum3(1) != 6 then return 12 end if
  if sum3(1) != 6 then return 12 end if
  // The repeated direct call sites above exhaust the shared inline byte budget.
  late = try(sum3("wrong"))
  if typeof(late) != "error" or late.code != 1308 then return 13 end if
  print "[OK] inline error boundaries, effects and monitor cleanup"
  return 0
end function
