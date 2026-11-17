// A closed-program Thread reference must keep cooperative polls and ordinary
// loop lowering. The constructor is deliberately never invoked: this fixture
// checks code generation on every target, not OS thread runtime support.
function worker()
  return 0
end function

function threadFactory()
  return Thread(worker)
end function

function threadedLoop(n as int, x as float)
  i as int = 0
  while i < n
    x = x * 0.5 + 0.125
    i = i + 1
  end while
  return [x, i]
end function

function main(args)
  factory = threadFactory
  result = threadedLoop(2, 0.125)
  if result[0] != 0.21875 or typeof(result[0]) != "float" then return 1 end if
  if result[1] != 2 then return 2 end if
  print "NUMERIC FLOAT LOOP THREADS [OK]"
  return 0
end function
