// Keep a Thread reference without creating an OS thread. Whole-program
// thread gating must preserve polling in both ordinary nested loop forms.
function worker() return 0 end function
function threadFactory() return Thread(worker) end function

function threadedNested(n as int, x as float)
  outer as int = 0
  while outer < 2
    inner as int = 0
    while inner < n and x <= 4.0
      x = x * 0.5 + 0.125
      inner = inner + 1
    end while
    outer = outer + 1
  end while
  return [x, outer]
end function

function main(args)
  factory = threadFactory
  result = threadedNested(2, 0.125)
  if result[0] != 0.2421875 or typeof(result[0]) != "float" then return 1 end if
  if result[1] != 2 then return 2 end if
  print "NUMERIC FLOAT NESTED THREADS [OK]"
  return 0
end function
