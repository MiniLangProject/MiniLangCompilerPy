asm x64() returns void
end asm

struct Pair
  value as int
end struct

enum Color
  Red
  Blue
end enum

function passPair(x as Pair) returns Pair
  return asm x64(in x as Pair) returns Pair
    mov result, x
  end asm
end function

function passColor(x as Color) returns Color
  return asm x64(in x as Color) returns Color
    mov result, x
  end asm
end function

function passArray(x as array) returns array
  return asm x64(in x as array) returns array
    mov result, x
  end asm
end function

function passBytes(x as bytes) returns bytes
  return asm x64(in x as bytes) returns bytes
    mov result, x
  end asm
end function

function passFunction(x as function) returns function
  return asm x64(in x as function) returns function
    mov result, x
  end asm
end function

function passOptional(x as string?) returns string?
  return asm x64(in x as string?) returns string?
    mov result, x
  end asm
end function

function passUnknown(x)
  return asm x64(in x as unknown) returns unknown
    mov result, x
  end asm
end function

function passThread(x as thread) returns thread
  return asm x64(in x as thread) returns thread
    mov result, x
  end asm
end function

function passError(x as error) returns error
  return asm x64(in x as error) returns error
    mov result, x
  end asm
end function

function bump(x as int) returns int
  asm x64(inout x as int) returns void
    add x, 1
  end asm
  return x
end function

function passVoid(x as void) returns void
  asm x64(in x as void) returns void
  end asm
end function

function sample()
  return 7
end function

function closureCapture()
  captured = 19
  function inner() returns int
    return asm x64(in captured as int) returns int
      mov result, captured
    end asm
  end function
  return inner()
end function

function main(args)
  p = Pair(42)
  if passPair(p).value != 42 then return 1 end if
  if passColor(Color.Blue) != Color.Blue then return 2 end if
  arr = [1, 2]
  if passArray(arr)[1] != 2 then return 3 end if
  buf = bytes(2)
  if len(passBytes(buf)) != 2 then return 4 end if
  fn = passFunction(sample)
  if fn() != 7 then return 5 end if
  if passOptional(void) != void then return 6 end if
  if passUnknown("text") != "text" then return 7 end if
  if closureCapture() != 19 then return 8 end if
  th = Thread(sample)
  if typeof(passThread(th)) != "thread" then return 9 end if
  e = try(error(12, "sample"))
  if typeof(try(passError(e))) != "error" then return 10 end if
  if bump(41) != 42 then return 11 end if
  passVoid(void)
  print "[OK] inline asm types"
  return 0
end function
