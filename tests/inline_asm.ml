function one() returns int
  return asm x64() returns int
    mov result, 1
  end asm
end function

function inline trailingZeros(x as int) returns int
  if x == 0 then return -1 end if
  return asm x64(in x as int) returns int
    bsf result, x
  end asm
end function

function inline choose(flag as bool, a as string, b as string) returns string
  return asm x64(in flag as bool, in a as string, in b as string) returns string
    mov result, a
    test flag, flag
    cmovnz result, b
  end asm
end function

function inline twice(x as float) returns float
  return asm x64(in x as float) returns float
    movsd result, x
    addsd result, x
  end asm
end function

function setByte(buffer as bytes, index as int, value as int) returns void
  asm unsafe x64(inout buffer as bytes, in index as int, in value as int) returns void
    mov byte [buffer.data + index], value
  end asm
end function

function main(args)
  if one() != 1 then return 6 end if
  if trailingZeros(8) != 3 then return 1 end if
  if choose(true, "left", "right") != "right" then return 2 end if
  if choose(false, "left", "right") != "left" then return 3 end if
  if twice(1.25) != 2.5 then return 4 end if
  b = bytes(3)
  setByte(b, 1, 65)
  if b[1] != 65 then return 5 end if
  print "[OK] inline asm core"
  return 0
end function
