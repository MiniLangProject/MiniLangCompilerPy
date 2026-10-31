function countBits(value as int) returns int
  return asm x64(in value as int) returns int
    popcnt result, value
  end asm
end function

function storeDword(buffer as bytes) returns void
  index = 0
  value = 0x12345678
  asm unsafe x64(inout buffer as bytes, in index as int, in value as int)
    mov dword [buffer.data + index], value
  end asm
end function

function readDword(buffer as bytes) returns int
  index = 0
  return asm unsafe x64(in buffer as bytes, in index as int) returns int
    mov result, dword [buffer.data + index]
  end asm
end function

function branchResult(flag as int) returns int
  return asm x64(in flag as int) returns int
    cmp flag, 0
    je zero
    mov result, 7
    jmp done
    label zero
    mov result, 9
    label done
  end asm
end function

function zeroFlag(value as int) returns bool
  return asm x64(in value as int, scratch saved as bool) returns bool
    test value, value
    setz saved
    mov result, saved
  end asm
end function

function rotateMultiply(value as int) returns int
  return asm x64(in value as int) returns int
    mov result, value
    rol result, 8
    ror result, 8
    imul result, 3
  end asm
end function

function addFloats(a as float, b as float) returns float
  return asm x64(in a as float, in b as float, scratch tmp as float) returns float
    movsd tmp, a
    addsd tmp, b
    movsd result, tmp
  end asm
end function

function sumBytes(buffer as bytes) returns int
  length = len(buffer)
  return asm unsafe x64(in buffer as bytes, in length as int, scratch index as int, scratch current as int) returns int
    mov result, 0
    mov index, 0
    label scan
    cmp index, length
    jge done
    movzx current, byte [buffer.data + index]
    add result, current
    add index, 1
    jmp scan
    label done
  end asm
end function

function sumTo(n as int) returns int
  return asm x64(in n as int, scratch i as int) returns int
    mov result, 0
    mov i, 0
    label scan
    cmp i, n
    jge done
    add result, i
    add i, 1
    jmp scan
    label done
  end asm
end function

function pick(flag as int, a as int, b as int) returns int
  return asm x64(in flag as int, in a as int, in b as int) returns int
    mov result, a
    cmp flag, 0
    je done
    mov result, b
    label done
  end asm
end function

function mask(x as int) returns int
  return asm x64(in x as int) returns int
    mov result, x
    and result, 15
    or result, 16
  end asm
end function

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
  if countBits(0) != 0 or countBits(0xF0F0) != 8 or countBits(-1) != 64 then return 18 end if
  wide = bytes(4, 0)
  storeDword(wide)
  if readDword(wide) != 0x12345678 or wide[0] != 0x78 or wide[3] != 0x12 then return 17 end if
  if branchResult(0) != 9 or branchResult(1) != 7 then return 13 end if
  if zeroFlag(0) != true or zeroFlag(1) != false then return 14 end if
  if rotateMultiply(21) != 63 then return 15 end if
  if addFloats(1.5, 2.5) != 4.0 then return 16 end if
  data = bytes(4, 0)
  data[0] = 1
  data[1] = 2
  data[2] = 3
  data[3] = 4
  if sumBytes(data) != 10 then return 12 end if
  if sumTo(10) != 45 or sumTo(0) != 0 then return 10 end if
  if pick(0, 5, 7) != 5 or pick(1, 5, 7) != 7 then return 11 end if
  if mask(35) != 19 then return 7 end if
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
