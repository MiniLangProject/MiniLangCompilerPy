function main(args)
  buffer = bytes(1)
  index = 0
  return asm x64(in buffer as bytes, in index as int) returns int
    movzx result, byte [buffer.data + index]
  end asm
end function
