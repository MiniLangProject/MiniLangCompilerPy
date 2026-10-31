function main(args)
  buffer = "x"
  index = 0
  return asm unsafe x64(in buffer as string, in index as int) returns int
    movzx result, byte [buffer.data + index]
  end asm
end function
