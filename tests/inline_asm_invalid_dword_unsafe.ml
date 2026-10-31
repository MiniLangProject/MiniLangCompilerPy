function main(args)
  data = bytes(4, 0)
  offset = 0
  return asm x64(in data as bytes, in offset as int) returns int
    mov result, dword [data.data + offset]
  end asm
end function
