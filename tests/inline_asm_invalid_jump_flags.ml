function main(args)
  return asm x64() returns int
    mov result, 0
    jz done
    label done
  end asm
end function
