function main(args)
  flag = 0
  return asm x64(in flag as int) returns int
    cmp flag, 0
    je done
    mov result, 1
    label done
  end asm
end function
