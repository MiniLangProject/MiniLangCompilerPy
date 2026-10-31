a = "text"
b = bytes(1)
x = asm x64(in a as string, in b as bytes) returns string
  mov result, b
end asm
