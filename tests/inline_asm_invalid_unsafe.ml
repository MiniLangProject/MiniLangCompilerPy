b = bytes(1)
i = 0
v = 65
asm x64(inout b as bytes, in i as int, in v as int)
  mov byte[b.data + i], v
end asm
