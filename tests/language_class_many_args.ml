class Five
  a as int = 0
  b as int = 0
  c as int = 0
  d as int = 0
  e as int = 0
end class

function main(args)
  direct = Five(1, 2, 3, 4, 5)
  if direct.a != 1 or direct.e != 5 then return 1 end if
  constructor = Five
  indirect = constructor(6, 7, 8, 9, 10)
  if indirect.d != 9 or indirect.e != 10 then return 2 end if
  return 0
end function
