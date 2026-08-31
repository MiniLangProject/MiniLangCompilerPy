interface Named
  function name() returns string
end interface

struct Broken implements Named
  value as string
end struct

function main(args)
  return 0
end function
