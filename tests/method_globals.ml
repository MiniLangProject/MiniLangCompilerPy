import "method_globals_lib.ml" as graphics

rootValue = 3
struct RootWriter
  function write(value)
    global rootValue, createdAtRoot
    rootValue = value
    createdAtRoot = value + 1
  end function
end struct

function main(args)
  canvas = graphics.Canvas(0)
  canvas.resize(30, 40)
  sizes = graphics.dimensions()
  if sizes[0] != 30 or sizes[1] != 40 or sizes[2] != 70 or canvas.size != 1200 then return 1 end if
  writer = RootWriter()
  writer.write(42)
  if rootValue != 42 or createdAtRoot != 43 then return 2 end if
  print("[OK] method globals")
  return 0
end function
