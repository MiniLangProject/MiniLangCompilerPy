struct Shape
  corners as int
end struct

function main(args)
  shape = Shape(4)
  shape.corners = "text"
  return 0
end function
