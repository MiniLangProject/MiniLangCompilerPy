// Method-level global declarations must resolve to the module, not the type.
package regression.method_globals
width = 7
height = 8

struct Canvas
  size
  function resize(w, h)
    global width, height, createdByMethod
    width = w
    height = h
    createdByMethod = w + h
    this.size = w * h
  end function
end struct

function dimensions()
  return [width, height, createdByMethod]
end function
