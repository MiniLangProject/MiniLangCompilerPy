interface Renderer
  function render(value as int) returns string
end interface

struct BrokenRenderer implements Renderer
  function render(value as string) returns int
    return 1
  end function
end struct

function main(args)
  return 0
end function
