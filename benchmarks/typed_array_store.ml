// Both modes allocate the same typed array. The fixed binding gives the
// compiler enough information to prove the literal element write safe.
#option PROVEN: bool = false

function run(count)
#if PROVEN
  var cells as array<int> = array<int>(array(256, 0))
#else
  cells = array<int>(array(256, 0))
#endif
  for i = 0 to count - 1
    cells[i & 255] = 7
  end for
  return cells[0] + cells[255]
end function

print run(20000000)
