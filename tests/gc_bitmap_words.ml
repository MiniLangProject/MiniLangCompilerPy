/// Exercise every bitmap bit/word/page boundary, aliases, cycles and reuse.
struct BitmapNode
  value,
  child,
end struct

function main(args)
  roots = array(20000, void)
  for cycle = 0 to 3
    for i = 0 to 19999
      payload = bytes(1 + i % 79, i % 251)
      node = BitmapNode(i, [payload, void])
      node.child[1] = node
      roots[i] = [node, node]
    end for
    gc_collect()
    for i = 0 to 19999
      node = roots[i][0]
      if node != roots[i][1] or node.child[1] != node then return 1 end if
      if node.value != i or len(node.child[0]) != 1 + i % 79 then return 2 end if
      if node.child[0][i % 79] != i % 251 then return 3 end if
      if i % 2 == 0 then roots[i] = void end if
    end for
    gc_collect()
    i = 1
    while i < 20000
      if roots[i][0].value != i then return 4 end if
      roots[i] = void
      i = i + 2
    end while
    gc_collect()
  end for
  print "GC BITMAP WORDS [OK]"
  return 0
end function
