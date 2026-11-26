// Width, depth, cycles and GC ownership regressions for structural equality.
checks=0 failures=0
function check(value,label)
  global checks,failures
  checks=checks+1
  if not value then failures=failures+1 print "[FAIL] "+label end if
end function
function equal(left,right) return left==right end function
function chain(depth,leaf)
  result=leaf
  for i=0 to depth-1
    result=[result,i]
  end for
  return result
end function
function deepest(value,depth)
  result=value
  for i=0 to depth-1
    result=result[0]
  end for
  return result
end function
function compareTemporary(depth)
  return equal(chain(depth,[71,"retained"]),chain(depth,[71,"retained"]))
end function
struct IdentityOnly
  value
end struct
function main(args)
  gc_set_limit(0)
  for each size in [0,1,31,32,33,255,256,257,1024,65536]
    left=array(size,31) right=array(size,31)
    requests=gc_stat(22)
    matched=equal(left,right)
    requested=gc_stat(22)-requests
    check(matched,"flat array width "+size)
    check(requested==0,"flat arrays allocate no workspace "+size)
    if size>0 then
      right[size-1]=32
      check(not equal(left,right) and not equal(right,left),"last-element mismatch "+size)
      right[size-1]=31 right[0]=30
      check(left!=right,"first-element mismatch "+size)
    end if
  end for
  check([1,true,0,false,2.5,"ab"+"cd"]==[true,1,false,0,2.5,"abcd"],"mixed numeric and string leaves")
  check([1,"x"]!=[1,"y"] and [1]!=[1,2],"string and length mismatch")
  identity=IdentityOnly(7)
  check([identity]==[identity] and [identity]!=[IdentityOnly(7)],"non-array object identity")
  child=[17,"shared"]
  check([child,child]==[[17,"shared"],[17,"shared"]],"alias-insensitive value equality")
  check([[child],[child]]==[[[17,"shared"]],[[17,"shared"]]],"nested shared graph")
  typed=array<int>([1,2,3])
  check(typed==[1,2,3] and [1,2,3]==typed,"typed array structural equality")
  for each depth in [31,32,33,63,64,65,257,1024,4096]
    left=chain(depth,[17,"leaf"]) right=chain(depth,[17,"leaf"])
    check(equal(left,right),"deep equal "+depth)
    leaf=deepest(right,depth) leaf[1]="changed"
    check(not equal(left,right) and not equal(right,left),"deep mismatch "+depth)
  end for

  // Memo growth also occurs in shallow trees with many distinct array pairs.
  left=array(4096,void) right=array(4096,void)
  for i=0 to 4095
    left[i]=[i,"node"] right[i]=[i,"node"]
  end for
  check(equal(left,right) and equal(right,left),"wide nested graph and hash growth")
  right[4095][0]=-1
  check(not equal(left,right) and not equal(right,left),"late nested mismatch after hash growth")
  child=[17,"shared"]
  left=array(1024,child) right=array(1024,void)
  for i=0 to 1023
    right[i]=[17,"shared"]
  end for
  check(equal(left,right) and equal(right,left),"asymmetric sharing across memo growth")
  right[1023][0]=18
  check(not equal(left,right) and not equal(right,left),"memo checks both pointers for shared left nodes")
  left=[17] right=[17] rightLeaf=right
  for i=0 to 29
    left=[left,left] right=[right,right]
  end for
  check(equal(left,right),"shared diamond DAG avoids repeated exponential work")
  rightLeaf[0]=18
  check(not equal(left,right) and not equal(right,left),"shared DAG leaf mismatch")

  // Cycles compare by their unfolded values, not graph-isomorphism or aliasing.
  left=[void,7] right=[void,7]
  left[0]=left right[0]=right
  check(equal(left,right) and equal(right,left),"separate self cycles")
  check(equal(left,left),"same cyclic object identity")
  right[1]=8
  check(not equal(left,right) and not equal(right,left),"mismatch after self cycle")
  right[1]=7
  a=[void,7] b=[a,7] a[0]=b
  check(equal(left,a) and equal(a,left),"one-node and two-node unfolded cycles")
  b[1]=8
  check(not equal(left,a) and not equal(a,left),"late mismatch in two-node cycle")
  x=[void,5] y=[x,5] x[0]=y
  check(equal(x,y) and equal(y,x),"reversed ordered pairs in one graph")
  y[1]=6
  check(not equal(x,y) and not equal(y,x),"reversed pair late mismatch")
  left=chain(128,void) right=chain(128,void)
  deepest(left,127)[0]=left deepest(right,127)[0]=right
  check(equal(left,right),"cycle across grown continuation workspace")
  deepest(right,63)[1]=-1
  check(not equal(left,right),"deep cyclic mismatch after growth")

  // Allocation-triggered collection must retain original graphs, pending
  // children, previous workspace and unrelated caller expression values.
  left=chain(1024,[71,"retained"]) right=chain(1024,[71,"retained"])
  retained=[bytes(4096,93),"caller root"]
  gc_collect()
  before=gc_stat(0)
  gc_set_limit(1)
  check(equal(left,right),"workspace growth during forced GC")
  check(gc_stat(0)>before,"comparison exercised collection")
  check(deepest(left,1024)[1]=="retained" and retained[0][4095]==93,"graph and caller roots survive")
  check(compareTemporary(512),"temporary operand roots survive growth")
  gc_set_limit(0)
  gc_collect()
  live=gc_stat(1)
  for i=0 to 63
    if not equal(left,right) then return 81 end if
    deepest(right,1024)[0]=72
    if equal(left,right) then return 82 end if
    deepest(right,1024)[0]=71
  end for
  gc_collect()
  check(gc_stat(1)<=live+65536,"successful and failed spill workspaces are reclaimable")
  print "ARRAY EQUALITY checks="+checks+" failures="+failures
  if failures==0 then print "ARRAY EQUALITY [OK]" end if
  return failures
end function
