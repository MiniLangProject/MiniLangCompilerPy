// `out` currently annotates native ABI metadata but still counts toward call
// arity. MulDiv has three scalar parameters, so it is a stable runtime probe.
extern function MulDiv(a as int, b as int, out c as int) from "kernel32.dll" returns int

function main(args)
  if MulDiv(6, 7, 3) != 14 then return 1 end if
  f = MulDiv
  if f(6, 7, 3) != 14 then return 1 end if
  print "extern out ABI [OK]"
  return 0
end function
