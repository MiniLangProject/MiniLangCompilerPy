extern function seven(a as i64, b as i64, c as i64, d as i64, e as i64, f as i64, g as i64) from "libmlc_abi.so" symbol "mlc_seven" returns i64
extern function mixed(a as i64, b as double, c as i64, d as double, e as i64, f as double, g as i64, h as double) from "libmlc_abi.so" symbol "mlc_mixed" returns double
extern function ten(a as double, b as double, c as double, d as double, e as double, f as double, g as double, h as double, i as double, j as double) from "libmlc_abi.so" symbol "mlc_ten_floats" returns double
extern function nativeOut(value as double, out result as double) from "libmlc_abi.so" symbol "mlc_out" returns double

function calls(value)
  for i = 0 to 31
    if seven(1, 2, 3, 4, 5, 6, 7) != 140 then return false end if
    if seven(-1, -2, -3, -4, -5, -6, -7) != -140 then return false end if
    if mixed(1, 2.5, 3, 4.5, 5, 6.5, 7, 8.5) != 38.0 then return false end if
    if ten(1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0) != 385.0 then return false end if
    if nativeOut(42.0) != 42.5 then return false end if
  end for
  return true
end function

function main(args)
  if not calls(0) then return 1 end if
  first = Thread(calls)
  second = Thread(calls)
  if not first.Start(1) or not second.Start(2) then return 2 end if
  gc_collect()
  if not first.Join(10000) or not second.Join(10000) then return 3 end if
  if first.Result() != true or second.Result() != true then return 4 end if
  print "ffi-registers-stack-out-threads=ok"
  return 37
end function
