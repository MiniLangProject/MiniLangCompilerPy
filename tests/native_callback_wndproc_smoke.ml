extern function CallWindowProcW(prev as ptr, hwnd as ptr, msg as u32, wParam as ptr, lParam as ptr) from "user32.dll" symbol "CallWindowProcW" returns ptr

function ok(cond, label)
  if cond then
    print label + " [OK]"
  else
    print label + " [FAIL]"
  end if
end function

function smokeWndProc(hwnd, msg, wParam, lParam)
  if hwnd != 0 then return 11 end if
  if wParam != 44 then return 12 end if
  if lParam != 55 then return 13 end if
  return msg + 7
end function

function main(args)
  print "=== NATIVE CALLBACK WNDPROC ==="
  cb = nativeCallback(smokeWndProc, "wndproc")
  ok(typeof(cb) == "int", "nativeCallback returns int")
  ok(cb != 0, "nativeCallback non-null")
  r = CallWindowProcW(cb, 0, 1234, 44, 55)
  ok(r == 1241, "nativeCallback wndproc result")
  print "=== DONE ==="
end function
