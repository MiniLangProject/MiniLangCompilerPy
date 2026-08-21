extern struct POINT
  x as i32
  y as i32
end struct

extern function GetCursorPos(out point as POINT) from "user32.dll" returns bool

point = GetCursorPos()
print point is POINT
print typeof(point.x)
print typeof(point.y)
print "extern struct out [OK]"
