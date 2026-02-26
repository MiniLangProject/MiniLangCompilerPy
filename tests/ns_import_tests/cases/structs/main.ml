import "../../testlib.ml"
import "geom.ml"

print "=== NS STRUCTS ==="
p = geom.Point(3, 4)
assertEq(p.x, 3, "geom.Point.x")
assertEq(p.y, 4, "geom.Point.y")
p.x = 9
assertEq(p.x, 9, "geom.Point set x")
print "=== DONE ==="
