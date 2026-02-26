import "../../testlib.ml"
import "fubar.ml"

print "=== NS/IMPORT BASIC ==="
assertEq(fubar.a(), 1, "fubar.a()")
assertEq(fubar.b(), 2, "fubar.b()")
print "=== DONE ==="
