import "../../testlib.ml"
import "mods/fubar.ml"

print "=== RELATIVE IMPORT ==="
assertEq(fubar.a(), 11, "fubar.a() via mods/fubar.ml")
print "=== DONE ==="
