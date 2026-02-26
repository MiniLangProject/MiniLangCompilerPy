// Minimal test helpers (declaration-only module)
function assertEq(a, b, msg)
    if a == b then
        print msg + " [OK]"
    else
        print msg + " [FAIL]"
        print "got"
        print a
        print "expected"
        print b
    end if
end function

function assertTrue(cond, msg)
    if cond then
        print msg + " [OK]"
    else
        print msg + " [FAIL]"
    end if
end function
