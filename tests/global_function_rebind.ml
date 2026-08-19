function original()
  return "original"
end function

function replacement()
  return "replacement"
end function

original = replacement
function main(args)
  if original() == "replacement" then
    print "global function rebind [OK]"
    return 0
  else
    print "global function rebind [FAIL]"
    return 1
  end if
end function
