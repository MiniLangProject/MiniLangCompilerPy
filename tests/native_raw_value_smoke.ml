function ok(cond, label)
  if cond then
    print label + " [OK]"
  else
    print label + " [FAIL]"
  end if
end function

function main(args)
  print "=== NATIVE RAW VALUE ==="
  b = bytes("x")
  raw = nativeRawValue(b)
  ok(typeof(raw) == "int", "nativeRawValue returns int")
  ok(raw != 0, "nativeRawValue non-zero")
  b2 = nativeValueFromRaw(raw)
  ok(b2 == b, "nativeValueFromRaw roundtrip")
  ok(nativeValueFromRaw("not raw") is void, "nativeValueFromRaw rejects non-int")
  print "=== DONE ==="
end function
