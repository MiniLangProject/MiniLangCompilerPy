extern function RtlMoveMemory(dest as ptr, src as bytes, count as int) from "kernel32.dll" symbol "RtlMoveMemory" returns ptr

function ok(cond, label)
  if cond then
    print label + " [OK]"
  else
    print label + " [FAIL]"
  end if
end function

function main(args)
  print "=== NATIVE BYTES PTR ==="
  dst = bytes(4, 0)
  src = bytes("ABCD")
  p = nativeBytesPtr(dst)
  ok(typeof(p) == "int", "nativeBytesPtr returns int")
  ok(p != 0, "nativeBytesPtr non-null")
  RtlMoveMemory(p, src, 4)
  ok(decode(dst) == "ABCD", "nativeBytesPtr payload write")
  ok(nativeBytesPtr("not bytes") == 0, "nativeBytesPtr rejects non-bytes")
  print "=== DONE ==="
end function
