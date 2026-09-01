// A raw value can point inside another managed object. Payload bytes there may
// accidentally resemble a valid heap header and object type. The collector
// must bound embedded lengths to that candidate block instead of scanning past
// committed heap memory.
backing = void
interiorCandidate = void

function main(args)
  backing = bytes(128, 0)

  // At payload+8, encode a plausible 64-byte block header. At payload+16,
  // encode OBJ_ENV (8) followed by an impossible 1,073,741,824-slot count.
  backing[8] = 64
  backing[16] = 8
  backing[23] = 64

  interiorCandidate = nativeValueFromRaw(nativeBytesPtr(backing) + 16)
  gc_collect()

  if typeof(backing) != "bytes" or len(backing) != 128 then return 2 end if
  interiorCandidate = void
  gc_collect()
  print "[OK] GC bounds conservative interior pointers"
  return 0
end function
