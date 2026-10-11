// Repeated snapshots must not let a small buffer consume the large hole
// while a smaller suitable hole remains available in another size class.
orderAnchors = array(8, void)
orderSmall = void
orderLarge = void

function seedOrderedHoles()
  global orderAnchors
  // Dynamic sizes preserve allocation order instead of preallocating a batch.
  // Anchors exceed a TLAB so they cannot fit in its already-reserved free tail.
  first = bytes(1024 * 1024 + heap_bytes_used() % 8, 31)
  orderAnchors[0] = bytes(128 * 1024 + heap_bytes_used() % 64, 61)
  second = bytes(8 * 1024 * 1024 + heap_bytes_used() % 8, 47)
  for i = 1 to 7
    orderAnchors[i] = bytes(128 * 1024 + heap_bytes_used() % 64, i)
  end for
  return first[0] + second[0]
end function

function reuseOrderedHoles()
  global orderSmall, orderLarge
  orderSmall = bytes(256 * 1024 + heap_bytes_used() % 8, 29)
  orderLarge = bytes(8 * 1024 * 1024 + heap_bytes_used() % 8, 53)
end function

function main(args)
  gc_set_limit(0)
  if seedOrderedHoles() != 78 then return 1 end if
  // First cycle publishes holes; later cycles must preserve useful placement.
  gc_collect()
  gc_collect()
  gc_collect()
  before = heap_bytes_used()
  reuseOrderedHoles()
  growth = heap_bytes_used() - before
  gc_collect()
  if orderSmall[0] != 29 or orderLarge[len(orderLarge) - 1] != 53 then return 2 end if
  if orderAnchors[0][131071] != 61 or orderAnchors[7][131071] != 7 then return 3 end if
  if growth > 1024 * 1024 then return 9 end if
  if gc_stat(20) != 0 then return 10 end if
  print "GC CONCURRENT ORDER [OK] growth=" + growth
  return 0
end function
