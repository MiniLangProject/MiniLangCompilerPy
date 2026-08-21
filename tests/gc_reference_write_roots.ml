/* Regression coverage for GC roots around constructors and reference writes. */

struct GcRootBox
  value
end struct

struct GcRootPair
  first
  second
end struct

struct GcRootWide
  a
  b
  c
  d
  e
  f
end struct

function gcReferenceConstructorArg(seed)
  GcRootBox(seed + 10)
  GcRootBox(seed + 11)
  GcRootBox(seed + 12)
  GcRootBox(seed + 13)
  GcRootBox(seed + 14)
  gc_collect()
  return GcRootBox(seed)
end function

gcReferenceSurvivor = void
gcReferenceTopLevel = GcRootWide(
  gcReferenceConstructorArg(100), gcReferenceConstructorArg(101), gcReferenceConstructorArg(102),
  gcReferenceConstructorArg(103), gcReferenceConstructorArg(104), gcReferenceConstructorArg(105)
)

function gcReferenceTarget()
  return GcRootBox(1)
end function

function gcReferenceRhs()
  global gcReferenceSurvivor
  // Evict the caller's unrooted target from the allocator's short handoff-root
  // ring before constructing the observable RHS value.
  GcRootBox(10)
  GcRootBox(11)
  GcRootBox(12)
  GcRootBox(13)
  GcRootBox(14)
  gc_collect()
  gcReferenceSurvivor = GcRootBox(2)
  return gcReferenceSurvivor
end function

function gcReferenceNested(seed)
  return GcRootPair(
    GcRootBox(seed),
    [GcRootBox(seed + 1), GcRootBox(seed + 2)]
  )
end function

function gcReferenceAssert(condition, message)
  if not condition then return error(1710, message) end if
  return true
end function

function main(args)
  global gcReferenceSurvivor

  gcReferenceAssert(typeof(gcReferenceTopLevel) == "struct", "top-level constructor remains a struct")
  gcReferenceAssert(typeof(gcReferenceTopLevel.a) == "struct", "top-level constructor roots early argument")
  gcReferenceAssert(gcReferenceTopLevel.a.value == 100, "top-level early constructor argument value")
  gcReferenceAssert(typeof(gcReferenceTopLevel.f) == "struct", "top-level constructor roots late argument")
  gcReferenceAssert(gcReferenceTopLevel.f.value == 105, "top-level late constructor argument value")

  // The target returned by gcReferenceTarget has no root other than the
  // assignment evaluator while gcReferenceRhs allocates. With a collection on
  // every allocation, losing that root lets the RHS reuse the target block and
  // turns this write into survivor.value = survivor.
  gcReferenceTarget().value = gcReferenceRhs()
  gcReferenceAssert(typeof(gcReferenceSurvivor) == "struct", "RHS survivor remains a struct")
  gcReferenceAssert(typeof(gcReferenceSurvivor.value) == "int", "temporary member target is rooted across RHS")
  gcReferenceAssert(gcReferenceSurvivor.value == 2, "temporary member write does not corrupt RHS")

  iteration = 0
  while iteration < 4000
    nested = gcReferenceNested(iteration)
    gc_collect()
    gcReferenceAssert(typeof(nested.first) == "struct", "constructor child remains a struct")
    gcReferenceAssert(nested.first.value == iteration, "constructor child value")
    gcReferenceAssert(typeof(nested.second) == "array", "constructor array remains an array")
    gcReferenceAssert(typeof(nested.second[0]) == "struct", "array reference promotes and survives")
    gcReferenceAssert(nested.second[0].value == iteration + 1, "array child value")

    replacement = GcRootBox(iteration + 3)
    nested.second[1] = replacement
    gc_collect()
    gcReferenceAssert(typeof(nested.second[1]) == "struct", "array reference write survives")
    gcReferenceAssert(nested.second[1].value == iteration + 3, "array replacement value")
    iteration = iteration + 1
  end while

  print "[OK] gc_reference_write_roots: PASS"
  return 0
end function
