/*
 * Regression for deep mutable object graphs under precise, periodic GC.
 *
 * This deliberately mirrors the BSP parser's ownership shape:
 *   - preallocated arrays that are promoted from immediate to reference arrays
 *   - structs with several nested Vec3 children
 *   - a parent map whose sibling arrays are assigned after construction
 *   - construction split across several user functions
 *   - both module-initializer and main-function roots
 *   - a closed-program Thread reference, so the TLS shadow-root path is emitted
 */

struct GcGraphVec3
  x
  y
  z
end struct

struct GcGraphPlane
  normal
  distance
  kind
end struct

struct GcGraphNode
  plane
  mins
  maxs
  links
  number
end struct

struct GcGraphLeaf
  mins
  maxs
  marks
  number
end struct

struct GcGraphMap
  planes
  nodes
  leaves
  models
  seed
end struct

function gcGraphAssert(condition, message)
  if not condition then return error(1720, message) end if
  return true
end function

function gcGraphVec(seed)
  return GcGraphVec3(seed, seed + 1, seed + 2)
end function

function gcGraphPlaneAt(seed)
  return GcGraphPlane(gcGraphVec(seed * 10), seed * 3, seed % 6)
end function

function gcGraphNestedLinks(seed)
  // The outer ArrayLit base normally lives in an ExprValueTemp register while
  // the inner calls and ArrayLit allocate and may collect.
  return [
    gcGraphVec(seed * 20),
    [gcGraphVec(seed * 20 + 3), gcGraphPlaneAt(seed + 7)],
    gcGraphVec(seed * 20 + 6)
  ]
end function

function inline gcGraphInlineArrayElement(seed)
  value = GcGraphVec3(seed, seed + 1, seed + 2)
  // Inline statement emission uses r12 for the checked member target.  An
  // enclosing ArrayLit must not mistake that scratch value for its own base.
  value.x = seed
  return value
end function

function gcGraphInlineArray(seed)
  return [gcGraphInlineArrayElement(seed), gcGraphInlineArrayElement(seed + 10)]
end function

function gcGraphNodeAt(seed)
  mins = gcGraphVec(seed * 30)
  maxs = gcGraphVec(seed * 30 + 3)
  plane = gcGraphPlaneAt(seed)
  links = gcGraphNestedLinks(seed)
  node = GcGraphNode(plane, mins, maxs, links, seed)

  // Match parse.ml's post-constructor writes and ensure every nested child is
  // still reachable when the struct is subsequently placed into an array.
  node.mins = mins
  node.maxs = maxs
  node.links = links
  return node
end function

function gcGraphLeafAt(seed)
  mins = gcGraphVec(seed * 40)
  maxs = gcGraphVec(seed * 40 + 3)
  marks = [seed, seed + 1, seed + 2, seed + 3]
  leaf = GcGraphLeaf(mins, maxs, marks, seed)
  leaf.mins = mins
  leaf.maxs = maxs
  return leaf
end function

function gcGraphBuildPlanes(count, seed)
  values = array(count)
  i = 0
  while i < count
    value = gcGraphPlaneAt(seed + i)
    values[i] = value
    if (i % 97) == 0 then gc_collect() end if
    i = i + 1
  end while
  return values
end function

function gcGraphBuildNodes(count, seed)
  values = array(count)
  i = 0
  while i < count
    value = gcGraphNodeAt(seed + i)
    values[i] = value
    if (i % 71) == 0 then gc_collect() end if
    i = i + 1
  end while
  return values
end function

function gcGraphBuildLeaves(count, seed)
  values = array(count)
  i = 0
  while i < count
    value = gcGraphLeafAt(seed + i)
    values[i] = value
    if (i % 83) == 0 then gc_collect() end if
    i = i + 1
  end while
  return values
end function

function gcGraphBuildModels(count, seed)
  values = array(count)
  i = 0
  while i < count
    values[i] = [gcGraphVec(seed + i), gcGraphVec(seed + i + 100000)]
    i = i + 1
  end while
  return values
end function

function gcGraphBuildMap(count, seed)
  map = GcGraphMap([], [], [], [], seed)
  planes = gcGraphBuildPlanes(count, seed)
  map.planes = planes
  gc_collect()

  nodes = gcGraphBuildNodes(count, seed + 10000)
  map.nodes = nodes
  gc_collect()

  leaves = gcGraphBuildLeaves(count, seed + 20000)
  map.leaves = leaves
  gc_collect()

  models = gcGraphBuildModels(48, seed + 30000)
  map.models = models
  gc_collect()
  return map
end function

function gcGraphValidate(map, count, seed)
  gcGraphAssert(typeof(map) == "struct", "map remains a struct")
  gcGraphAssert(typeof(map.planes) == "array", "planes remain an array")
  gcGraphAssert(typeof(map.nodes) == "array", "nodes remain an array")
  gcGraphAssert(typeof(map.leaves) == "array", "leaves remain an array")
  gcGraphAssert(typeof(map.models) == "array", "models remain an array")
  gcGraphAssert(len(map.planes) == count, "plane count")
  gcGraphAssert(len(map.nodes) == count, "node count")
  gcGraphAssert(len(map.leaves) == count, "leaf count")

  i = 0
  while i < count
    plane = map.planes[i]
    gcGraphAssert(typeof(plane) == "struct", "plane remains a struct")
    gcGraphAssert(typeof(plane.normal) == "struct", "plane normal remains a struct")
    gcGraphAssert(plane.normal.x == (seed + i) * 10, "plane normal value")

    nodeSeed = seed + 10000 + i
    node = map.nodes[i]
    gcGraphAssert(typeof(node) == "struct", "node remains a struct")
    gcGraphAssert(typeof(node.plane) == "struct", "node plane remains a struct")
    gcGraphAssert(typeof(node.plane.normal) == "struct", "node plane normal remains a struct")
    gcGraphAssert(typeof(node.mins) == "struct", "node mins remains a struct")
    gcGraphAssert(typeof(node.maxs) == "struct", "node maxs remains a struct")
    gcGraphAssert(node.mins.x == nodeSeed * 30, "node mins value")
    gcGraphAssert(node.maxs.z == nodeSeed * 30 + 5, "node maxs value")
    gcGraphAssert(typeof(node.links) == "array", "node links remain an array")
    gcGraphAssert(typeof(node.links[1]) == "array", "nested links remain an array")
    gcGraphAssert(typeof(node.links[1][1]) == "struct", "nested link plane remains a struct")
    gcGraphAssert(typeof(node.links[1][1].normal) == "struct", "nested link normal remains a struct")

    leafSeed = seed + 20000 + i
    leaf = map.leaves[i]
    gcGraphAssert(typeof(leaf) == "struct", "leaf remains a struct")
    gcGraphAssert(typeof(leaf.mins) == "struct", "leaf mins remains a struct")
    gcGraphAssert(typeof(leaf.maxs) == "struct", "leaf maxs remains a struct")
    gcGraphAssert(leaf.mins.x == leafSeed * 40, "leaf mins value")

    i = i + 1
  end while
  return true
end function

function gcGraphChurn(round)
  i = 0
  while i < 1800
    garbage = [gcGraphVec(round + i), gcGraphPlaneAt(round + i), [i, i + 1, i + 2]]
    i = i + 1
  end while
  gc_collect()
end function

// Merely referencing the constructor is enough to select the TLS/thread-aware
// allocator and shadow-root traversal in this closed program. It is never run.
function gcGraphUnusedWorker()
  return 0
end function

function gcGraphNeverRunThread()
  return Thread(gcGraphUnusedWorker)
end function

// Exercise module initialization calling into ordinary user functions while
// retaining a deep graph in a package/global root.
gcGraphModuleMap = gcGraphBuildMap(96, 700000)

function main(args)
  inlineArray = gcGraphInlineArray(1234)
  gcGraphAssert(typeof(inlineArray) == "array", "inline element preserves outer array base")
  gcGraphAssert(len(inlineArray) == 2, "inline element array length")
  gcGraphAssert(typeof(inlineArray[0]) == "struct", "inline first element remains a struct")
  gcGraphAssert(inlineArray[0].x == 1234, "inline first element value")
  gcGraphAssert(typeof(inlineArray[1]) == "struct", "inline second element remains a struct")
  gcGraphAssert(inlineArray[1].x == 1244, "inline second element value")

  gcGraphValidate(gcGraphModuleMap, 96, 700000)

  mapCount = 3
  graphCount = 1400
  retained = array(mapCount)
  m = 0
  while m < mapCount
    seed = m * 100000
    retained[m] = gcGraphBuildMap(graphCount, seed)
    gcGraphChurn(m * 10000)
    gcGraphValidate(retained[m], graphCount, seed)
    m = m + 1
  end while

  round = 0
  while round < 12
    gcGraphChurn(round * 200000)
    m = 0
    while m < mapCount
      seed = m * 100000
      gcGraphValidate(retained[m], graphCount, seed)
      m = m + 1
    end while
    gcGraphValidate(gcGraphModuleMap, 96, 700000)
    round = round + 1
  end while

  print "[OK] gc_nested_graph_roots: PASS"
  return 0
end function
