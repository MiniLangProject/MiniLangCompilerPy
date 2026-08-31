/* Diagnostic benchmark for language-level optimizer features. */

import std.time as time

escapedTail = []

function typedArithmetic(iterations as int) returns int
  checksum = 0
  for i = 0 to iterations - 1
    result = (i & 1023) * 3 + 1
    result = (result ^ 85) + 7
    result = result * 5 - 11
    result = (result & 2047) * 3 + 19
    checksum = checksum + result
  end for
  return checksum
end function

function dynamicArithmetic(iterations)
  checksum = 0
  for i = 0 to iterations - 1
    result = (i & 1023) * 3 + 1
    result = (result ^ 85) + 7
    result = result * 5 - 11
    result = (result & 2047) * 3 + 19
    checksum = checksum + result
  end for
  return checksum
end function

function automaticInline(value as int) returns int
  return value * 3 + 1
end function

function typedOutOfLine(value as int) returns int
  result = value * 3 + 1
  return result
end function

iterator function eagerNumbers(limit as int) returns int
  for i = 0 to limit - 1
    yield i
  end for
end function

lazy iterator function lazyNumbers(limit as int) returns int
  for i = 0 to limit - 1
    yield i
  end for
end function

function stackTailSum(values...)
  total = 0
  for each value in values
    total = total + value
  end for
  return total
end function

function heapTailSum(values...)
  global escapedTail
  escapedTail = values
  total = 0
  for each value in values
    total = total + value
  end for
  return total
end function

async function pooledWork(value as int) returns int
  return value * 2 + 1
end function

function threadedWork(value)
  return value * 2 + 1
end function

function main(args)
  arithmeticIterations = 24000000
  iteratorCount = 1500000
  variadicIterations = 5000000
  asyncWaves = 64
  asyncWidth = 64

  // Warm the generated functions before collecting millisecond timings.
  warmup = typedArithmetic(2) + dynamicArithmetic(2) + automaticInline(1) + typedOutOfLine(1)
  if warmup <= 0 then return 1 end if

  started = time.ticks()
  checksum = typedArithmetic(arithmeticIterations)
  typedMs = time.ticks() - started

  started = time.ticks()
  dynamicChecksum = dynamicArithmetic(arithmeticIterations)
  dynamicMs = time.ticks() - started
  if checksum != dynamicChecksum then return 2 end if

  inlineChecksum = 0
  started = time.ticks()
  for i = 0 to arithmeticIterations - 1
    inlineChecksum = inlineChecksum + automaticInline(i & 1023)
  end for
  inlineMs = time.ticks() - started

  callChecksum = 0
  started = time.ticks()
  for i = 0 to arithmeticIterations - 1
    callChecksum = callChecksum + typedOutOfLine(i & 1023)
  end for
  outOfLineMs = time.ticks() - started
  if inlineChecksum != callChecksum then return 3 end if

  gc_collect()
  eagerHeapBefore = heap_bytes_used()
  started = time.ticks()
  eagerValues = eagerNumbers(iteratorCount)
  eagerHeapBytes = heap_bytes_used() - eagerHeapBefore
  eagerChecksum = 0
  for each value in eagerValues
    eagerChecksum = eagerChecksum + value
  end for
  eagerMs = time.ticks() - started
  eagerValues = void
  gc_collect()

  lazyHeapBefore = heap_bytes_used()
  started = time.ticks()
  lazyValues = lazyNumbers(iteratorCount)
  lazyHeapBytes = heap_bytes_used() - lazyHeapBefore
  lazyChecksum = 0
  for each value in lazyValues
    lazyChecksum = lazyChecksum + value
  end for
  lazyMs = time.ticks() - started
  if eagerChecksum != lazyChecksum then return 4 end if

  stackChecksum = 0
  started = time.ticks()
  for i = 0 to variadicIterations - 1
    stackChecksum = stackChecksum + stackTailSum(1, 2, 3, 4, 5)
  end for
  stackVariadicMs = time.ticks() - started

  heapChecksum = 0
  started = time.ticks()
  for i = 0 to variadicIterations - 1
    heapChecksum = heapChecksum + heapTailSum(1, 2, 3, 4, 5)
  end for
  heapVariadicMs = time.ticks() - started
  if stackChecksum != heapChecksum then return 5 end if

  asyncChecksum = 0
  jobs = array(asyncWidth, void)
  started = time.ticks()
  for wave = 0 to asyncWaves - 1
    for i = 0 to asyncWidth - 1
      jobs[i] = pooledWork(i)
    end for
    for i = 0 to asyncWidth - 1
      asyncChecksum = asyncChecksum + await jobs[i]
      if not jobs[i].Dispose() then return 6 end if
    end for
  end for
  pooledMs = time.ticks() - started

  threadChecksum = 0
  workers = array(asyncWidth, void)
  started = time.ticks()
  for wave = 0 to asyncWaves - 1
    for i = 0 to asyncWidth - 1
      workers[i] = Thread(threadedWork)
      if not workers[i].Start(i) then return 7 end if
    end for
    for i = 0 to asyncWidth - 1
      if not workers[i].Join(30000) then return 8 end if
      threadChecksum = threadChecksum + workers[i].Result()
      if not workers[i].Close() then return 9 end if
    end for
  end for
  threadsMs = time.ticks() - started
  if asyncChecksum != threadChecksum then return 10 end if

  print "typed_arithmetic_ms=" + typedMs + " dynamic_arithmetic_ms=" + dynamicMs
  print "auto_inline_ms=" + inlineMs + " typed_call_ms=" + outOfLineMs
  print "eager_iterator_ms=" + eagerMs + " lazy_iterator_ms=" + lazyMs
  print "eager_iterator_heap_bytes=" + eagerHeapBytes + " lazy_iterator_heap_bytes=" + lazyHeapBytes
  print "stack_variadic_ms=" + stackVariadicMs + " escaping_variadic_ms=" + heapVariadicMs
  print "pooled_async_jobs=" + (asyncWaves * asyncWidth) + " elapsed_ms=" + pooledMs
  print "native_threads=" + (asyncWaves * asyncWidth) + " elapsed_ms=" + threadsMs
  return 0
end function
