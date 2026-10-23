// Regression: an unreachable function is still lowered for diagnostics.
// Concurrent-GC member writes in that transient code path must retain the
// spill hook, without making helpers from discarded instructions reachable.
struct DeadBarrierBox
  value
end struct

function unusedConcurrentBarrier()
  box = DeadBarrierBox(void)
  box.value = array(2, bytes(16, 37))
  return true
end function

print "GC CONCURRENT DEAD FUNCTION [OK]"
