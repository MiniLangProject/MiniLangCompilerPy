/*
   Copyright 2026 Nils Kopal

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

import std.assert as a

function ok(cond, label)
  return a.assertTrue(cond, label)
end function

print "=== GC PERIODIC ==="

// Disable periodic GC while we build up garbage.
// We want to verify that periodic triggering works (not the OOM fallback).
gc_set_limit(0)

base_free = heap_free_blocks()

// Allocate a lot of short-lived objects (garbage).
for i = 0 to 12000
  tmp = bytes(1024)
end for

// Drop the last reference too.
tmp = 0

// Create ONE live object at the end of the heap, so GC can't just rewind heap_ptr to heap_base.
// This forces dead blocks *before* it to become free-list blocks.
anchor = bytes(64)
ok(len(anchor) == 64, "anchor len pre")

free0 = heap_free_blocks()
ok(free0 == base_free, "no free blocks before periodic GC")

// Force the next allocation to trigger periodic GC.
gc_set_limit(1)

x = bytes(16)
// Drop x; anchor must remain alive.
x = 0

free1 = heap_free_blocks()
ok(free1 > free0, "periodic GC created free blocks")
ok(len(anchor) == 64, "anchor still alive")

// Tidy up: disable periodic GC again.
gc_set_limit(0)

print "=== DONE ==="

