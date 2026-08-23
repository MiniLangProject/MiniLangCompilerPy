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

package std.cpu

const SSE2 = 1
const SSE42 = 2
const AVX = 4
const AVX2 = 8
const AES_NI = 16
const PCLMULQDQ = 32
const SHA = 64

// Return capabilities detected once during process startup.
function features()
  return runtimeCpuFeatures()
end function

// Return the feature mask currently used by runtime dispatch.
function activeFeatures()
  return runtimeCpuActiveFeatures()
end function

// Restrict dispatch for differential tests and benchmarks.  The mask cannot
// enable unsupported instructions.  A negative value restores all detected
// features; the previous active mask is returned.
function setDispatchMaskForTesting(mask)
  return runtimeCpuSetMask(mask)
end function
