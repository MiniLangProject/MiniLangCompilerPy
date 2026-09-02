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

//! Provides the std cpu package.

package std.cpu

/// Track the sse2 value used by this standard-library module.
const SSE2 = 1
/// Track the sse42 value used by this standard-library module.
const SSE42 = 2
/// Track the avx value used by this standard-library module.
const AVX = 4
/// Track the avx2 value used by this standard-library module.
const AVX2 = 8
/// Track the aes ni value used by this standard-library module.
const AES_NI = 16
/// Track the pclmulqdq value used by this standard-library module.
const PCLMULQDQ = 32
/// Track the sha value used by this standard-library module.
const SHA = 64

/// Return capabilities detected once during process startup.
function features()
  return runtimeCpuFeatures()
end function

/// Return the feature mask currently used by runtime dispatch.
function activeFeatures()
  return runtimeCpuActiveFeatures()
end function

/// Restrict dispatch for differential tests and benchmarks. The mask cannot enable unsupported instructions. A negative value restores all detected features; the previous active mask is returned.
/// @param mask Value supplied for `mask`.
function setDispatchMaskForTesting(mask)
  return runtimeCpuSetMask(mask)
end function
