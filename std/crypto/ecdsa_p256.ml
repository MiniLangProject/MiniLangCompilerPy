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

//! Provides ECDSA-P256 signature verification backed by the platform crypto provider.

package std.crypto.ecdsa_p256

import std.crypto as crypto
#if TARGET_OS == "windows"
import std.crypto._cng as backend
#else
import std.crypto._openssl as backend
#endif

/// Error code returned for invalid ECDSA-P256 arguments or backend failures.
const ECDSA_P256_ERR = 242

/// Verify a SHA-256 ECDSA-P256 signature.
/// Public keys use the 64-byte big-endian X||Y representation. Signatures use
/// the fixed-width 64-byte IEEE-P1363 r||s representation.
/// @param publicKey Raw P-256 public key.
/// @param message Message whose signature is checked.
/// @param signature Raw IEEE-P1363 signature.
function verify(publicKey, message, signature)
  if typeof(publicKey) != "bytes" or len(publicKey) != 64 then return false end if
  if typeof(message) != "bytes" then return false end if
  if typeof(signature) != "bytes" or len(signature) != 64 then return false end if
  digest = crypto.sha256(message)
  if typeof(digest) == "error" then return false end if
  ok = backend.ecdsaP256Verify(publicKey, digest, signature)
  crypto.secureZero(digest)
  return ok
end function
