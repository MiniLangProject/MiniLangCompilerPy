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
//! Mbed TLS implementation of the internal standard-library crypto contract.
package std.crypto._minux

/// Call the native digest and HMAC bridge.
/// @internal
extern function _hash(algorithm as int, key as ptr, keyLength as i64, input as ptr, length as u64, output as ptr) from "libminilang_minux.so" symbol "mlc_crypto_hash" returns bool
/// Fill native bytes from the MinUX cryptographic random provider.
/// @internal
extern function _random(output as ptr, length as u64) from "libminilang_minux.so" symbol "mlc_crypto_random" returns bool
/// Call the native password-based key derivation bridge.
/// @internal
extern function _pbkdf2(algorithm as int, password as ptr, passwordLength as u64, salt as ptr, saltLength as u64, iterations as int, output as ptr, length as u32) from "libminilang_minux.so" symbol "mlc_crypto_pbkdf2" returns bool
/// Call the native extract-and-expand bridge.
/// @internal
extern function _hkdf(algorithm as int, input as ptr, inputLength as u64, salt as ptr, saltLength as u64, info as ptr, infoLength as u64, output as ptr, length as u64) from "libminilang_minux.so" symbol "mlc_crypto_hkdf" returns bool
/// Call the native authenticated encryption bridge.
/// @internal
extern function _gcm(encrypting as int, key as ptr, nonce as ptr, aad as ptr, aadLength as u64, input as ptr, inputLength as u64, output as ptr, tagLength as u64) from "libminilang_minux.so" symbol "mlc_crypto_gcm" returns bool
/// Call the native Curve25519 bridge.
/// @internal
extern function _x25519(privateKey as ptr, publicKey as ptr, output as ptr) from "libminilang_minux.so" symbol "mlc_crypto_x25519" returns bool
/// Call native P-256 signature verification.
/// @internal
extern function _verify(publicKey as ptr, digest as ptr, signature as ptr) from "libminilang_minux.so" symbol "mlc_crypto_p256_verify" returns bool

/// Translate a standard hash name to the native provider identifier.
/// @internal
function _algorithm(name)
  if name == "SHA256" then return 256 end if
  if name == "SHA384" then return 384 end if
  return 0
end function
/// Write a digest or HMAC into the supplied output buffer.
/// @internal
function hash(algorithm, key, input, output)
  keyPointer = 0
  keyLength = -1
  if typeof(key) == "bytes" then keyPointer = nativeBytesPtr(key); keyLength = len(key) end if
  return _hash(_algorithm(algorithm), keyPointer, keyLength, nativeBytesPtr(input), len(input), nativeBytesPtr(output))
end function
/// Fill an existing managed buffer with cryptographic random bytes.
/// @internal
function random(output)
  return _random(nativeBytesPtr(output), len(output))
end function
/// Derive password-based key bytes into the supplied output.
/// @internal
function pbkdf2(algorithm, password, salt, iterations, output)
  return _pbkdf2(_algorithm(algorithm), nativeBytesPtr(password), len(password), nativeBytesPtr(salt), len(salt), iterations, nativeBytesPtr(output), len(output))
end function
/// Derive key bytes using the selected hash and context.
/// @internal
function hkdf(algorithm, digestLength, input, salt, info, output)
  return _hkdf(_algorithm(algorithm), nativeBytesPtr(input), len(input), nativeBytesPtr(salt), len(salt), nativeBytesPtr(info), len(info), nativeBytesPtr(output), len(output))
end function
/// Encrypt or decrypt an authenticated GCM byte range.
/// @internal
function aesGcm(encrypting, key, nonce, aad, input, output, tagLength)
  mode = 0
  if encrypting then mode = 1 end if
  return _gcm(mode, nativeBytesPtr(key), nativeBytesPtr(nonce), nativeBytesPtr(aad), len(aad), nativeBytesPtr(input), len(input), nativeBytesPtr(output), tagLength)
end function
/// Derive a Curve25519 public key.
/// @internal
function x25519Public(privateKey, output)
  return _x25519(nativeBytesPtr(privateKey), 0, nativeBytesPtr(output))
end function
/// Derive a Curve25519 shared secret.
/// @internal
function x25519(privateKey, publicKey, output)
  return _x25519(nativeBytesPtr(privateKey), nativeBytesPtr(publicKey), nativeBytesPtr(output))
end function
/// Verify a P-256 signature over an existing digest.
/// @internal
function ecdsaP256Verify(publicKey, digest, signature)
  return _verify(nativeBytesPtr(publicKey), nativeBytesPtr(digest), nativeBytesPtr(signature))
end function
