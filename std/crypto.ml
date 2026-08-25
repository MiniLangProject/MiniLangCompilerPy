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

package std.crypto
#if TARGET_OS == "windows"
import std.crypto._cng as cng
#else
import std.crypto._openssl as cng
#endif

const CRYPTO_ERR = 240

function _cryptoError(message)
  return error(CRYPTO_ERR, message)
end function

// Compute SHA-256 through the platform crypto backend.
function sha256(input)
  if typeof(input) != "bytes" then return _cryptoError("sha256 expects bytes") end if
  output = bytes(32, 0)
  if not cng.hash("SHA256", void, input, output) then return _cryptoError("SHA-256 backend failure") end if
  return output
end function

// Compute SHA-384 through the platform crypto backend.
function sha384(input)
  if typeof(input) != "bytes" then return _cryptoError("sha384 expects bytes") end if
  output = bytes(48, 0)
  if not cng.hash("SHA384", void, input, output) then return _cryptoError("SHA-384 backend failure") end if
  return output
end function

// Compute HMAC-SHA-256 through the platform crypto backend.
function hmacSha256(key, input)
  if typeof(key) != "bytes" or typeof(input) != "bytes" then return _cryptoError("hmacSha256 expects bytes") end if
  output = bytes(32, 0)
  if not cng.hash("SHA256", key, input, output) then return _cryptoError("HMAC-SHA-256 backend failure") end if
  return output
end function

// Compute HMAC-SHA-384 through the platform crypto backend.
function hmacSha384(key, input)
  if typeof(key) != "bytes" or typeof(input) != "bytes" then return _cryptoError("hmacSha384 expects bytes") end if
  output = bytes(48, 0)
  if not cng.hash("SHA384", key, input, output) then return _cryptoError("HMAC-SHA-384 backend failure") end if
  return output
end function

function _hkdf(hashAlgorithm, digestLength, inputKeyMaterial, salt, info, length)
  if typeof(inputKeyMaterial) != "bytes" or typeof(salt) != "bytes" or typeof(info) != "bytes" then
    return _cryptoError("HKDF expects bytes")
  end if
  if typeof(length) != "int" or length < 0 or length > 255 * digestLength then
    return _cryptoError("Invalid HKDF output length")
  end if
  output = bytes(length, 0)
  if not cng.hkdf(hashAlgorithm, digestLength, inputKeyMaterial, salt, info, output) then
    return _cryptoError("HKDF backend failure")
  end if
  return output
end function

// RFC-5869 HKDF-SHA-256 (extract and expand).
function hkdfSha256(inputKeyMaterial, salt, info, length)
  return _hkdf("SHA256", 32, inputKeyMaterial, salt, info, length)
end function

// RFC-5869 HKDF-SHA-384 (extract and expand).
function hkdfSha384(inputKeyMaterial, salt, info, length)
  return _hkdf("SHA384", 48, inputKeyMaterial, salt, info, length)
end function

function _pbkdf2(hashAlgorithm, password, salt, iterations, length)
  if typeof(password) != "bytes" or typeof(salt) != "bytes" then return _cryptoError("PBKDF2 expects bytes") end if
  if typeof(iterations) != "int" or iterations <= 0 or iterations > 0x7FFFFFFF then return _cryptoError("Invalid PBKDF2 iteration count") end if
  if typeof(length) != "int" or length < 0 or length > 0x7FFFFFFF then return _cryptoError("Invalid PBKDF2 output length") end if
  output = bytes(length, 0)
  if not cng.pbkdf2(hashAlgorithm, password, salt, iterations, output) then return _cryptoError("PBKDF2 backend failure") end if
  return output
end function

// Derive key material using PBKDF2-HMAC-SHA-256.
function pbkdf2Sha256(password, salt, iterations, length)
  return _pbkdf2("SHA256", password, salt, iterations, length)
end function

// Derive key material using PBKDF2-HMAC-SHA-384.
function pbkdf2Sha384(password, salt, iterations, length)
  return _pbkdf2("SHA384", password, salt, iterations, length)
end function

// Obtain cryptographically secure random bytes from the platform provider.
function secureRandom(length)
  if typeof(length) != "int" or length < 0 or length > 0x7FFFFFFF then return _cryptoError("Invalid random length") end if
  output = bytes(length, 0)
  if not cng.random(output) then return _cryptoError("Secure random backend failure") end if
  return output
end function

// Compare two bytes values without content-dependent early exits.
function constantTimeEquals(a, b)
  if typeof(a) != "bytes" or typeof(b) != "bytes" then return false end if
  return bytesConstantTimeEquals(a, b)
end function

// Best-effort in-place erasure.  MiniLang's native fill helper performs the
// observable write, but callers must still avoid prior copies of key material.
function secureZero(buffer)
  if typeof(buffer) != "bytes" then return false end if
  if len(buffer) > 0 then fillBytes(buffer, 0, len(buffer), 0) end if
  return true
end function

// Derive the RFC-7748 public key for a 32-byte X25519 private scalar.
function x25519PublicKey(privateKey)
  if typeof(privateKey) != "bytes" or len(privateKey) != 32 then return _cryptoError("X25519 private key must be 32 bytes") end if
  output = bytes(32, 0)
  if not cng.x25519Public(privateKey, output) then return _cryptoError("X25519 public-key derivation failed") end if
  return output
end function

// Derive an X25519 shared secret.  CNG errors and all-zero weak results are
// rejected without returning secret bytes.
function x25519(privateKey, peerPublicKey)
  if typeof(privateKey) != "bytes" or len(privateKey) != 32 then return _cryptoError("X25519 private key must be 32 bytes") end if
  if typeof(peerPublicKey) != "bytes" or len(peerPublicKey) != 32 then return _cryptoError("X25519 public key must be 32 bytes") end if
  output = bytes(32, 0)
  if not cng.x25519(privateKey, peerPublicKey, output) then return _cryptoError("X25519 agreement failed") end if
  zero = bytes(32, 0)
  weak = bytesConstantTimeEquals(output, zero)
  secureZero(zero)
  if weak then
    secureZero(output)
    return _cryptoError("X25519 rejected a weak public key")
  end if
  return output
end function
