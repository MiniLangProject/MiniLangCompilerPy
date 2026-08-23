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

// Internal Windows CNG bridge.  Public callers use std.crypto and
// std.crypto.aes_gcm; this module only marshals validated byte buffers into
// BCrypt.  Cryptographic transformations never run in MiniLang loops.
package std.crypto._cng

extern function BCryptOpenAlgorithmProvider(result as bytes, algorithm as wstr, implementation as ptr, flags as u32) from "bcrypt.dll" returns i32
extern function BCryptCloseAlgorithmProvider(handle as ptr, flags as u32) from "bcrypt.dll" returns i32
extern function BCryptHash(handle as ptr, secret as ptr, secretLength as u32, input as ptr, inputLength as u32, output as ptr, outputLength as u32) from "bcrypt.dll" returns i32
extern function BCryptGenRandom(handle as ptr, output as ptr, outputLength as u32, flags as u32) from "bcrypt.dll" returns i32
extern function BCryptSetPropertyW(handle as ptr, property as wstr, value as wstr, valueLength as u32, flags as u32) from "bcrypt.dll" symbol "BCryptSetProperty" returns i32
extern function BCryptSetPropertyBytes(handle as ptr, property as wstr, value as bytes, valueLength as u32, flags as u32) from "bcrypt.dll" symbol "BCryptSetProperty" returns i32
extern function BCryptGenerateSymmetricKey(handle as ptr, result as bytes, keyObject as ptr, keyObjectLength as u32, secret as ptr, secretLength as u32, flags as u32) from "bcrypt.dll" returns i32
extern function BCryptDestroyKey(handle as ptr) from "bcrypt.dll" returns i32
extern function BCryptEncrypt(key as ptr, input as ptr, inputLength as u32, paddingInfo as ptr, iv as ptr, ivLength as u32, output as ptr, outputLength as u32, resultLength as bytes, flags as u32) from "bcrypt.dll" returns i32
extern function BCryptDecrypt(key as ptr, input as ptr, inputLength as u32, paddingInfo as ptr, iv as ptr, ivLength as u32, output as ptr, outputLength as u32, resultLength as bytes, flags as u32) from "bcrypt.dll" returns i32
extern function BCryptKeyDerivation(key as ptr, parameters as ptr, output as ptr, outputLength as u32, resultLength as bytes, flags as u32) from "bcrypt.dll" returns i32
extern function BCryptImportKeyPair(algorithm as ptr, importKey as ptr, blobType as wstr, result as bytes, input as ptr, inputLength as u32, flags as u32) from "bcrypt.dll" returns i32
extern function BCryptExportKey(key as ptr, exportKey as ptr, blobType as wstr, output as ptr, outputLength as u32, resultLength as bytes, flags as u32) from "bcrypt.dll" returns i32
extern function BCryptSecretAgreement(privateKey as ptr, publicKey as ptr, result as bytes, flags as u32) from "bcrypt.dll" returns i32
extern function BCryptDeriveKey(secret as ptr, kdf as wstr, parameters as ptr, output as ptr, outputLength as u32, resultLength as bytes, flags as u32) from "bcrypt.dll" returns i32
extern function BCryptDestroySecret(secret as ptr) from "bcrypt.dll" returns i32

const BCRYPT_ALG_HANDLE_HMAC_FLAG = 0x00000008
const BCRYPT_USE_SYSTEM_PREFERRED_RNG = 0x00000002
const BCRYPT_KDF_HKDF_INFO = 0x14
const BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC = 0x504B4345
const BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC = 0x564B4345

// Encode a low 64-bit native address into a C structure.
function _putPtr(buffer, offset, value)
  for i = 0 to 7
    buffer[offset + i] = (value >> (i * 8)) & 0xFF
  end for
end function

function _putU32(buffer, offset, value)
  buffer[offset] = value & 0xFF
  buffer[offset + 1] = (value >> 8) & 0xFF
  buffer[offset + 2] = (value >> 16) & 0xFF
  buffer[offset + 3] = (value >> 24) & 0xFF
end function

function _getPtr(buffer)
  value = 0
  for i = 0 to 7
    value = value | (buffer[i] << (i * 8))
  end for
  return value
end function

function _getU32(buffer)
  return buffer[0] | (buffer[1] << 8) | (buffer[2] << 16) | (buffer[3] << 24)
end function

function _zero(buffer)
  if typeof(buffer) == "bytes" and len(buffer) > 0 then
    fillBytes(buffer, 0, len(buffer), 0)
  end if
end function

// Run SHA-2 or HMAC-SHA-2 through the BCrypt one-shot hash API.
function hash(algorithm, key, input, output)
  providerBytes = bytes(8, 0)
  flags = 0
  secretPtr = 0
  secretLength = 0
  if typeof(key) == "bytes" then
    flags = BCRYPT_ALG_HANDLE_HMAC_FLAG
    secretPtr = nativeBytesPtr(key)
    secretLength = len(key)
  end if

  status = BCryptOpenAlgorithmProvider(providerBytes, algorithm, 0, flags)
  provider = _getPtr(providerBytes)
  ok = status == 0 and provider != 0
  if ok then
    status = BCryptHash(provider, secretPtr, secretLength, nativeBytesPtr(input), len(input), nativeBytesPtr(output), len(output))
    ok = status == 0
  end if
  if provider != 0 then BCryptCloseAlgorithmProvider(provider, 0) end if
  _zero(providerBytes)
  if not ok then _zero(output) end if
  return ok
end function

// Fill output with bytes from the system-preferred CNG random provider.
function random(output)
  if len(output) == 0 then return true end if
  status = BCryptGenRandom(0, nativeBytesPtr(output), len(output), BCRYPT_USE_SYSTEM_PREFERRED_RNG)
  if status != 0 then _zero(output) end if
  return status == 0
end function

// Derive HKDF output using the native CNG HKDF provider.
function hkdf(hashAlgorithm, digestLength, inputKeyMaterial, salt, info, output)
  providerBytes = bytes(8, 0)
  keyBytes = bytes(8, 0)
  resultLength = bytes(4, 0)
  parameter = bytes(16, 0)
  descriptor = bytes(16, 0)
  effectiveSalt = salt
  if len(effectiveSalt) == 0 then effectiveSalt = bytes(digestLength, 0) end if

  status = BCryptOpenAlgorithmProvider(providerBytes, "HKDF", 0, 0)
  provider = _getPtr(providerBytes)
  keyHandle = 0
  ok = status == 0 and provider != 0
  if ok then
    status = BCryptGenerateSymmetricKey(provider, keyBytes, 0, 0, nativeBytesPtr(inputKeyMaterial), len(inputKeyMaterial), 0)
    keyHandle = _getPtr(keyBytes)
    ok = status == 0 and keyHandle != 0
  end if
  if ok then
    status = BCryptSetPropertyW(keyHandle, "HkdfHashAlgorithm", hashAlgorithm, (len(hashAlgorithm) + 1) * 2, 0)
    ok = status == 0
  end if
  if ok then
    status = BCryptSetPropertyBytes(keyHandle, "HkdfSaltAndFinalize", effectiveSalt, len(effectiveSalt), 0)
    ok = status == 0
  end if

  parametersPtr = 0
  if ok and len(info) > 0 then
    _putU32(parameter, 0, len(info))
    _putU32(parameter, 4, BCRYPT_KDF_HKDF_INFO)
    _putPtr(parameter, 8, nativeBytesPtr(info))
    _putU32(descriptor, 0, 0)
    _putU32(descriptor, 4, 1)
    _putPtr(descriptor, 8, nativeBytesPtr(parameter))
    parametersPtr = nativeBytesPtr(descriptor)
  end if
  if ok and len(output) > 0 then
    status = BCryptKeyDerivation(keyHandle, parametersPtr, nativeBytesPtr(output), len(output), resultLength, 0)
    ok = status == 0 and _getU32(resultLength) == len(output)
  end if

  if keyHandle != 0 then BCryptDestroyKey(keyHandle) end if
  if provider != 0 then BCryptCloseAlgorithmProvider(provider, 0) end if
  _zero(providerBytes)
  _zero(keyBytes)
  _zero(resultLength)
  _zero(parameter)
  _zero(descriptor)
  if effectiveSalt != salt then _zero(effectiveSalt) end if
  if not ok then _zero(output) end if
  return ok
end function

// Encrypt/decrypt one AES-GCM message.  For encryption input is plaintext and
// output is ciphertext||tag.  For decryption input is ciphertext||tag and
// output is plaintext.  CNG authenticates before this function reports success.
function aesGcm(encrypting, key, nonce, aad, input, output, tagLength)
  providerBytes = bytes(8, 0)
  keyBytes = bytes(8, 0)
  resultLength = bytes(4, 0)
  authInfo = bytes(88, 0)

  status = BCryptOpenAlgorithmProvider(providerBytes, "AES", 0, 0)
  provider = _getPtr(providerBytes)
  keyHandle = 0
  ok = status == 0 and provider != 0
  if ok then
    status = BCryptSetPropertyW(provider, "ChainingMode", "ChainingModeGCM", 32, 0)
    ok = status == 0
  end if
  if ok then
    status = BCryptGenerateSymmetricKey(provider, keyBytes, 0, 0, nativeBytesPtr(key), len(key), 0)
    keyHandle = _getPtr(keyBytes)
    ok = status == 0 and keyHandle != 0
  end if

  payloadLength = len(input)
  tagPtr = 0
  if encrypting then
    tagPtr = nativeBytesPtr(output) + payloadLength
  else
    payloadLength = len(input) - tagLength
    tagPtr = nativeBytesPtr(input) + payloadLength
  end if
  _putU32(authInfo, 0, 88)
  _putU32(authInfo, 4, 1)
  _putPtr(authInfo, 8, nativeBytesPtr(nonce))
  _putU32(authInfo, 16, len(nonce))
  if len(aad) > 0 then _putPtr(authInfo, 24, nativeBytesPtr(aad)) end if
  _putU32(authInfo, 32, len(aad))
  _putPtr(authInfo, 40, tagPtr)
  _putU32(authInfo, 48, tagLength)

  if ok and encrypting then
    status = BCryptEncrypt(keyHandle, nativeBytesPtr(input), payloadLength, nativeBytesPtr(authInfo), 0, 0, nativeBytesPtr(output), payloadLength, resultLength, 0)
    ok = status == 0 and _getU32(resultLength) == payloadLength
  end if
  if ok and not encrypting then
    status = BCryptDecrypt(keyHandle, nativeBytesPtr(input), payloadLength, nativeBytesPtr(authInfo), 0, 0, nativeBytesPtr(output), payloadLength, resultLength, 0)
    ok = status == 0 and _getU32(resultLength) == payloadLength
  end if

  if keyHandle != 0 then BCryptDestroyKey(keyHandle) end if
  if provider != 0 then BCryptCloseAlgorithmProvider(provider, 0) end if
  _zero(providerBytes)
  _zero(keyBytes)
  _zero(resultLength)
  _zero(authInfo)
  if not ok then _zero(output) end if
  return ok
end function

function _openX25519(providerBytes)
  status = BCryptOpenAlgorithmProvider(providerBytes, "ECDH", 0, 0)
  provider = _getPtr(providerBytes)
  if status != 0 or provider == 0 then return 0 end if
  status = BCryptSetPropertyW(provider, "ECCCurveName", "curve25519", 22, 0)
  if status != 0 then
    BCryptCloseAlgorithmProvider(provider, 0)
    return 0
  end if
  return provider
end function

function _makeX25519PrivateBlob(privateKey)
  blob = bytes(104, 0)
  _putU32(blob, 0, BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC)
  _putU32(blob, 4, 32)
  copyBytes(blob, 72, privateKey, 0, 32)
  // CNG consumes the clamped DivHTimesH representation.
  blob[72] = blob[72] & 248
  blob[103] = (blob[103] & 127) | 64
  return blob
end function

function _makeX25519PublicBlob(publicKey)
  blob = bytes(72, 0)
  _putU32(blob, 0, BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC)
  _putU32(blob, 4, 32)
  copyBytes(blob, 8, publicKey, 0, 32)
  return blob
end function

// Derive an RFC-7748 public key from a 32-byte private scalar.
function x25519Public(privateKey, output)
  providerBytes = bytes(8, 0)
  privateHandleBytes = bytes(8, 0)
  resultLength = bytes(4, 0)
  privateBlob = _makeX25519PrivateBlob(privateKey)
  publicBlob = bytes(72, 0)
  provider = _openX25519(providerBytes)
  privateHandle = 0
  ok = provider != 0
  if ok then
    status = BCryptImportKeyPair(provider, 0, "ECCPRIVATEBLOB", privateHandleBytes, nativeBytesPtr(privateBlob), len(privateBlob), 0)
    privateHandle = _getPtr(privateHandleBytes)
    ok = status == 0 and privateHandle != 0
  end if
  if ok then
    status = BCryptExportKey(privateHandle, 0, "ECCPUBLICBLOB", nativeBytesPtr(publicBlob), len(publicBlob), resultLength, 0)
    ok = status == 0 and _getU32(resultLength) >= 40
  end if
  if ok then copyBytes(output, 0, publicBlob, 8, 32) end if
  if privateHandle != 0 then BCryptDestroyKey(privateHandle) end if
  if provider != 0 then BCryptCloseAlgorithmProvider(provider, 0) end if
  _zero(providerBytes)
  _zero(privateHandleBytes)
  _zero(resultLength)
  _zero(privateBlob)
  _zero(publicBlob)
  if not ok then _zero(output) end if
  return ok
end function

// Perform RFC-7748 X25519 and reject all-zero shared secrets.
function x25519(privateKey, publicKey, output)
  providerBytes = bytes(8, 0)
  privateHandleBytes = bytes(8, 0)
  publicHandleBytes = bytes(8, 0)
  secretHandleBytes = bytes(8, 0)
  resultLength = bytes(4, 0)
  privateBlob = _makeX25519PrivateBlob(privateKey)
  publicBlob = _makeX25519PublicBlob(publicKey)
  provider = _openX25519(providerBytes)
  privateHandle = 0
  publicHandle = 0
  secretHandle = 0
  ok = provider != 0
  if ok then
    status = BCryptImportKeyPair(provider, 0, "ECCPRIVATEBLOB", privateHandleBytes, nativeBytesPtr(privateBlob), len(privateBlob), 0)
    privateHandle = _getPtr(privateHandleBytes)
    ok = status == 0 and privateHandle != 0
  end if
  if ok then
    status = BCryptImportKeyPair(provider, 0, "ECCPUBLICBLOB", publicHandleBytes, nativeBytesPtr(publicBlob), len(publicBlob), 0)
    publicHandle = _getPtr(publicHandleBytes)
    ok = status == 0 and publicHandle != 0
  end if
  if ok then
    status = BCryptSecretAgreement(privateHandle, publicHandle, secretHandleBytes, 0)
    secretHandle = _getPtr(secretHandleBytes)
    ok = status == 0 and secretHandle != 0
  end if
  if ok then
    status = BCryptDeriveKey(secretHandle, "TRUNCATE", 0, nativeBytesPtr(output), len(output), resultLength, 0)
    ok = status == 0 and _getU32(resultLength) == 32
    if ok then
      // BCrypt's raw-secret KDF exports the integer in the opposite byte
      // order from RFC 7748.  Convert only the representation; the scalar
      // multiplication itself remains entirely inside CNG.
      for i = 0 to 15
        j = 31 - i
        tmp = output[i]
        output[i] = output[j]
        output[j] = tmp
      end for
    end if
  end if

  if secretHandle != 0 then BCryptDestroySecret(secretHandle) end if
  if publicHandle != 0 then BCryptDestroyKey(publicHandle) end if
  if privateHandle != 0 then BCryptDestroyKey(privateHandle) end if
  if provider != 0 then BCryptCloseAlgorithmProvider(provider, 0) end if
  _zero(providerBytes)
  _zero(privateHandleBytes)
  _zero(publicHandleBytes)
  _zero(secretHandleBytes)
  _zero(resultLength)
  _zero(privateBlob)
  _zero(publicBlob)
  if not ok then _zero(output) end if
  return ok
end function
