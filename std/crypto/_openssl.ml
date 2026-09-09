/*
Copyright 2026 Nils Kopal

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Internal OpenSSL 3 bridge for the public std.crypto modules on Linux.
//! Provides the std crypto _openssl package.

package std.crypto._openssl

/// Track the evp ctrl gcm set ivlen value used by this standard-library module.
/// @internal
const EVP_CTRL_GCM_SET_IVLEN = 0x09
/// Track the evp ctrl gcm get tag value used by this standard-library module.
/// @internal
const EVP_CTRL_GCM_GET_TAG = 0x10
/// Track the evp ctrl gcm set tag value used by this standard-library module.
/// @internal
const EVP_CTRL_GCM_SET_TAG = 0x11
/// Track the evp pkey x25519 value used by this standard-library module.
/// @internal
const EVP_PKEY_X25519 = 1034
/// OpenSSL numeric identifier for the NIST P-256 curve.
/// @internal
const NID_X9_62_PRIME256V1 = 415

/// Provide the sha256 operation for this standard-library module.
/// @internal
extern function _sha256(input as ptr, length as u64, output as ptr) from "libcrypto.so.3" symbol "SHA256" returns ptr
/// Provide the sha384 operation for this standard-library module.
/// @internal
extern function _sha384(input as ptr, length as u64, output as ptr) from "libcrypto.so.3" symbol "SHA384" returns ptr
/// Provide the evp sha256 operation for this standard-library module.
/// @internal
extern function _evpSha256() from "libcrypto.so.3" symbol "EVP_sha256" returns ptr
/// Provide the evp sha384 operation for this standard-library module.
/// @internal
extern function _evpSha384() from "libcrypto.so.3" symbol "EVP_sha384" returns ptr
/// Provide the hmac operation for this standard-library module.
/// @internal
extern function _hmac(digest as ptr, key as ptr, keyLength as int, input as ptr, inputLength as u64, output as ptr, outputLength as bytes) from "libcrypto.so.3" symbol "HMAC" returns ptr
/// Provide the random operation for this standard-library module.
/// @internal
extern function _random(output as ptr, length as int) from "libcrypto.so.3" symbol "RAND_bytes" returns i32
/// Provide the native pbkdf2 operation for this standard-library module.
/// @internal
extern function _nativePbkdf2(password as ptr, passwordLength as int, salt as ptr, saltLength as int, iterations as int, digest as ptr, outputLength as int, output as ptr) from "libcrypto.so.3" symbol "PKCS5_PBKDF2_HMAC" returns i32

/// Provide the cipher context new operation for this standard-library module.
/// @internal
extern function _cipherContextNew() from "libcrypto.so.3" symbol "EVP_CIPHER_CTX_new" returns ptr
/// Provide the cipher context free operation for this standard-library module.
/// @internal
extern function _cipherContextFree(context as ptr) from "libcrypto.so.3" symbol "EVP_CIPHER_CTX_free" returns void
/// Provide the aes256 gcm operation for this standard-library module.
/// @internal
extern function _aes256Gcm() from "libcrypto.so.3" symbol "EVP_aes_256_gcm" returns ptr
/// Provide the encrypt init operation for this standard-library module.
/// @internal
extern function _encryptInit(context as ptr, cipher as ptr, implementation as ptr, key as ptr, iv as ptr) from "libcrypto.so.3" symbol "EVP_EncryptInit_ex" returns i32
/// Provide the encrypt update operation for this standard-library module.
/// @internal
extern function _encryptUpdate(context as ptr, output as ptr, outputLength as bytes, input as ptr, inputLength as int) from "libcrypto.so.3" symbol "EVP_EncryptUpdate" returns i32
/// Provide the encrypt final operation for this standard-library module.
/// @internal
extern function _encryptFinal(context as ptr, output as ptr, outputLength as bytes) from "libcrypto.so.3" symbol "EVP_EncryptFinal_ex" returns i32
/// Provide the decrypt init operation for this standard-library module.
/// @internal
extern function _decryptInit(context as ptr, cipher as ptr, implementation as ptr, key as ptr, iv as ptr) from "libcrypto.so.3" symbol "EVP_DecryptInit_ex" returns i32
/// Provide the decrypt update operation for this standard-library module.
/// @internal
extern function _decryptUpdate(context as ptr, output as ptr, outputLength as bytes, input as ptr, inputLength as int) from "libcrypto.so.3" symbol "EVP_DecryptUpdate" returns i32
/// Provide the decrypt final operation for this standard-library module.
/// @internal
extern function _decryptFinal(context as ptr, output as ptr, outputLength as bytes) from "libcrypto.so.3" symbol "EVP_DecryptFinal_ex" returns i32
/// Provide the cipher control operation for this standard-library module.
/// @internal
extern function _cipherControl(context as ptr, operation as int, argument as int, data as ptr) from "libcrypto.so.3" symbol "EVP_CIPHER_CTX_ctrl" returns i32

/// Creates new raw private key.
/// @internal
extern function _newRawPrivateKey(kind as int, engine as ptr, key as ptr, keyLength as u64) from "libcrypto.so.3" symbol "EVP_PKEY_new_raw_private_key" returns ptr
/// Creates new raw public key.
/// @internal
extern function _newRawPublicKey(kind as int, engine as ptr, key as ptr, keyLength as u64) from "libcrypto.so.3" symbol "EVP_PKEY_new_raw_public_key" returns ptr
/// Returns get raw public key.
/// @internal
extern function _getRawPublicKey(key as ptr, output as ptr, outputLength as bytes) from "libcrypto.so.3" symbol "EVP_PKEY_get_raw_public_key" returns i32
/// Provide the key free operation for this standard-library module.
/// @internal
extern function _keyFree(key as ptr) from "libcrypto.so.3" symbol "EVP_PKEY_free" returns void
/// Provide the derive context new operation for this standard-library module.
/// @internal
extern function _deriveContextNew(key as ptr, engine as ptr) from "libcrypto.so.3" symbol "EVP_PKEY_CTX_new" returns ptr
/// Provide the derive context free operation for this standard-library module.
/// @internal
extern function _deriveContextFree(context as ptr) from "libcrypto.so.3" symbol "EVP_PKEY_CTX_free" returns void
/// Provide the derive init operation for this standard-library module.
/// @internal
extern function _deriveInit(context as ptr) from "libcrypto.so.3" symbol "EVP_PKEY_derive_init" returns i32
/// Provide the derive set peer operation for this standard-library module.
/// @internal
extern function _deriveSetPeer(context as ptr, peer as ptr) from "libcrypto.so.3" symbol "EVP_PKEY_derive_set_peer" returns i32
/// Provide the derive operation for this standard-library module.
/// @internal
extern function _derive(context as ptr, output as ptr, outputLength as bytes) from "libcrypto.so.3" symbol "EVP_PKEY_derive" returns i32

/// Create an EC key for a named curve.
/// @internal
extern function _ecKeyNewByCurveName(nid as int) from "libcrypto.so.3" symbol "EC_KEY_new_by_curve_name" returns ptr
/// Release an EC key.
/// @internal
extern function _ecKeyFree(key as ptr) from "libcrypto.so.3" symbol "EC_KEY_free" returns void
/// Return the immutable group associated with an EC key.
/// @internal
extern function _ecKeyGetGroup(key as ptr) from "libcrypto.so.3" symbol "EC_KEY_get0_group" returns ptr
/// Set an EC public point on a key.
/// @internal
extern function _ecKeySetPublicKey(key as ptr, point as ptr) from "libcrypto.so.3" symbol "EC_KEY_set_public_key" returns i32
/// Allocate a point in an EC group.
/// @internal
extern function _ecPointNew(group as ptr) from "libcrypto.so.3" symbol "EC_POINT_new" returns ptr
/// Release an EC point.
/// @internal
extern function _ecPointFree(point as ptr) from "libcrypto.so.3" symbol "EC_POINT_free" returns void
/// Decode an SEC1 point octet string.
/// @internal
extern function _ecPointOct2Point(group as ptr, point as ptr, input as ptr, inputLength as u64, context as ptr) from "libcrypto.so.3" symbol "EC_POINT_oct2point" returns i32
/// Allocate an ECDSA signature value.
/// @internal
extern function _ecdsaSigNew() from "libcrypto.so.3" symbol "ECDSA_SIG_new" returns ptr
/// Release an ECDSA signature value.
/// @internal
extern function _ecdsaSigFree(signature as ptr) from "libcrypto.so.3" symbol "ECDSA_SIG_free" returns void
/// Transfer r and s into an ECDSA signature value.
/// @internal
extern function _ecdsaSigSet0(signature as ptr, r as ptr, s as ptr) from "libcrypto.so.3" symbol "ECDSA_SIG_set0" returns i32
/// Parse a big-endian unsigned integer.
/// @internal
extern function _bnBin2Bn(input as ptr, inputLength as int, result as ptr) from "libcrypto.so.3" symbol "BN_bin2bn" returns ptr
/// Release a big number that has not been transferred to another object.
/// @internal
extern function _bnFree(value as ptr) from "libcrypto.so.3" symbol "BN_free" returns void
/// Verify an ECDSA signature over a caller-supplied digest.
/// @internal
extern function _ecdsaDoVerify(digest as ptr, digestLength as int, signature as ptr, key as ptr) from "libcrypto.so.3" symbol "ECDSA_do_verify" returns i32

/// Provide the put u64 operation for this standard-library module.
/// @internal
function _putU64(buffer, value)
  i = 0
  while i < 8
    buffer[i] = (value >> (i * 8)) & 0xFF
    i = i + 1
  end while
end function

/// Returns get u32.
/// @internal
function _getU32(buffer)
  return buffer[0] | (buffer[1] << 8) | (buffer[2] << 16) | (buffer[3] << 24)
end function

/// Provide the zero operation for this standard-library module.
/// @internal
function _zero(buffer)
  if typeof(buffer) == "bytes" and len(buffer) > 0 then fillBytes(buffer, 0, len(buffer), 0) end if
end function

/// Provide the digest operation for this standard-library module.
/// @internal
function _digest(algorithm)
  if algorithm == "SHA256" then return _evpSha256() end if
  if algorithm == "SHA384" then return _evpSha384() end if
  return 0
end function

/// Reports whether hash.
/// @internal
function hash(algorithm, key, input, output)
  if typeof(key) == "bytes" then
    outputLength = bytes(4, 0)
    result = _hmac(_digest(algorithm), nativeBytesPtr(key), len(key), nativeBytesPtr(input), len(input), nativeBytesPtr(output), outputLength)
    ok = result != 0 and _getU32(outputLength) == len(output)
    _zero(outputLength)
    if not ok then _zero(output) end if
    return ok
  end if

  result = 0
  if algorithm == "SHA256" then result = _sha256(nativeBytesPtr(input), len(input), nativeBytesPtr(output)) end if
  if algorithm == "SHA384" then result = _sha384(nativeBytesPtr(input), len(input), nativeBytesPtr(output)) end if
  if result == 0 then _zero(output) end if
  return result != 0
end function

/// Provide the random operation for this standard-library module.
/// @internal
function random(output)
  if len(output) == 0 then return true end if
  ok = _random(nativeBytesPtr(output), len(output)) == 1
  if not ok then _zero(output) end if
  return ok
end function

/// Derive PBKDF2 output through OpenSSL's constant-time HMAC implementation.
/// @internal
function pbkdf2(hashAlgorithm, password, salt, iterations, output)
  digest = _digest(hashAlgorithm)
  if digest == 0 then return false end if
  ok = true
  if len(output) > 0 then
    ok = _nativePbkdf2(nativeBytesPtr(password), len(password), nativeBytesPtr(salt), len(salt), iterations, digest, len(output), nativeBytesPtr(output)) == 1
  end if
  if not ok then _zero(output) end if
  return ok
end function

/// RFC-5869 extract-and-expand using OpenSSL's HMAC primitive.
/// @internal
function hkdf(hashAlgorithm, digestLength, inputKeyMaterial, salt, info, output)
  effectiveSalt = salt
  if len(effectiveSalt) == 0 then effectiveSalt = bytes(digestLength, 0) end if
  pseudorandomKey = bytes(digestLength, 0)
  if not hash(hashAlgorithm, effectiveSalt, inputKeyMaterial, pseudorandomKey) then return false end if

  previous = bytes(0)
  position = 0
  counter = 1
  ok = true
  while position < len(output) and ok
    blockInput = previous + info + bytes(1, counter)
    block = bytes(digestLength, 0)
    ok = hash(hashAlgorithm, pseudorandomKey, blockInput, block)
    if ok then
      amount = len(output) - position
      if amount > digestLength then amount = digestLength end if
      copyBytes(output, position, block, 0, amount)
      position = position + amount
      previous = block
      counter = counter + 1
    end if
    _zero(blockInput)
  end while
  _zero(pseudorandomKey)
  _zero(previous)
  if effectiveSalt != salt then _zero(effectiveSalt) end if
  if not ok then _zero(output) end if
  return ok
end function

/// Provide the aes gcm operation for this standard-library module.
/// @internal
function aesGcm(encrypting, key, nonce, aad, input, output, tagLength)
  context = _cipherContextNew()
  if context == 0 then return false end if
  outputLength = bytes(4, 0)
  finalLength = bytes(4, 0)
  payloadLength = len(input)
  if not encrypting then payloadLength = payloadLength - tagLength end if
  ok = true

  if encrypting then
    ok = _encryptInit(context, _aes256Gcm(), 0, 0, 0) == 1
    if ok then ok = _cipherControl(context, EVP_CTRL_GCM_SET_IVLEN, len(nonce), 0) == 1 end if
    if ok then ok = _encryptInit(context, 0, 0, nativeBytesPtr(key), nativeBytesPtr(nonce)) == 1 end if
    if ok and len(aad) > 0 then ok = _encryptUpdate(context, 0, outputLength, nativeBytesPtr(aad), len(aad)) == 1 end if
    if ok and payloadLength > 0 then ok = _encryptUpdate(context, nativeBytesPtr(output), outputLength, nativeBytesPtr(input), payloadLength) == 1 end if
    produced = _getU32(outputLength)
    if ok then ok = _encryptFinal(context, nativeBytesPtr(output) + produced, finalLength) == 1 end if
    if ok then ok = _cipherControl(context, EVP_CTRL_GCM_GET_TAG, tagLength, nativeBytesPtr(output) + payloadLength) == 1 end if
  else
    ok = _decryptInit(context, _aes256Gcm(), 0, 0, 0) == 1
    if ok then ok = _cipherControl(context, EVP_CTRL_GCM_SET_IVLEN, len(nonce), 0) == 1 end if
    if ok then ok = _decryptInit(context, 0, 0, nativeBytesPtr(key), nativeBytesPtr(nonce)) == 1 end if
    if ok and len(aad) > 0 then ok = _decryptUpdate(context, 0, outputLength, nativeBytesPtr(aad), len(aad)) == 1 end if
    if ok and payloadLength > 0 then ok = _decryptUpdate(context, nativeBytesPtr(output), outputLength, nativeBytesPtr(input), payloadLength) == 1 end if
    produced = _getU32(outputLength)
    if ok then ok = _cipherControl(context, EVP_CTRL_GCM_SET_TAG, tagLength, nativeBytesPtr(input) + payloadLength) == 1 end if
    if ok then ok = _decryptFinal(context, nativeBytesPtr(output) + produced, finalLength) == 1 end if
  end if

  _cipherContextFree(context)
  _zero(outputLength)
  _zero(finalLength)
  if not ok then _zero(output) end if
  return ok
end function

/// Provide the x25519 public operation for this standard-library module.
/// @internal
function x25519Public(privateKey, output)
  key = _newRawPrivateKey(EVP_PKEY_X25519, 0, nativeBytesPtr(privateKey), len(privateKey))
  if key == 0 then return false end if
  outputLength = bytes(8, 0)
  _putU64(outputLength, len(output))
  ok = _getRawPublicKey(key, nativeBytesPtr(output), outputLength) == 1
  _keyFree(key)
  _zero(outputLength)
  if not ok then _zero(output) end if
  return ok
end function

/// Provide the x25519 operation for this standard-library module.
/// @internal
function x25519(privateKey, publicKey, output)
  privateHandle = _newRawPrivateKey(EVP_PKEY_X25519, 0, nativeBytesPtr(privateKey), len(privateKey))
  publicHandle = _newRawPublicKey(EVP_PKEY_X25519, 0, nativeBytesPtr(publicKey), len(publicKey))
  context = 0
  ok = privateHandle != 0 and publicHandle != 0
  if ok then
    context = _deriveContextNew(privateHandle, 0)
    ok = context != 0
  end if
  if ok then ok = _deriveInit(context) == 1 end if
  if ok then ok = _deriveSetPeer(context, publicHandle) == 1 end if
  outputLength = bytes(8, 0)
  _putU64(outputLength, len(output))
  if ok then ok = _derive(context, nativeBytesPtr(output), outputLength) == 1 end if
  if context != 0 then _deriveContextFree(context) end if
  if publicHandle != 0 then _keyFree(publicHandle) end if
  if privateHandle != 0 then _keyFree(privateHandle) end if
  _zero(outputLength)
  if not ok then _zero(output) end if
  return ok
end function

/// Verify a raw IEEE-P1363 ECDSA-P256 signature over a SHA-256 digest.
/// @internal
function ecdsaP256Verify(publicKey, digest, signature)
  key = _ecKeyNewByCurveName(NID_X9_62_PRIME256V1)
  group = 0
  point = 0
  nativeSignature = 0
  r = 0
  s = 0
  transferred = false
  ok = key != 0

  encodedPoint = bytes(65, 0)
  encodedPoint[0] = 4
  copyBytes(encodedPoint, 1, publicKey, 0, 64)
  if ok then
    group = _ecKeyGetGroup(key)
    point = _ecPointNew(group)
    ok = group != 0 and point != 0
  end if
  if ok then ok = _ecPointOct2Point(group, point, nativeBytesPtr(encodedPoint), len(encodedPoint), 0) == 1 end if
  if ok then ok = _ecKeySetPublicKey(key, point) == 1 end if
  if ok then
    nativeSignature = _ecdsaSigNew()
    r = _bnBin2Bn(nativeBytesPtr(signature), 32, 0)
    s = _bnBin2Bn(nativeBytesPtr(signature) + 32, 32, 0)
    ok = nativeSignature != 0 and r != 0 and s != 0
  end if
  if ok then
    transferred = _ecdsaSigSet0(nativeSignature, r, s) == 1
    ok = transferred
  end if
  if ok then ok = _ecdsaDoVerify(nativeBytesPtr(digest), len(digest), nativeSignature, key) == 1 end if

  if not transferred then
    if r != 0 then _bnFree(r) end if
    if s != 0 then _bnFree(s) end if
  end if
  if nativeSignature != 0 then _ecdsaSigFree(nativeSignature) end if
  if point != 0 then _ecPointFree(point) end if
  if key != 0 then _ecKeyFree(key) end if
  _zero(encodedPoint)
  return ok
end function
