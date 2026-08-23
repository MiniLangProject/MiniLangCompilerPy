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

import std.assert as t
import std.crypto as crypto
import std.crypto.aes_gcm as gcm
import std.encoding.hex as hex

function h(value)
  return hex.decode(value)
end function

function changedCopy(value, offset)
  output = slice(value, 0, len(value))
  output[offset] = output[offset] ^ 1
  return output
end function

function main(args)
  t.assertEq(crypto.sha256(bytes(0)), h("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), "SHA-256 empty")
  t.assertEq(crypto.sha256(bytes("abc")), h("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"), "SHA-256 abc")
  t.assertEq(crypto.sha384(bytes("abc")), h("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"), "SHA-384 abc")
  millionA = bytes(1000000, 97)
  t.assertEq(crypto.sha256(millionA), h("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"), "SHA-256 million a")
  t.assertEq(crypto.sha384(millionA), h("9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985"), "SHA-384 million a")

  hmacKey = bytes(20, 0x0B)
  hmacData = bytes("Hi There")
  t.assertEq(crypto.hmacSha256(hmacKey, hmacData), h("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"), "HMAC-SHA-256 RFC 4231")
  t.assertEq(crypto.hmacSha384(hmacKey, hmacData), h("afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"), "HMAC-SHA-384 RFC 4231")

  ikm = bytes(22, 0x0B)
  salt = h("000102030405060708090a0b0c")
  info = h("f0f1f2f3f4f5f6f7f8f9")
  t.assertEq(crypto.hkdfSha256(ikm, salt, info, 42), h("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"), "HKDF-SHA-256 RFC 5869")
  t.assertEq(crypto.hkdfSha384(ikm, salt, info, 42), h("9b5097a86038b805309076a44b3a9f38063e25b516dcbf369f394cfab43685f748b6457763e4f0204fc5"), "HKDF-SHA-384 vector")

  key = bytes(32, 0)
  nonce = bytes(12, 0)
  plaintext = bytes(16, 0)
  sealed = gcm.seal(key, nonce, plaintext, bytes(0), 16)
  t.assertEq(sealed, h("cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"), "AES-256-GCM NIST vector")
  t.assertEq(gcm.open(key, nonce, sealed, bytes(0), 16), plaintext, "AES-256-GCM decrypt")
  t.assertEq(gcm.seal(key, nonce, bytes(0), bytes(0), 16), h("530f8afbc74536b9a963b4f1c4cb738b"), "AES-256-GCM empty")

  aad = bytes("authenticated metadata")
  message = bytes("MiniLang CNG AES-GCM")
  sealed12 = gcm.seal(key, nonce, message, aad, 12)
  t.assertEq(gcm.open(key, nonce, sealed12, aad, 12), message, "AES-256-GCM 96-bit tag")
  t.assertEq(typeof(try(gcm.open(key, nonce, changedCopy(sealed12, 0), aad, 12))), "error", "AES-GCM rejects ciphertext tamper")
  t.assertEq(typeof(try(gcm.open(key, nonce, changedCopy(sealed12, len(sealed12) - 1), aad, 12))), "error", "AES-GCM rejects tag tamper")
  t.assertEq(typeof(try(gcm.open(key, nonce, sealed12, changedCopy(aad, 0), 12))), "error", "AES-GCM rejects AAD tamper")
  t.assertEq(typeof(try(gcm.open(changedCopy(key, 0), nonce, sealed12, aad, 12))), "error", "AES-GCM rejects wrong key")
  t.assertEq(typeof(try(gcm.open(key, changedCopy(nonce, 0), sealed12, aad, 12))), "error", "AES-GCM rejects nonce tamper")
  t.assertEq(typeof(try(gcm.seal(bytes(31), nonce, message, aad, 16))), "error", "AES-GCM rejects non-256-bit key")
  t.assertEq(typeof(try(gcm.seal(key, bytes(11), message, aad, 16))), "error", "AES-GCM rejects short nonce")
  t.assertEq(typeof(try(gcm.seal(key, nonce, message, aad, 11))), "error", "AES-GCM rejects short tag")
  largePlaintext = bytes(1048576, 0x6D)
  largeSealed = gcm.seal(key, nonce, largePlaintext, aad, 16)
  t.assertEq(gcm.open(key, nonce, largeSealed, aad, 16), largePlaintext, "AES-256-GCM large roundtrip")

  alicePrivate = h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
  alicePublic = h("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
  bobPrivate = h("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
  bobPublic = h("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
  expectedSecret = h("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
  t.assertEq(crypto.x25519PublicKey(alicePrivate), alicePublic, "X25519 Alice public RFC 7748")
  t.assertEq(crypto.x25519PublicKey(bobPrivate), bobPublic, "X25519 Bob public RFC 7748")
  aliceSecret = crypto.x25519(alicePrivate, bobPublic)
  bobSecret = crypto.x25519(bobPrivate, alicePublic)
  t.assertEq(aliceSecret, expectedSecret, "X25519 shared secret RFC 7748")
  t.assertEq(bobSecret, expectedSecret, "X25519 reciprocal secret")
  t.assertEq(typeof(try(crypto.x25519(alicePrivate, bytes(32, 0)))), "error", "X25519 rejects weak input")

  t.assertTrue(crypto.constantTimeEquals(bytes("same"), bytes("same")), "constant-time equal")
  t.assertFalse(crypto.constantTimeEquals(bytes("same"), bytes("diff")), "constant-time different")
  secret = bytes("erase me")
  t.assertTrue(crypto.secureZero(secret), "secure zero result")
  t.assertEq(secret, bytes(8, 0), "secure zero contents")
  random = crypto.secureRandom(64)
  t.assertEq(len(random), 64, "secure random length")
  t.assertFalse(crypto.constantTimeEquals(random, bytes(64, 0)), "secure random nonzero")

  print "[OK] CNG crypto"
end function
