/*
Copyright 2026 Nils Kopal

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Diagnostic, same-machine throughput measurements for crypto and compression.
import std.compress as compression
import std.crypto as crypto
import std.crypto.aes_gcm as aes
import std.crypto.ecdsa_p256 as ecdsa
import std.time as tm

function millis(start)
  elapsed = tm.ticks() - start
  if elapsed < 1 then return 1 end if
  return elapsed
end function

function report(label, bytesPerCall, iterations, elapsed)
  mib = (bytesPerCall * iterations) / 1048576.0
  print label + ": " + elapsed + " ms, " + ((mib * 1000.0) / elapsed) + " MiB/s"
end function

function reportOps(label, iterations, elapsed)
  print label + ": " + elapsed + " ms, " + ((iterations * 1000.0) / elapsed) + " ops/s"
end function

function patterned(n)
  result = bytes(n, 0)
  i = 0
  while i < n
    result[i] = ((i >> 3) + i * 7) & 255
    i = i + 1
  end while
  return result
end function

function randomish(n)
  result = bytes(n, 0)
  state = 0x2468ACE1
  i = 0
  while i < n
    state = (state ^ (state << 13)) & 0xFFFFFFFF
    state = (state ^ (state >> 17)) & 0xFFFFFFFF
    state = (state ^ (state << 5)) & 0xFFFFFFFF
    result[i] = state & 255
    i = i + 1
  end while
  return result
end function

function benchCompression(label, input, iterations)
  decodeIterations = iterations * 32
  start = tm.ticks()
  packed = bytes(0)
  for i = 0 to iterations - 1
    packed = compression.fast(input)
  end for
  elapsed = millis(start)
  if typeof(packed) != "bytes" then return 1 end if
  print label + " fast ratio=" + len(packed) + "/" + len(input)
  report(label + " fast compress", len(input), iterations, elapsed)
  start = tm.ticks()
  decoded = bytes(0)
  for i = 0 to decodeIterations - 1
    decoded = compression.decompress(packed, len(input))
  end for
  elapsed = millis(start)
  if decoded != input then return 1 end if
  report(label + " fast decompress", len(input), decodeIterations, elapsed)

  start = tm.ticks()
  for i = 0 to iterations - 1
    packed = compression.compact(input)
  end for
  elapsed = millis(start)
  if typeof(packed) != "bytes" then return 1 end if
  print label + " compact ratio=" + len(packed) + "/" + len(input) + " algorithm=" + packed[4]
  report(label + " compact compress", len(input), iterations, elapsed)
  start = tm.ticks()
  for i = 0 to decodeIterations - 1
    decoded = compression.decompress(packed, len(input))
  end for
  elapsed = millis(start)
  if decoded != input then return 1 end if
  report(label + " compact decompress", len(input), decodeIterations, elapsed)
  return 0
end function

function main(args)
  small = patterned(1024)
  large = patterned(1024 * 1024)
  key = bytes(32, 0x42)
  nonce = bytes(12, 0)
  aad = bytes(0)
  sealed = bytes(0)
  opened = bytes(0)
  print "MiniLang crypto and compression benchmark"

  start = tm.ticks()
  for i = 0 to 19999
    digest = crypto.sha256(small)
  end for
  report("SHA-256 1 KiB", len(small), 20000, millis(start))
  start = tm.ticks()
  for i = 0 to 255
    digest = crypto.sha256(large)
  end for
  report("SHA-256 1 MiB", len(large), 256, millis(start))
  start = tm.ticks()
  for i = 0 to 255
    digest = crypto.sha384(large)
  end for
  report("SHA-384 1 MiB", len(large), 256, millis(start))
  start = tm.ticks()
  for i = 0 to 19999
    digest = crypto.hmacSha256(key, small)
  end for
  report("HMAC-SHA-256 1 KiB", len(small), 20000, millis(start))
  start = tm.ticks()
  for i = 0 to 19999
    digest = crypto.hmacSha384(key, small)
  end for
  report("HMAC-SHA-384 1 KiB", len(small), 20000, millis(start))
  start = tm.ticks()
  for i = 0 to 19999
    nonce[0] = i & 255
    nonce[1] = (i >> 8) & 255
    sealed = aes.seal(key, nonce, small, aad, 16)
  end for
  report("AES-256-GCM seal 1 KiB", len(small), 20000, millis(start))
  start = tm.ticks()
  for i = 0 to 19999
    opened = aes.open(key, nonce, sealed, aad, 16)
  end for
  if opened != small then return 1 end if
  report("AES-256-GCM open 1 KiB", len(small), 20000, millis(start))
  nonce[2] = 1
  start = tm.ticks()
  for i = 0 to 255
    nonce[0] = i
    sealed = aes.seal(key, nonce, large, aad, 16)
  end for
  report("AES-256-GCM seal 1 MiB", len(large), 256, millis(start))
  start = tm.ticks()
  for i = 0 to 255
    opened = aes.open(key, nonce, sealed, aad, 16)
  end for
  if opened != large then return 1 end if
  report("AES-256-GCM open 1 MiB", len(large), 256, millis(start))
  start = tm.ticks()
  for i = 0 to 255
    random = crypto.secureRandom(1024 * 1024)
  end for
  report("secureRandom 1 MiB", 1024 * 1024, 256, millis(start))
  salt = bytes(16, 0x2A)
  info = bytes("MiniLang KDF benchmark")
  derived = bytes(0)
  start = tm.ticks()
  for i = 0 to 9999
    derived = crypto.hkdfSha256(key, salt, info, 64)
  end for
  if typeof(derived) != "bytes" then return 1 end if
  reportOps("HKDF-SHA-256 64 bytes", 10000, millis(start))
  start = tm.ticks()
  for i = 0 to 9999
    derived = crypto.hkdfSha384(key, salt, info, 64)
  end for
  if typeof(derived) != "bytes" then return 1 end if
  reportOps("HKDF-SHA-384 64 bytes", 10000, millis(start))
  password = bytes("benchmark password")
  start = tm.ticks()
  for i = 0 to 63
    derived = crypto.pbkdf2Sha256(password, salt, 10000, 32)
  end for
  if typeof(derived) != "bytes" then return 1 end if
  reportOps("PBKDF2-SHA-256 10000 rounds", 64, millis(start))
  start = tm.ticks()
  for i = 0 to 63
    derived = crypto.pbkdf2Sha384(password, salt, 10000, 48)
  end for
  if typeof(derived) != "bytes" then return 1 end if
  reportOps("PBKDF2-SHA-384 10000 rounds", 64, millis(start))
  privateKey = fromHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
  peerPublic = fromHex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
  publicKey = bytes(0)
  shared = bytes(0)
  start = tm.ticks()
  for i = 0 to 999
    publicKey = crypto.x25519PublicKey(privateKey)
  end for
  if typeof(publicKey) != "bytes" then return 1 end if
  reportOps("X25519 public key", 1000, millis(start))
  start = tm.ticks()
  for i = 0 to 999
    shared = crypto.x25519(privateKey, peerPublic)
  end for
  if typeof(shared) != "bytes" then return 1 end if
  reportOps("X25519 agreement", 1000, millis(start))
  verifyKey = fromHex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
  verifyMessage = bytes("MiniLang ECDSA-P256 self test")
  signature = fromHex("45ad878ed724d17906f74f08f1c36fa229d12b9d643d3008abeb7d0ff1fccb6c3ad6e38d23b7e94ad8865b73dea449259033a081538418d1fab1005dc712da7f")
  verified = false
  start = tm.ticks()
  for i = 0 to 999
    verified = ecdsa.verify(verifyKey, verifyMessage, signature)
  end for
  if not verified then return 1 end if
  reportOps("ECDSA-P256 verify", 1000, millis(start))
  equal = false
  start = tm.ticks()
  for i = 0 to 255
    equal = crypto.constantTimeEquals(large, large)
  end for
  if not equal then return 1 end if
  report("constantTimeEquals 1 MiB", len(large), 256, millis(start))
  wipe = bytes(1024 * 1024, 0xA5)
  start = tm.ticks()
  for i = 0 to 255
    crypto.secureZero(wipe)
  end for
  report("secureZero 1 MiB", len(wipe), 256, millis(start))
  if len(args) > 0 and args[0] == "--crypto-only" then
    print "[OK] crypto-only benchmark"
    return 0
  end if

  if benchCompression("repeated", bytes(1024 * 1024, 0x41), 64) != 0 then return 1 end if
  if benchCompression("patterned", large, 64) != 0 then return 1 end if
  if benchCompression("randomish", randomish(1024 * 1024), 64) != 0 then return 1 end if
  print "[OK] crypto compression benchmark"
end function
