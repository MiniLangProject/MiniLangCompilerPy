import std.crypto.ecdsa_p256 as ecdsa

function main(args)
  publicKey = fromHex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
  message = fromHex("4d696e694c616e672045434453412d503235362073656c662074657374")
  signature = fromHex("45ad878ed724d17906f74f08f1c36fa229d12b9d643d3008abeb7d0ff1fccb6c3ad6e38d23b7e94ad8865b73dea449259033a081538418d1fab1005dc712da7f")
  if not ecdsa.verify(publicKey, message, signature) then return 1 end if
  message[0] = message[0] ^ 1
  if ecdsa.verify(publicKey, message, signature) then return 2 end if
  print("[OK] ECDSA-P256")
  return 0
end function
