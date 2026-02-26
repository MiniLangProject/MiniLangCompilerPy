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

// ============================================================
// AES-128 (ECB) – in MiniLang
// ============================================================

AES_SBOX =[
0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

AES_INV_SBOX =[
0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
]

AES_RCON =[
0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
]

// ---------- bit helpers ----------
// Uses built-in bitwise operators: &, |, ^, ~, <<, >>

// ---------- GF(2^8) multiply ----------
function aes_xtime(a)
  // multiply by x in GF(2^8)
  a2 =(a << 1) & 255
  if (a & 128) != 0 then
    a2 = a2 ^ 27
  end if
  return a2
end function

function aes_mul(a, b)
  // GF(2^8) multiply (Russian peasant)
  p = 0
  i = 0
  while i < 8
    if (b & 1) == 1 then
      p = p ^ a
    end if
    a = aes_xtime(a)
    b = b >> 1
    i = i + 1
  end while
  return p
end function

function aes_mul2(a)
  return aes_xtime(a)
end function

function aes_mul3(a)
  return aes_xtime(a) ^ a
end function

// ---------- state ops ----------
function aes_add_round_key(state, expkey, round)
  base = round * 16
  i = 0
  while i < 16
    state[i] = state[i] ^ expkey[base + i]
    i = i + 1
  end while
end function

function aes_sub_bytes(state, box)
  i = 0
  while i < 16
    state[i] = box[state[i]]
    i = i + 1
  end while
end function

function aes_shift_rows(state)
  t = state[1]
  state[1] = state[5]
  state[5] = state[9]
  state[9] = state[13]
  state[13] = t

  t1 = state[2]
  t2 = state[6]
  state[2] = state[10]
  state[6] = state[14]
  state[10] = t1
  state[14] = t2

  t = state[3]
  state[3] = state[15]
  state[15] = state[11]
  state[11] = state[7]
  state[7] = t
end function

function aes_inv_shift_rows(state)
  t = state[13]
  state[13] = state[9]
  state[9] = state[5]
  state[5] = state[1]
  state[1] = t

  t1 = state[2]
  t2 = state[6]
  state[2] = state[10]
  state[6] = state[14]
  state[10] = t1
  state[14] = t2

  t = state[3]
  state[3] = state[7]
  state[7] = state[11]
  state[11] = state[15]
  state[15] = t
end function

function aes_mix_columns(state)
  c = 0
  while c < 4
    i = c * 4
    a0 = state[i + 0]
    a1 = state[i + 1]
    a2 = state[i + 2]
    a3 = state[i + 3]

    r0 = aes_mul2(a0) ^ aes_mul3(a1) ^ a2 ^ a3
    r1 = a0 ^ aes_mul2(a1) ^ aes_mul3(a2) ^ a3
    r2 = a0 ^ a1 ^ aes_mul2(a2) ^ aes_mul3(a3)
    r3 = aes_mul3(a0) ^ a1 ^ a2 ^ aes_mul2(a3)

    state[i + 0] = r0
    state[i + 1] = r1
    state[i + 2] = r2
    state[i + 3] = r3

    c = c + 1
  end while
end function

function aes_inv_mix_columns(state)
  c = 0
  while c < 4
    i = c * 4
    a0 = state[i + 0]
    a1 = state[i + 1]
    a2 = state[i + 2]
    a3 = state[i + 3]

    r0 = aes_mul(a0, 14) ^ aes_mul(a1, 11) ^ aes_mul(a2, 13) ^ aes_mul(a3, 9)
    r1 = aes_mul(a0, 9) ^ aes_mul(a1, 14) ^ aes_mul(a2, 11) ^ aes_mul(a3, 13)
    r2 = aes_mul(a0, 13) ^ aes_mul(a1, 9) ^ aes_mul(a2, 14) ^ aes_mul(a3, 11)
    r3 = aes_mul(a0, 11) ^ aes_mul(a1, 13) ^ aes_mul(a2, 9) ^ aes_mul(a3, 14)

    state[i + 0] = r0
    state[i + 1] = r1
    state[i + 2] = r2
    state[i + 3] = r3

    c = c + 1
  end while
end function

// ---------- key expansion ----------
function aes128_expand_key(key)
  exp = key +[]
  i = 4
  rci = 1
  while i < 44
    t0 = exp[(i - 1) * 4 + 0]
    t1 = exp[(i - 1) * 4 + 1]
    t2 = exp[(i - 1) * 4 + 2]
    t3 = exp[(i - 1) * 4 + 3]
    if (i % 4) == 0 then
      tmp = t0
      t0 = t1
      t1 = t2
      t2 = t3
      t3 = tmp

      t0 = AES_SBOX[t0]
      t1 = AES_SBOX[t1]
      t2 = AES_SBOX[t2]
      t3 = AES_SBOX[t3]

      t0 = t0 ^ AES_RCON[rci]
      rci = rci + 1
    end if

    b0 = exp[(i - 4) * 4 + 0] ^ t0
    b1 = exp[(i - 4) * 4 + 1] ^ t1
    b2 = exp[(i - 4) * 4 + 2] ^ t2
    b3 = exp[(i - 4) * 4 + 3] ^ t3

    exp = exp +[b0, b1, b2, b3]
    i = i + 1

  end while
  return exp
end function

// ---------- block encrypt/decrypt ----------
function aes128_encrypt_block(expkey, block)
  state = block +[]
  aes_add_round_key(state, expkey, 0)

  round = 1
  while round <= 9
    aes_sub_bytes(state, AES_SBOX)
    aes_shift_rows(state)
    aes_mix_columns(state)
    aes_add_round_key(state, expkey, round)
    round = round + 1
  end while

  aes_sub_bytes(state, AES_SBOX)
  aes_shift_rows(state)
  aes_add_round_key(state, expkey, 10)

  return state
end function

function aes128_decrypt_block(expkey, block)
  state = block +[]
  aes_add_round_key(state, expkey, 10)

  round = 9
  while round >= 1
    aes_inv_shift_rows(state)
    aes_sub_bytes(state, AES_INV_SBOX)
    aes_add_round_key(state, expkey, round)
    aes_inv_mix_columns(state)
    round = round - 1
  end while

  aes_inv_shift_rows(state)
  aes_sub_bytes(state, AES_INV_SBOX)
  aes_add_round_key(state, expkey, 0)

  return state
end function

// ---------- ECB ----------
function aes128_ecb_encrypt_bytes(key, data)
  exp = aes128_expand_key(key)
  val = data +[]
  i = 0
  while i < len(val)
    block =[
    val[i + 0], val[i + 1], val[i + 2], val[i + 3],
    val[i + 4], val[i + 5], val[i + 6], val[i + 7],
    val[i + 8], val[i + 9], val[i + 10], val[i + 11],
    val[i + 12], val[i + 13], val[i + 14], val[i + 15],
]
    enc = aes128_encrypt_block(exp, block)
    j = 0
    while j < 16
      val[i + j] = enc[j]
      j = j + 1
    end while
    i = i + 16
  end while
  return val
end function

function aes128_ecb_decrypt_bytes(key, data)
  exp = aes128_expand_key(key)
  val = data +[]
  i = 0
  while i < len(val)
    block =[
    val[i + 0], val[i + 1], val[i + 2], val[i + 3],
    val[i + 4], val[i + 5], val[i + 6], val[i + 7],
    val[i + 8], val[i + 9], val[i + 10], val[i + 11],
    val[i + 12], val[i + 13], val[i + 14], val[i + 15],
]
    dec = aes128_decrypt_block(exp, block)
    j = 0
    while j < 16
      val[i + j] = dec[j]
      j = j + 1
    end while
    i = i + 16
  end while
  return val
end function

// ---------- hex helpers ----------
HEX_DIGITS = "0123456789abcdef"
HEX_DIGITS_UPPER = "0123456789ABCDEF"
function hex_val(c)
  digits = HEX_DIGITS
  i = 0
  while i < 16
    if c == digits[i] then
      return i
    end if
    i = i + 1
  end while

  digits2 = HEX_DIGITS_UPPER
  i = 0
  while i < 16
    if c == digits2[i] then
      return i
    end if
    i = i + 1
  end while

  return -1
end function

function hex_to_bytes(s)
  n = len(s)
  val =[]
  i = 0
  while i < n
    hi = hex_val(s[i])
    lo = hex_val(s[i + 1])
    val = val +[hi * 16 + lo]
    i = i + 2
  end while
  return val
end function

function byte_to_hex(b)
  hi =(b >> 4) & 15
  lo = b & 15
  return HEX_DIGITS[hi] + HEX_DIGITS[lo]
end function

function bytes_to_hex(arr)
  val = ""
  i = 0
  while i < len(arr)
    val = val + byte_to_hex(arr[i])
    i = i + 1
  end while
  return val
end function

// ---------- NIST KAT Test ----------
key = hex_to_bytes("000102030405060708090a0b0c0d0e0f")
pt = hex_to_bytes("00112233445566778899aabbccddeeff")

print "key= " + bytes_to_hex(key)
print "pt = " + bytes_to_hex(pt)

ct = aes128_ecb_encrypt_bytes(key, pt)
print "ct = " + bytes_to_hex(ct)

dt = aes128_ecb_decrypt_bytes(key, ct)
print "dt = " + bytes_to_hex(dt)

