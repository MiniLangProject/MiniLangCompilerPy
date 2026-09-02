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

//! Provides the std crypto aes_gcm package.

package std.crypto.aes_gcm
#if TARGET_OS == "windows"
import std.crypto._cng as cng
#else
import std.crypto._openssl as cng
#endif

/// Stores the aes gcm err.
const AES_GCM_ERR = 241

/// Represents encrypted.
struct Encrypted
  /// Stores the ciphertext member of `Encrypted`.
  ciphertext,
  /// Stores the tag member of `Encrypted`.
  tag
end struct

/// Implements aes error.
/// @internal
function _aesError(message)
  return error(AES_GCM_ERR, message)
end function

/// Implements valid common.
/// @internal
function _validCommon(key, nonce, aad, tagLength)
  if typeof(key) != "bytes" or len(key) != 32 then return false end if
  if typeof(nonce) != "bytes" or len(nonce) < 12 or len(nonce) > 16 then return false end if
  if typeof(aad) != "bytes" then return false end if
  if typeof(tagLength) != "int" or tagLength < 12 or tagLength > 16 then return false end if
  return true
end function

/// Encrypt with AES-256-GCM and return ciphertext||tag.
/// @param key Value supplied for `key`.
/// @param nonce Value supplied for `nonce`.
/// @param plaintext Value supplied for `plaintext`.
/// @param aad Value supplied for `aad`.
/// @param tagLength Value supplied for `tagLength`.
function seal(key, nonce, plaintext, aad, tagLength)
  if not _validCommon(key, nonce, aad, tagLength) or typeof(plaintext) != "bytes" then
    return _aesError("Invalid AES-256-GCM arguments")
  end if
  if len(plaintext) > 0x7FFFFFFF - tagLength then return _aesError("AES-256-GCM input is too large") end if
  output = bytes(len(plaintext) + tagLength, 0)
  if not cng.aesGcm(true, key, nonce, aad, plaintext, output, tagLength) then
    return _aesError("AES-256-GCM encryption failed")
  end if
  return output
end function

/// Authenticate and decrypt ciphertext||tag. Authentication failure returns an error and the temporary plaintext buffer is wiped before it can escape.
/// @param key Value supplied for `key`.
/// @param nonce Value supplied for `nonce`.
/// @param sealed Value supplied for `sealed`.
/// @param aad Value supplied for `aad`.
/// @param tagLength Value supplied for `tagLength`.
function open(key, nonce, sealed, aad, tagLength)
  if not _validCommon(key, nonce, aad, tagLength) or typeof(sealed) != "bytes" or len(sealed) < tagLength then
    return _aesError("Invalid AES-256-GCM arguments")
  end if
  output = bytes(len(sealed) - tagLength, 0)
  if not cng.aesGcm(false, key, nonce, aad, sealed, output, tagLength) then
    return _aesError("AES-256-GCM authentication failed")
  end if
  return output
end function

/// Convenience API returning separate ciphertext and tag fields.
/// @param key Value supplied for `key`.
/// @param nonce Value supplied for `nonce`.
/// @param plaintext Value supplied for `plaintext`.
/// @param aad Value supplied for `aad`.
/// @param tagLength Value supplied for `tagLength`.
function encrypt(key, nonce, plaintext, aad, tagLength)
  sealed = seal(key, nonce, plaintext, aad, tagLength)
  if typeof(sealed) == "error" then return sealed end if
  n = len(sealed) - tagLength
  return Encrypted(slice(sealed, 0, n), slice(sealed, n, tagLength))
end function

/// Convenience API accepting separate ciphertext and tag values.
/// @param key Value supplied for `key`.
/// @param nonce Value supplied for `nonce`.
/// @param ciphertext Value supplied for `ciphertext`.
/// @param tag Value supplied for `tag`.
/// @param aad Value supplied for `aad`.
function decrypt(key, nonce, ciphertext, tag, aad)
  if typeof(ciphertext) != "bytes" or typeof(tag) != "bytes" then return _aesError("Invalid AES-256-GCM arguments") end if
  return open(key, nonce, ciphertext + tag, aad, len(tag))
end function
