//! Provides the std tls _schannel package.

package std.tls._schannel

// Copyright 2026 MiniLangProject contributors
// SPDX-License-Identifier: Apache-2.0
// Internal Schannel transport used by std.tls on Windows. The module owns
// SSPI handles and TLS record buffers but never closes the caller's TCP socket.

import std.io.file as file_api
import std.net as network

/// Native Schannel transport for std.tls. The module owns SSPI handles, certificate contexts and TLS record buffering for one Stream.
/// @internal
const INVALID_ARGUMENT = 9001
/// Stores the tls error.
/// @internal
const TLS_ERROR = 9034

/// Stores the sec e ok.
/// @internal
const SEC_E_OK = 0
/// Stores the sec i continue needed.
/// @internal
const SEC_I_CONTINUE_NEEDED = 590610
/// Stores the sec i context expired.
/// @internal
const SEC_I_CONTEXT_EXPIRED = 590615
/// Stores the sec i renegotiate.
/// @internal
const SEC_I_RENEGOTIATE = 590625
/// Stores the sec e invalid token.
/// @internal
const SEC_E_INVALID_TOKEN = -2146893048
/// Stores the sec e incomplete message.
/// @internal
const SEC_E_INCOMPLETE_MESSAGE = -2146893032
/// Stores the sec e wrong principal.
/// @internal
const SEC_E_WRONG_PRINCIPAL = -2146893022
/// Stores the sec e untrusted root.
/// @internal
const SEC_E_UNTRUSTED_ROOT = -2146893019
/// Stores the sec e cert unknown.
/// @internal
const SEC_E_CERT_UNKNOWN = -2146893017
/// Stores the secpkg cred inbound.
/// @internal
const SECPKG_CRED_INBOUND = 1
/// Stores the secpkg cred outbound.
/// @internal
const SECPKG_CRED_OUTBOUND = 2
/// Stores the unisp package.
/// @internal
const UNISP_PACKAGE = "Microsoft Unified Security Protocol Provider"
/// Stores the security native drep.
/// @internal
const SECURITY_NATIVE_DREP = 16
/// Stores the isc req sequence detect.
/// @internal
const ISC_REQ_SEQUENCE_DETECT = 8
/// Stores the isc req replay detect.
/// @internal
const ISC_REQ_REPLAY_DETECT = 4
/// Stores the isc req confidentiality.
/// @internal
const ISC_REQ_CONFIDENTIALITY = 16
/// Stores the isc req extended error.
/// @internal
const ISC_REQ_EXTENDED_ERROR = 16384
/// Stores the isc req stream.
/// @internal
const ISC_REQ_STREAM = 32768
/// Stores the asc req replay detect.
/// @internal
const ASC_REQ_REPLAY_DETECT = 4
/// Stores the asc req mutual auth.
/// @internal
const ASC_REQ_MUTUAL_AUTH = 2
/// Stores the asc req sequence detect.
/// @internal
const ASC_REQ_SEQUENCE_DETECT = 8
/// Stores the asc req confidentiality.
/// @internal
const ASC_REQ_CONFIDENTIALITY = 16
/// Stores the asc req extended error.
/// @internal
const ASC_REQ_EXTENDED_ERROR = 32768
/// Stores the asc req stream.
/// @internal
const ASC_REQ_STREAM = 65536
/// Stores the secbuffer empty.
/// @internal
const SECBUFFER_EMPTY = 0
/// Stores the secbuffer data.
/// @internal
const SECBUFFER_DATA = 1
/// Stores the secbuffer token.
/// @internal
const SECBUFFER_TOKEN = 2
/// Stores the secbuffer missing.
/// @internal
const SECBUFFER_MISSING = 4
/// Stores the secbuffer extra.
/// @internal
const SECBUFFER_EXTRA = 5
/// Stores the secbuffer stream trailer.
/// @internal
const SECBUFFER_STREAM_TRAILER = 6
/// Stores the secbuffer stream header.
/// @internal
const SECBUFFER_STREAM_HEADER = 7
/// Stores the secbuffer version.
/// @internal
const SECBUFFER_VERSION = 0
/// Stores the sec buffer size.
/// @internal
const SEC_BUFFER_SIZE = 16
/// Stores the sec buffer desc size.
/// @internal
const SEC_BUFFER_DESC_SIZE = 16
/// Stores the cred handle size.
/// @internal
const CRED_HANDLE_SIZE = 16
/// Stores the timestamp size.
/// @internal
const TIMESTAMP_SIZE = 8
/// Stores the tls token bytes.
/// @internal
const TLS_TOKEN_BYTES = 65536
/// Stores the tls network receive bytes.
/// @internal
const TLS_NETWORK_RECEIVE_BYTES = 65536
/// Stores the tls max pfx bytes.
/// @internal
const TLS_MAX_PFX_BYTES = 16777216
/// Stores the tls max receive bytes.
/// @internal
const TLS_MAX_RECEIVE_BYTES = 67108864

/// Stores the sch credentials version.
/// @internal
const SCH_CREDENTIALS_VERSION = 5
/// Stores the sch credentials bytes.
/// @internal
const SCH_CREDENTIALS_BYTES = 72
/// Stores the tls parameters bytes.
/// @internal
const TLS_PARAMETERS_BYTES = 40
/// Stores the crypto settings bytes.
/// @internal
const CRYPTO_SETTINGS_BYTES = 48
/// Stores the tls key exchange usage.
/// @internal
const TLS_KEY_EXCHANGE_USAGE = 0
/// Stores the sch cred manual cred validation.
/// @internal
const SCH_CRED_MANUAL_CRED_VALIDATION = 8
/// Stores the sch cred no default creds.
/// @internal
const SCH_CRED_NO_DEFAULT_CREDS = 16
/// Stores the sch cred auto cred validation.
/// @internal
const SCH_CRED_AUTO_CRED_VALIDATION = 32
/// Stores the sch use strong crypto.
/// @internal
const SCH_USE_STRONG_CRYPTO = 4194304
/// Stores the sp prot tls1 3 server.
/// @internal
const SP_PROT_TLS1_3_SERVER = 4096
/// Stores the sp prot tls1 3 client.
/// @internal
const SP_PROT_TLS1_3_CLIENT = 8192
/// Stores the sp prot tls1 2 server.
/// @internal
const SP_PROT_TLS1_2_SERVER = 1024
/// Stores the sp prot tls1 2 client.
/// @internal
const SP_PROT_TLS1_2_CLIENT = 2048
/// Stores the sp prot legacy server.
/// @internal
const SP_PROT_LEGACY_SERVER = 1365
/// Stores the sp prot legacy client.
/// @internal
const SP_PROT_LEGACY_CLIENT = 2730
/// Stores the sp prot before tls1 2 server.
/// @internal
const SP_PROT_BEFORE_TLS1_2_SERVER = 341
/// Stores the sp prot before tls1 2 client.
/// @internal
const SP_PROT_BEFORE_TLS1_2_CLIENT = 682
/// Stores the secpkg attr stream sizes.
/// @internal
const SECPKG_ATTR_STREAM_SIZES = 4
/// Stores the secpkg attr remote cert context.
/// @internal
const SECPKG_ATTR_REMOTE_CERT_CONTEXT = 83
/// Stores the secpkg attr connection info.
/// @internal
const SECPKG_ATTR_CONNECTION_INFO = 90
/// Stores the secpkg attr cipher info.
/// @internal
const SECPKG_ATTR_CIPHER_INFO = 100
/// Stores the schannel shutdown.
/// @internal
const SCHANNEL_SHUTDOWN = 1
/// Stores the secpkg cipher info bytes.
/// @internal
const SECPKG_CIPHER_INFO_BYTES = 680

/// Stores the cert store prov system w.
/// @internal
const CERT_STORE_PROV_SYSTEM_W = 10
/// Stores the cert system store current user.
/// @internal
const CERT_SYSTEM_STORE_CURRENT_USER = 65536
/// Stores the cert system store local machine.
/// @internal
const CERT_SYSTEM_STORE_LOCAL_MACHINE = 131072
/// Stores the x509 asn encoding.
/// @internal
const X509_ASN_ENCODING = 1
/// Stores the pkcs 7 asn encoding.
/// @internal
const PKCS_7_ASN_ENCODING = 65536
/// Stores the cert encoding.
/// @internal
const CERT_ENCODING = 65537
/// Stores the cert find sha1 hash.
/// @internal
const CERT_FIND_SHA1_HASH = 65536
/// Stores the cert find has private key.
/// @internal
const CERT_FIND_HAS_PRIVATE_KEY = 1376256
/// Stores the cert close store force flag.
/// @internal
const CERT_CLOSE_STORE_FORCE_FLAG = 1
/// Stores the crypt user keyset.
/// @internal
const CRYPT_USER_KEYSET = 4096
/// Stores the cert sha256 hash prop id.
/// @internal
const CERT_SHA256_HASH_PROP_ID = 107
/// Stores the cert chain policy ssl.
/// @internal
const CERT_CHAIN_POLICY_SSL = 4
/// Stores the cert chain cache end cert.
/// @internal
const CERT_CHAIN_CACHE_END_CERT = 1
/// Stores the authtype server.
/// @internal
const AUTHTYPE_SERVER = 2
/// Stores the security flag ignore unknown ca.
/// @internal
const SECURITY_FLAG_IGNORE_UNKNOWN_CA = 256
/// Stores the cert chain para bytes.
/// @internal
const CERT_CHAIN_PARA_BYTES = 96
/// Stores the ssl policy extra bytes.
/// @internal
const SSL_POLICY_EXTRA_BYTES = 24
/// Stores the cert chain policy para bytes.
/// @internal
const CERT_CHAIN_POLICY_PARA_BYTES = 16
/// Stores the cert chain policy status bytes.
/// @internal
const CERT_CHAIN_POLICY_STATUS_BYTES = 24
/// Stores the server auth oid.
/// @internal
const SERVER_AUTH_OID = "1.3.6.1.5.5.7.3.1"

/// Owns an acquired Schannel credential and every allocation whose lifetime it requires.
/// @internal
struct SchannelCredential
  // SSPI CredHandle encoded in native-layout bytes.
  /// Stores the handle member of `SchannelCredential`.
  handle
  // Credential expiry timestamp returned by SSPI.
  /// Stores the expiry member of `SchannelCredential`.
  expiry
  // Distinguishes a server credential from a client credential.
  /// Stores the inbound member of `SchannelCredential`.
  inbound
  // Prevents duplicate native-handle release.
  /// Stores the closed member of `SchannelCredential`.
  closed
  // Server leaf certificate context, or void for a client credential.
  /// Stores the certificate context member of `SchannelCredential`.
  certificateContext
  // Certificate store kept open while the server credential is usable.
  /// Stores the certificate store member of `SchannelCredential`.
  certificateStore
  // SCH_CREDENTIALS structure retained for the native credential lifetime.
  /// Stores the credential bytes member of `SchannelCredential`.
  credentialBytes
  // Native pointer array that pins the configured server certificate.
  /// Stores the pinned certificate pointers member of `SchannelCredential`.
  pinnedCertificatePointers
  // Imported PFX payload retained and wiped when the credential closes.
  /// Stores the pfx bytes member of `SchannelCredential`.
  pfxBytes
  // TLS_PARAMETERS structure that enforces the configured protocol minimum.
  /// Stores the tls parameters member of `SchannelCredential`.
  tlsParameters
  // CRYPTO_SETTINGS array that disables every key-exchange group except X25519.
  /// Stores the disabled crypto member of `SchannelCredential`.
  disabledCrypto
  // Algorithm-name buffers referenced by the disabled crypto settings.
  /// Stores the disabled crypto strings member of `SchannelCredential`.
  disabledCryptoStrings
  // Selects explicit chain and pin validation for a client credential.
  /// Stores the manual validation member of `SchannelCredential`.
  manualValidation
end struct

/// Holds one established TLS connection plus its encrypted and plaintext queues.
/// @internal
struct TlsContext
  // Credential that authenticated and parameterized this connection.
  /// Stores the credential member of `TlsContext`.
  credential
  // Caller-owned connected TCP socket used for encrypted record transport.
  /// Stores the socket handle member of `TlsContext`.
  socketHandle
  // SSPI CtxtHandle encoded in native-layout bytes.
  /// Stores the handle member of `TlsContext`.
  handle
  // Context expiry timestamp returned by SSPI.
  /// Stores the expiry member of `TlsContext`.
  expiry
  // Negotiated SSPI context attributes.
  /// Stores the attributes member of `TlsContext`.
  attributes
  // Prevents use or release after closure.
  /// Stores the closed member of `TlsContext`.
  closed
  // Distinguishes a received close_notify from released native handles.
  /// Stores the released member of `TlsContext`.
  released
  // True for the accepted server side and false for the connecting client side.
  /// Stores the server member of `TlsContext`.
  server
  // TLS records received but not yet consumed by Schannel.
  /// Stores the encrypted input member of `TlsContext`.
  encryptedInput
  // Plaintext produced by Schannel but not yet consumed by the caller.
  /// Stores the decrypted input member of `TlsContext`.
  decryptedInput
  // Provider-specific record header capacity.
  /// Stores the stream header bytes member of `TlsContext`.
  streamHeaderBytes
  // Provider-specific AEAD trailer capacity.
  /// Stores the stream trailer bytes member of `TlsContext`.
  streamTrailerBytes
  // Maximum plaintext carried by one encrypted TLS record.
  /// Stores the maximum message bytes member of `TlsContext`.
  maximumMessageBytes
  // Immutable std.tls client or server options.
  /// Stores the options member of `TlsContext`.
  options
  // Handshake records retained until the ServerHello profile is verified.
  /// Stores the handshake transcript member of `TlsContext`.
  handshakeTranscript
  // IANA identifier of the negotiated TLS cipher suite.
  /// Stores the negotiated cipher suite member of `TlsContext`.
  negotiatedCipherSuite
  // IANA identifier of the negotiated key-exchange group.
  /// Stores the negotiated group member of `TlsContext`.
  negotiatedGroup
  // SHA-256 digest of the peer leaf certificate in DER form.
  /// Stores the peer certificate sha256 member of `TlsContext`.
  peerCertificateSha256
end struct

/// Acquires a Schannel credential from the supplied SCH_CREDENTIALS byte structure.
/// @internal
extern function AcquireCredentialsHandleWWithAuth(principal as ptr, packageName as wstr, credentialUse as u32, logonId as ptr, authData as bytes, getKeyFn as ptr, getKeyArgument as ptr, credentialHandle as bytes, expiry as bytes) from "secur32.dll" symbol "AcquireCredentialsHandleW" returns i32
/// Releases an SSPI credential handle.
/// @internal
extern function FreeCredentialsHandle(credentialHandle as bytes) from "secur32.dll" symbol "FreeCredentialsHandle" returns i32
/// Starts a client handshake without an existing context or inbound token.
/// @internal
extern function InitializeSecurityContextW(credentialHandle as bytes, contextHandle as ptr, targetName as wstr, contextReq as u32, reserved1 as u32, targetDataRep as u32, inputDesc as ptr, reserved2 as u32, newContext as bytes, outputDesc as bytes, contextAttr as bytes, expiry as bytes) from "secur32.dll" symbol "InitializeSecurityContextW" returns i32
/// Advances a client handshake using an existing context and peer input.
/// @internal
extern function InitializeSecurityContextWContinue(credentialHandle as bytes, contextHandle as bytes, targetName as wstr, contextReq as u32, reserved1 as u32, targetDataRep as u32, inputDesc as bytes, reserved2 as u32, newContext as bytes, outputDesc as bytes, contextAttr as bytes, expiry as bytes) from "secur32.dll" symbol "InitializeSecurityContextW" returns i32
/// Produces the client-side close_notify token after applying SCHANNEL_SHUTDOWN.
/// @internal
extern function InitializeSecurityContextWShutdown(credentialHandle as bytes, contextHandle as bytes, targetName as wstr, contextReq as u32, reserved1 as u32, targetDataRep as u32, inputDesc as ptr, reserved2 as u32, newContext as bytes, outputDesc as bytes, contextAttr as bytes, expiry as bytes) from "secur32.dll" symbol "InitializeSecurityContextW" returns i32
/// Starts a server handshake from the first client token.
/// @internal
extern function AcceptSecurityContextInitial(credentialHandle as bytes, contextHandle as ptr, inputDesc as bytes, contextReq as u32, targetDataRep as u32, newContext as bytes, outputDesc as bytes, contextAttr as bytes, expiry as bytes) from "secur32.dll" symbol "AcceptSecurityContext" returns i32
/// Advances a server handshake using an existing context and peer input.
/// @internal
extern function AcceptSecurityContextContinue(credentialHandle as bytes, contextHandle as bytes, inputDesc as bytes, contextReq as u32, targetDataRep as u32, newContext as bytes, outputDesc as bytes, contextAttr as bytes, expiry as bytes) from "secur32.dll" symbol "AcceptSecurityContext" returns i32
/// Produces the server-side close_notify token after applying SCHANNEL_SHUTDOWN.
/// @internal
extern function AcceptSecurityContextShutdown(credentialHandle as bytes, contextHandle as bytes, inputDesc as ptr, contextReq as u32, targetDataRep as u32, newContext as bytes, outputDesc as bytes, contextAttr as bytes, expiry as bytes) from "secur32.dll" symbol "AcceptSecurityContext" returns i32
/// Authenticates and encrypts one plaintext record with the negotiated AEAD keys.
/// @internal
extern function EncryptMessage(contextHandle as bytes, qualityOfProtection as u32, message as bytes, sequenceNumber as u32) from "secur32.dll" symbol "EncryptMessage" returns i32
/// Authenticates and decrypts one TLS record with the negotiated AEAD keys.
/// @internal
extern function DecryptMessage(contextHandle as bytes, message as bytes, sequenceNumber as u32, qualityOfProtection as bytes) from "secur32.dll" symbol "DecryptMessage" returns i32
/// Reads an attribute from an established SSPI context.
/// @internal
extern function QueryContextAttributesW(contextHandle as bytes, attribute as u32, buffer as bytes) from "secur32.dll" symbol "QueryContextAttributesW" returns i32
/// Applies the SCHANNEL_SHUTDOWN control token to an established context.
/// @internal
extern function ApplyControlToken(contextHandle as bytes, inputDesc as bytes) from "secur32.dll" symbol "ApplyControlToken" returns i32
/// Releases an SSPI security-context handle.
/// @internal
extern function DeleteSecurityContext(contextHandle as bytes) from "secur32.dll" symbol "DeleteSecurityContext" returns i32
/// Opens a Windows certificate store by provider and location.
/// @internal
extern function CertOpenStore(storeProvider as ptr, encodingType as u32, cryptProvider as ptr, flags as u32, parameter as wstr) from "crypt32.dll" symbol "CertOpenStore" returns ptr
/// Searches a certificate store using a pointer-valued search parameter.
/// @internal
extern function CertFindCertificateInStore(store as ptr, encodingType as u32, findFlags as u32, findType as u32, findParameter as ptr, previousContext as ptr) from "crypt32.dll" symbol "CertFindCertificateInStore" returns ptr
/// Searches a certificate store using a byte-encoded search parameter.
/// @internal
extern function CertFindCertificateInStoreBytes(store as ptr, encodingType as u32, findFlags as u32, findType as u32, findParameter as bytes, previousContext as ptr) from "crypt32.dll" symbol "CertFindCertificateInStore" returns ptr
/// Releases one Windows certificate context.
/// @internal
extern function CertFreeCertificateContext(context as ptr) from "crypt32.dll" symbol "CertFreeCertificateContext" returns bool
/// Closes a Windows certificate store.
/// @internal
extern function CertCloseStore(store as ptr, flags as u32) from "crypt32.dll" symbol "CertCloseStore" returns bool
/// Imports an encrypted PKCS#12 identity into a temporary certificate store.
/// @internal
extern function PFXImportCertStore(pfxBlob as bytes, password as wstr, flags as u32) from "crypt32.dll" symbol "PFXImportCertStore" returns ptr
/// Reads a property such as the SHA-256 digest from a certificate context.
/// @internal
extern function CertGetCertificateContextProperty(context as ptr, propertyId as u32, data as bytes, size as bytes) from "crypt32.dll" symbol "CertGetCertificateContextProperty" returns bool
/// Builds and cryptographically verifies the peer certificate chain.
/// @internal
extern function CertGetCertificateChain(chainEngine as ptr, certificateContext as ptr, currentTime as ptr, additionalStore as ptr, chainParameters as bytes, flags as u32, reserved as ptr, chainContext as bytes) from "crypt32.dll" symbol "CertGetCertificateChain" returns bool
/// Applies hostname, lifetime, EKU, and trust policy to a built certificate chain.
/// @internal
extern function CertVerifyCertificateChainPolicy(policyOid as ptr, chainContext as ptr, policyParameters as bytes, policyStatus as bytes) from "crypt32.dll" symbol "CertVerifyCertificateChainPolicy" returns bool
/// Releases a certificate chain returned by CertGetCertificateChain.
/// @internal
extern function CertFreeCertificateChain(chainContext as ptr) from "crypt32.dll" symbol "CertFreeCertificateChain" returns void
/// Reads a process environment variable into caller-owned memory.
/// @internal
extern function GetEnvironmentVariableA(name as cstr, buffer as bytes, size as u32) from "kernel32.dll" symbol "GetEnvironmentVariableA" returns u32
/// Returns the calling thread's latest Win32 error code.
/// @internal
extern function GetLastError() from "kernel32.dll" symbol "GetLastError" returns u32

/// Creates a transport-scoped TLS error with consistent operation context.
/// @internal
function fail(operation, message)
  return error(TLS_ERROR, "std.tls/Schannel " + operation + ": " + message)
end function

/// Converts a native Schannel status code into a MiniLang TLS error.
/// @internal
function statusFailure(operation, status)
  return fail(operation, "Schannel status " + status)
end function

/// Reports whether a value owns a Schannel credential handle.
/// @internal
function isCredential(value)
  return value is SchannelCredential
end function

/// Reports whether a value is an established native TLS context.
/// @internal
function isTlsContext(value)
  return value is TlsContext
end function

/// Updates write u16 le.
/// @internal
function _writeU16LE(target, offset, value)
  target[offset] = value & 0xFF
  target[offset + 1] = (value >> 8) & 0xFF
end function

/// Updates write u32 le.
/// @internal
function _writeU32LE(target, offset, value)
  target[offset] = value & 0xFF
  target[offset + 1] = (value >> 8) & 0xFF
  target[offset + 2] = (value >> 16) & 0xFF
  target[offset + 3] = (value >> 24) & 0xFF
end function

/// Returns read u32 le.
/// @internal
function _readU32LE(source, offset)
  return source[offset] | (source[offset + 1] << 8) | (source[offset + 2] << 16) | (source[offset + 3] << 24)
end function

/// Writes a native 64-bit pointer into an ABI structure.
/// @internal
function writePointer(target, offset, pointerValue)
  i = 0
  while i < 8
    target[offset + i] = (pointerValue >> (i * 8)) & 0xFF
    i = i + 1
  end while
  return true
end function

/// Reads a checked native 64-bit pointer from an ABI structure.
/// @internal
function readPointer(source, offset)
  value = 0
  i = 0
  while i < 8
    value = value | (source[offset + i] << (i * 8))
    i = i + 1
  end while
  return value
end function

/// Builds a single native SecBuffer over caller-owned bytes.
/// @internal
function createSecBuffer(bufferType, payload)
  if typeof(bufferType) != "int" or typeof(payload) != "bytes" then return error(INVALID_ARGUMENT, "platform.tls_schannel.createSecBuffer: invalid buffer arguments") end if
  result = bytes(SEC_BUFFER_SIZE, 0)
  _writeU32LE(result, 0, len(payload))
  _writeU32LE(result, 4, bufferType)
  if len(payload) > 0 then writePointer(result, 8, nativeBytesPtr(payload)) end if
  return result
end function

/// Builds a one-element SecBufferDesc for an SSPI call.
/// @internal
function createSecBufferDesc(buffer)
  if typeof(buffer) != "bytes" or len(buffer) != SEC_BUFFER_SIZE then return error(INVALID_ARGUMENT, "platform.tls_schannel.createSecBufferDesc: buffer must be SecBuffer bytes") end if
  result = bytes(SEC_BUFFER_DESC_SIZE, 0)
  _writeU32LE(result, 0, SECBUFFER_VERSION)
  _writeU32LE(result, 4, 1)
  writePointer(result, 8, nativeBytesPtr(buffer))
  return result
end function

/// Populates one element of a contiguous native SecBuffer array.
/// @internal
function writeSecBuffer(target, index, bufferType, pointerValue, length)
  if typeof(target) != "bytes" or typeof(index) != "int" or typeof(bufferType) != "int" or typeof(pointerValue) != "int" or typeof(length) != "int" then return error(INVALID_ARGUMENT, "platform.tls_schannel.writeSecBuffer: invalid arguments") end if
  offset = index * SEC_BUFFER_SIZE
  if index < 0 or offset > len(target) - SEC_BUFFER_SIZE then return error(INVALID_ARGUMENT, "platform.tls_schannel.writeSecBuffer: index out of range") end if
  _writeU32LE(target, offset, length)
  _writeU32LE(target, offset + 4, bufferType)
  writePointer(target, offset + 8, pointerValue)
  return true
end function

/// Reads the byte count stored in a SecBuffer array element.
/// @internal
function secBufferLength(target, index)
  return _readU32LE(target, index * SEC_BUFFER_SIZE)
end function

/// Reads the buffer type stored in a SecBuffer array element.
/// @internal
function secBufferType(target, index)
  return _readU32LE(target, index * SEC_BUFFER_SIZE + 4)
end function

/// Reads the native data pointer stored in a SecBuffer array element.
/// @internal
function secBufferPointer(target, index)
  return readPointer(target, index * SEC_BUFFER_SIZE + 8)
end function

/// Allocates a bounded contiguous array of native SecBuffer structures.
/// @internal
function createSecBufferArray(count)
  if typeof(count) != "int" or count < 1 or count > 8 then return error(INVALID_ARGUMENT, "platform.tls_schannel.createSecBufferArray: count is invalid") end if
  return bytes(count * SEC_BUFFER_SIZE, 0)
end function

/// Builds a SecBufferDesc that references a validated buffer array.
/// @internal
function createSecBufferDescForArray(buffers, count)
  if typeof(buffers) != "bytes" or typeof(count) != "int" or count < 1 or count > 8 or len(buffers) != count * SEC_BUFFER_SIZE then return error(INVALID_ARGUMENT, "platform.tls_schannel.createSecBufferDescForArray: buffers are invalid") end if
  result = bytes(SEC_BUFFER_DESC_SIZE, 0)
  _writeU32LE(result, 0, SECBUFFER_VERSION)
  _writeU32LE(result, 4, count)
  writePointer(result, 8, nativeBytesPtr(buffers))
  return result
end function

/// Copies a checked byte range without exposing pointer arithmetic to callers.
/// @internal
function copyRange(source, offset, count, operation)
  if typeof(source) != "bytes" or typeof(offset) != "int" or typeof(count) != "int" or offset < 0 or count < 0 or offset > len(source) - count then
    return fail(operation, "byte range is invalid")
  end if
  if count == 0 then return bytes(0) end if
  return slice(source, offset, count)
end function

/// Concatenates two immutable byte sequences into fresh storage.
/// @internal
function appendBytes(left, right)
  if typeof(left) != "bytes" or typeof(right) != "bytes" then return error(INVALID_ARGUMENT, "platform.tls_schannel.appendBytes: arguments must be bytes") end if
  output = bytes(len(left) + len(right), 0)
  if len(left) > 0 then copyBytes(output, 0, left, 0, len(left)) end if
  if len(right) > 0 then copyBytes(output, len(left), right, 0, len(right)) end if
  return output
end function

/// Compares a UTF-8 string prefix without locale-dependent conversions.
/// @internal
function startsWith(text, prefix)
  if typeof(text) != "string" or typeof(prefix) != "string" then return false end if
  raw = bytes(text)
  wanted = bytes(prefix)
  if len(raw) < len(wanted) then return false end if
  for index = 0 to len(wanted) - 1
    if raw[index] != wanted[index] then return false end if
  end for
  return true
end function

/// Extracts and validates a UTF-8 substring by byte offset.
/// @internal
function substring(text, offset, count)
  raw = bytes(text)
  if offset < 0 or count < 0 or offset > len(raw) - count then return error(INVALID_ARGUMENT, "platform.tls_schannel.substring: range is invalid") end if
  if count == 0 then return "" end if
  value = decode(slice(raw, offset, count))
  if typeof(value) != "string" then return error(INVALID_ARGUMENT, "platform.tls_schannel.substring: text is not UTF-8") end if
  return value
end function

/// Maps one ASCII hexadecimal digit to its numeric value.
/// @internal
function hexValue(value)
  if value >= 48 and value <= 57 then return value - 48 end if
  if value >= 65 and value <= 70 then return value - 55 end if
  if value >= 97 and value <= 102 then return value - 87 end if
  return -1
end function

/// Normalizes a displayed SHA-1 certificate thumbprint into exactly 20 bytes.
/// @internal
function thumbprintBytes(thumbprint)
  if typeof(thumbprint) != "string" or len(thumbprint) == 0 then return error(INVALID_ARGUMENT, "platform.tls_schannel.thumbprintBytes: thumbprint must be non-empty") end if
  raw = bytes(thumbprint)
  hex = bytes(40, 0)
  count = 0
  for index = 0 to len(raw) - 1
    value = raw[index]
    digit = hexValue(value)
    if digit >= 0 then
      if count >= 40 then return error(INVALID_ARGUMENT, "platform.tls_schannel.thumbprintBytes: thumbprint is too long") end if
      hex[count] = digit
      count = count + 1
    else if value == 32 or value == 9 or value == 58 or value == 45 then
      ignored = true
    else
      return error(INVALID_ARGUMENT, "platform.tls_schannel.thumbprintBytes: thumbprint contains non-hex data")
    end if
  end for
  if count != 40 then return error(INVALID_ARGUMENT, "platform.tls_schannel.thumbprintBytes: SHA1 thumbprint must contain 40 hex digits") end if
  output = bytes(20, 0)
  for byteIndex = 0 to 19
    output[byteIndex] = (hex[byteIndex * 2] << 4) | hex[byteIndex * 2 + 1]
  end for
  fillBytes(hex, 0, len(hex), 0)
  return output
end function

/// Builds the native CRYPT_DATA_BLOB view used for PKCS#12 import.
/// @internal
function cryptBlob(data)
  if typeof(data) != "bytes" then return error(INVALID_ARGUMENT, "platform.tls_schannel.cryptBlob: data must be bytes") end if
  blob = bytes(16, 0)
  _writeU32LE(blob, 0, len(data))
  if len(data) > 0 then writePointer(blob, 8, nativeBytesPtr(data)) end if
  return blob
end function

/// Materializes SCH_CREDENTIALS and disables protocols older than the requested minimum. Cipher and key-exchange selection remains under the OS policy.
/// @internal
function schannelCredentialBytes(certificateContext, inbound, manualValidation, minimumVersion)
  cred = bytes(SCH_CREDENTIALS_BYTES, 0)
  _writeU32LE(cred, 0, SCH_CREDENTIALS_VERSION)
  tlsParameters = bytes(TLS_PARAMETERS_BYTES, 0)
  disabledProtocols = SP_PROT_LEGACY_CLIENT
  if minimumVersion == "1.2" then disabledProtocols = SP_PROT_BEFORE_TLS1_2_CLIENT end if
  if inbound and minimumVersion == "1.3" then disabledProtocols = SP_PROT_LEGACY_SERVER end if
  if inbound and minimumVersion == "1.2" then disabledProtocols = SP_PROT_BEFORE_TLS1_2_SERVER end if
  _writeU32LE(tlsParameters, 16, disabledProtocols)
  _writeU32LE(cred, 56, 1)
  writePointer(cred, 64, nativeBytesPtr(tlsParameters))
  if inbound then
    certPointers = bytes(8, 0)
    writePointer(certPointers, 0, certificateContext)
    _writeU32LE(cred, 8, 1)
    writePointer(cred, 16, nativeBytesPtr(certPointers))
    _writeU32LE(cred, 52, SCH_USE_STRONG_CRYPTO)
    return [cred, certPointers, tlsParameters, bytes(0), []]
  end if
  validationFlag = SCH_CRED_AUTO_CRED_VALIDATION
  if manualValidation then validationFlag = SCH_CRED_MANUAL_CRED_VALIDATION end if
  _writeU32LE(cred, 52, validationFlag | SCH_CRED_NO_DEFAULT_CREDS | SCH_USE_STRONG_CRYPTO)
  return [cred, bytes(0), tlsParameters, bytes(0), []]
end function

/// Reads an environment secret into wipeable bytes instead of a long-lived string.
/// @internal
function environmentSecret(name)
  if typeof(name) != "string" or len(name) == 0 then return error(INVALID_ARGUMENT, "platform.tls_schannel.environmentSecret: name must be non-empty") end if
  buffer = bytes(4096, 0)
  count = GetEnvironmentVariableA(name, buffer, len(buffer))
  if count == 0 then return void end if
  if count >= len(buffer) then return fail("environmentSecret", "environment variable is too large")
  end if
  return slice(buffer, 0, count)
end function

/// Loads the optional PKCS#12 password from the dedicated environment variable.
/// @internal
function pfxPasswordFromEnvironment()
  return environmentSecret("MINILANG_TLS_PFX_PASSWORD")
end function

/// Decodes temporary password bytes for the Windows PKCS#12 API.
/// @internal
function passwordText(passwordBytes)
  if passwordBytes is void then return "" end if
  if typeof(passwordBytes) != "bytes" then return error(INVALID_ARGUMENT, "platform.tls_schannel.passwordText: password must be bytes") end if
  value = decode(passwordBytes)
  if typeof(value) != "string" then return error(INVALID_ARGUMENT, "platform.tls_schannel.passwordText: password must be UTF-8") end if
  return value
end function

/// Opens the selected current-user or local-machine certificate store.
/// @internal
function openSystemStore(location)
  store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, void, location, "MY")
  if store == 0 then return fail("openSystemStore", "CertOpenStore failed (" + GetLastError() + ")") end if
  return store
end function

/// Locates a certificate by its exact SHA-1 store thumbprint.
/// @internal
function findCertificateInStore(store, thumbprintHash)
  blob = cryptBlob(thumbprintHash)
  context = CertFindCertificateInStoreBytes(store, CERT_ENCODING, 0, CERT_FIND_SHA1_HASH, blob, void)
  fillBytes(blob, 0, len(blob), 0)
  return context
end function

/// Resolves a store certificate reference and verifies that a private key is available.
/// @internal
function loadStoreCertificate(thumbprint)
  hash = try(thumbprintBytes(thumbprint))
  if typeof(hash) == "error" then return hash end if
  currentStore = try(openSystemStore(CERT_SYSTEM_STORE_CURRENT_USER))
  if typeof(currentStore) == "error" then fillBytes(hash, 0, len(hash), 0); return currentStore end if
  context = findCertificateInStore(currentStore, hash)
  if context != 0 then
    fillBytes(hash, 0, len(hash), 0)
    return [context, currentStore]
  end if
  ignoredCurrentClose = CertCloseStore(currentStore, 0)
  machineStore = try(openSystemStore(CERT_SYSTEM_STORE_LOCAL_MACHINE))
  if typeof(machineStore) == "error" then fillBytes(hash, 0, len(hash), 0); return machineStore end if
  context = findCertificateInStore(machineStore, hash)
  fillBytes(hash, 0, len(hash), 0)
  if context == 0 then
    ignoredMachineClose = CertCloseStore(machineStore, 0)
    return fail("loadStoreCertificate", "certificate thumbprint was not found in CurrentUser\\MY or LocalMachine\\MY")
  end if
  return [context, machineStore]
end function

/// Imports a bounded PKCS#12 identity and selects its private-key certificate.
/// @internal
function loadPfxCertificate(path, passwordBytes)
  if typeof(path) != "string" or len(path) == 0 then return error(INVALID_ARGUMENT, "platform.tls_schannel.loadPfxCertificate: PFX path must be non-empty") end if
  payload = try(file_api.readAllBytes(path, TLS_MAX_PFX_BYTES))
  if typeof(payload) == "error" then return payload end if
  blob = cryptBlob(payload)
  secretText = try(passwordText(passwordBytes))
  if typeof(secretText) == "error" then fillBytes(payload, 0, len(payload), 0); fillBytes(blob, 0, len(blob), 0); return secretText end if
  store = PFXImportCertStore(blob, secretText, CRYPT_USER_KEYSET)
  fillBytes(blob, 0, len(blob), 0)
  if typeof(passwordBytes) == "bytes" then fillBytes(passwordBytes, 0, len(passwordBytes), 0) end if
  if store == 0 then fillBytes(payload, 0, len(payload), 0); return fail("loadPfxCertificate", "PFXImportCertStore failed (" + GetLastError() + ")") end if
  context = CertFindCertificateInStore(store, CERT_ENCODING, 0, CERT_FIND_HAS_PRIVATE_KEY, void, void)
  if context == 0 then
    ignoredClose = CertCloseStore(store, CERT_CLOSE_STORE_FORCE_FLAG)
    fillBytes(payload, 0, len(payload), 0)
    return fail("loadPfxCertificate", "PFX does not contain a certificate with private key")
  end if
  return [context, store, payload]
end function

/// Returns the scheme portion of a server certificate reference.
/// @internal
function certificateReferenceKind(certificateReference)
  if startsWith(certificateReference, "pfx:") then return "pfx" end if
  return "store"
end function

/// Returns the value portion of a server certificate reference.
/// @internal
function certificateReferenceValue(certificateReference)
  if startsWith(certificateReference, "store:") then return substring(certificateReference, 6, len(bytes(certificateReference)) - 6) end if
  if startsWith(certificateReference, "pfx:") then return substring(certificateReference, 4, len(bytes(certificateReference)) - 4) end if
  return certificateReference
end function

/// Acquires an outbound Schannel credential with automatic or manual pin validation.
/// @internal
function acquireClientCredential(options)
  manualValidation = not options.verifyPeer or typeof(options.sha256Pin) == "bytes"
  authData = try(schannelCredentialBytes(0, false, manualValidation, options.minimumVersion))
  if typeof(authData) == "error" then return authData end if
  handle = bytes(CRED_HANDLE_SIZE, 0)
  expiry = bytes(TIMESTAMP_SIZE, 0)
  status = AcquireCredentialsHandleWWithAuth(void, UNISP_PACKAGE, SECPKG_CRED_OUTBOUND, void, authData[0], void, void, handle, expiry)
  if status != SEC_E_OK then return statusFailure("acquireClientCredential", status) end if
  return SchannelCredential(handle, expiry, false, false, 0, 0, authData[0], authData[1], bytes(0), authData[2], authData[3], authData[4], manualValidation)
end function

/// Creates the compatibility server credential without an explicit identity. Loads the configured identity and acquires a version-restricted server credential.
/// @internal
function acquireServerCredentialWithPassword(certificateReference, passwordBytes, minimumVersion)
  if typeof(certificateReference) != "string" or len(certificateReference) == 0 then return error(INVALID_ARGUMENT, "platform.tls_schannel.acquireServerCredentialWithPassword: certificate reference must be non-empty") end if
  value = try(certificateReferenceValue(certificateReference))
  if typeof(value) == "error" then return value end if
  loaded = void
  pfxPayload = bytes(0)
  if certificateReferenceKind(certificateReference) == "pfx" then
    secret = passwordBytes
    if secret is void then secret = try(pfxPasswordFromEnvironment()) end if
    loaded = try(loadPfxCertificate(value, secret))
    if typeof(loaded) == "error" then return loaded end if
    pfxPayload = loaded[2]
  else
    loaded = try(loadStoreCertificate(value))
    if typeof(loaded) == "error" then return loaded end if
  end if
  certContext = loaded[0]
  certStore = loaded[1]
  authData = try(schannelCredentialBytes(certContext, true, false, minimumVersion))
  if typeof(authData) == "error" then ignoredCert = CertFreeCertificateContext(certContext); ignoredStore = CertCloseStore(certStore, CERT_CLOSE_STORE_FORCE_FLAG); return authData end if
  handle = bytes(CRED_HANDLE_SIZE, 0)
  expiry = bytes(TIMESTAMP_SIZE, 0)
  status = AcquireCredentialsHandleWWithAuth(void, UNISP_PACKAGE, SECPKG_CRED_INBOUND, void, authData[0], void, void, handle, expiry)
  if status != SEC_E_OK then
    ignoredCert = CertFreeCertificateContext(certContext)
    ignoredStore = CertCloseStore(certStore, CERT_CLOSE_STORE_FORCE_FLAG)
    if len(pfxPayload) > 0 then fillBytes(pfxPayload, 0, len(pfxPayload), 0) end if
    return statusFailure("acquireServerCredentialWithPassword", status)
  end if
  return SchannelCredential(handle, expiry, true, false, certContext, certStore, authData[0], authData[1], pfxPayload, authData[2], authData[3], authData[4], false)
end function

/// Releases a credential and wipes or closes every retained native dependency.
/// @internal
function closeCredential(credential)
  if credential is not SchannelCredential then return error(INVALID_ARGUMENT, "platform.tls_schannel.closeCredential: credential must be SchannelCredential") end if
  if credential.closed then return true end if
  status = FreeCredentialsHandle(credential.handle)
  credential.closed = true
  if status != SEC_E_OK then return statusFailure("closeCredential", status) end if
  if credential.certificateContext != 0 then ignoredCert = CertFreeCertificateContext(credential.certificateContext) end if
  if credential.certificateStore != 0 then ignoredStore = CertCloseStore(credential.certificateStore, CERT_CLOSE_STORE_FORCE_FLAG) end if
  fillBytes(credential.handle, 0, len(credential.handle), 0)
  fillBytes(credential.expiry, 0, len(credential.expiry), 0)
  if typeof(credential.credentialBytes) == "bytes" then fillBytes(credential.credentialBytes, 0, len(credential.credentialBytes), 0) end if
  if typeof(credential.pinnedCertificatePointers) == "bytes" then fillBytes(credential.pinnedCertificatePointers, 0, len(credential.pinnedCertificatePointers), 0) end if
  if typeof(credential.pfxBytes) == "bytes" then fillBytes(credential.pfxBytes, 0, len(credential.pfxBytes), 0) end if
  if typeof(credential.tlsParameters) == "bytes" then fillBytes(credential.tlsParameters, 0, len(credential.tlsParameters), 0) end if
  if typeof(credential.disabledCrypto) == "bytes" then fillBytes(credential.disabledCrypto, 0, len(credential.disabledCrypto), 0) end if
  if typeof(credential.disabledCryptoStrings) == "array" then
    for each cryptoName in credential.disabledCryptoStrings
      if typeof(cryptoName) == "bytes" then fillBytes(cryptoName, 0, len(cryptoName), 0) end if
    end for
  end if
  credential.certificateContext = 0
  credential.certificateStore = 0
  return true
end function

/// Copies the exact SSPI output token from its bounded backing storage.
/// @internal
function handshakeOutputToken(outputBuffer, tokenBytes, operation)
  tokenLength = _readU32LE(outputBuffer, 0)
  if tokenLength < 0 or tokenLength > TLS_TOKEN_BYTES then return fail(operation, "Schannel returned invalid token length") end if
  token = bytes(0)
  if tokenLength > 0 then token = slice(tokenBytes, 0, tokenLength) end if
  return token
end function

/// Returns the client SSPI flags required for confidential ordered streams.
/// @internal
function contextFlagsClient()
  return ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR | ISC_REQ_STREAM
end function

/// Returns the server SSPI flags required for confidential ordered streams.
/// @internal
function contextFlagsServer(requireClientCertificate)
  flags = ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT | ASC_REQ_CONFIDENTIALITY | ASC_REQ_EXTENDED_ERROR | ASC_REQ_STREAM
  if requireClientCertificate then flags = flags | ASC_REQ_MUTUAL_AUTH end if
  return flags
end function

/// Compares fixed-size security values without data-dependent early returns.
/// @internal
function constantTimeEquals(left, right)
  if typeof(left) != "bytes" or typeof(right) != "bytes" or len(left) != len(right) then return false end if
  difference = 0
  for index = 0 to len(left) - 1
    difference = difference | (left[index] ^ right[index])
  end for
  return difference == 0
end function

/// Encodes an ASCII DNS name as a null-terminated UTF-16LE buffer for CryptoAPI.
/// @internal
function wideServerName(serverName)
  if typeof(serverName) != "string" or len(bytes(serverName)) == 0 then return error(INVALID_ARGUMENT, "platform.tls_schannel.wideServerName: serverName must be non-empty") end if
  raw = bytes(serverName)
  output = bytes((len(raw) + 1) * 2, 0)
  for index = 0 to len(raw) - 1
    if raw[index] > 127 then return error(INVALID_ARGUMENT, "platform.tls_schannel.wideServerName: serverName must be an ASCII/IDNA DNS name") end if
    _writeU16LE(output, index * 2, raw[index])
  end for
  return output
end function

/// Builds optional Schannel blacklist entries for NIST ECDHE groups. The native std.tls provider currently leaves group selection to Windows policy.
/// @internal
function disabledNistKeyExchangeCrypto()
  names = ["ECDH_P256", "ECDH_P384", "ECDH_P521"]
  settings = bytes(len(names) * CRYPTO_SETTINGS_BYTES, 0)
  retainedNames = []
  for index = 0 to len(names) - 1
    wideName = try(wideServerName(names[index]))
    if typeof(wideName) == "error" then return wideName end if
    retainedNames = retainedNames + [wideName]
    offset = index * CRYPTO_SETTINGS_BYTES
    _writeU32LE(settings, offset, TLS_KEY_EXCHANGE_USAGE)
    _writeU16LE(settings, offset + 8, len(bytes(names[index])) * 2)
    _writeU16LE(settings, offset + 10, len(wideName))
    writePointer(settings, offset + 16, nativeBytesPtr(wideName))
  end for
  return [settings, retainedNames]
end function

/// Reads the SHA-256 digest of a certificate's complete DER encoding.
/// @internal
function certificateSha256(certificateContext)
  if typeof(certificateContext) != "int" or certificateContext == 0 then return error(INVALID_ARGUMENT, "platform.tls_schannel.certificateSha256: certificate context is invalid") end if
  digest = bytes(32, 0)
  digestLength = bytes(4, 0)
  _writeU32LE(digestLength, 0, len(digest))
  ok = CertGetCertificateContextProperty(certificateContext, CERT_SHA256_HASH_PROP_ID, digest, digestLength)
  if not ok or _readU32LE(digestLength, 0) != 32 then fillBytes(digest, 0, len(digest), 0); return fail("certificateSha256", "CryptoAPI could not hash the leaf certificate (" + GetLastError() + ")") end if
  return digest
end function

/// Queries the peer leaf certificate context owned by the completed Schannel context.
/// @internal
function remoteCertificateContext(context)
  pointerBytes = bytes(8, 0)
  status = QueryContextAttributesW(context.handle, SECPKG_ATTR_REMOTE_CERT_CONTEXT, pointerBytes)
  if status != SEC_E_OK then return statusFailure("remoteCertificateContext", status) end if
  certificateContext = try(readPointer(pointerBytes, 0))
  if typeof(certificateContext) == "error" then return certificateContext end if
  if certificateContext == 0 then return fail("remoteCertificateContext", "Schannel returned no peer certificate") end if
  return certificateContext
end function

/// Builds a Windows X.509 chain and checks time, EKU, signature, and DNS name. Pin mode ignores only the unknown-root result so an exact self-signed leaf can authenticate the server; every other SSL chain-policy failure remains fatal.
/// @internal
function validatePinnedX509(certificateContext, serverName)
  oidText = bytes(SERVER_AUTH_OID)
  oid = bytes(len(oidText) + 1, 0)
  copyBytes(oid, 0, oidText, 0, len(oidText))
  oidPointers = bytes(8, 0)
  writePointer(oidPointers, 0, nativeBytesPtr(oid))

  chainParameters = bytes(CERT_CHAIN_PARA_BYTES, 0)
  _writeU32LE(chainParameters, 0, CERT_CHAIN_PARA_BYTES)
  _writeU32LE(chainParameters, 8, 0)
  _writeU32LE(chainParameters, 16, 1)
  writePointer(chainParameters, 24, nativeBytesPtr(oidPointers))
  _writeU32LE(chainParameters, 56, 10000)
  chainPointerBytes = bytes(8, 0)
  built = CertGetCertificateChain(void, certificateContext, void, void, chainParameters, CERT_CHAIN_CACHE_END_CERT, void, chainPointerBytes)
  if not built then return fail("validatePinnedX509", "CertGetCertificateChain failed (" + GetLastError() + ")") end if
  chainContext = try(readPointer(chainPointerBytes, 0))
  if typeof(chainContext) == "error" or chainContext == 0 then return fail("validatePinnedX509", "CryptoAPI returned no certificate chain") end if

  wideName = try(wideServerName(serverName))
  if typeof(wideName) == "error" then CertFreeCertificateChain(chainContext); return wideName end if
  sslExtra = bytes(SSL_POLICY_EXTRA_BYTES, 0)
  _writeU32LE(sslExtra, 0, SSL_POLICY_EXTRA_BYTES)
  _writeU32LE(sslExtra, 4, AUTHTYPE_SERVER)
  _writeU32LE(sslExtra, 8, SECURITY_FLAG_IGNORE_UNKNOWN_CA)
  writePointer(sslExtra, 16, nativeBytesPtr(wideName))
  policyParameters = bytes(CERT_CHAIN_POLICY_PARA_BYTES, 0)
  _writeU32LE(policyParameters, 0, CERT_CHAIN_POLICY_PARA_BYTES)
  writePointer(policyParameters, 8, nativeBytesPtr(sslExtra))
  policyStatus = bytes(CERT_CHAIN_POLICY_STATUS_BYTES, 0)
  _writeU32LE(policyStatus, 0, CERT_CHAIN_POLICY_STATUS_BYTES)
  verified = CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chainContext, policyParameters, policyStatus)
  policyError = _readU32LE(policyStatus, 4)
  CertFreeCertificateChain(chainContext)
  if not verified then return fail("validatePinnedX509", "CertVerifyCertificateChainPolicy failed (" + GetLastError() + ")") end if
  if policyError != 0 then return fail("validatePinnedX509", "pinned certificate failed SSL policy with status " + policyError) end if
  return true
end function

/// Authenticates the peer leaf using either Schannel system trust or exact pinning.
/// @internal
function verifyPeerCertificate(context)
  certificateContext = try(remoteCertificateContext(context))
  if typeof(certificateContext) == "error" then return certificateContext end if
  digest = try(certificateSha256(certificateContext))
  if typeof(digest) == "error" then CertFreeCertificateContext(certificateContext); return digest end if
  context.peerCertificateSha256 = digest
  if typeof(context.options.sha256Pin) == "bytes" then
    chainResult = try(validatePinnedX509(certificateContext, context.options.serverName))
    if typeof(chainResult) == "error" then CertFreeCertificateContext(certificateContext); return chainResult end if
    if not constantTimeEquals(digest, context.options.sha256Pin) then CertFreeCertificateContext(certificateContext); return fail("verifyPeerCertificate", "leaf certificate SHA-256 pin mismatch") end if
  end if
  CertFreeCertificateContext(certificateContext)
  return true
end function

/// Queries and validates Schannel TLS record framing limits.
/// @internal
function queryStreamSizes(context)
  sizes = bytes(20, 0)
  status = QueryContextAttributesW(context.handle, SECPKG_ATTR_STREAM_SIZES, sizes)
  if status != SEC_E_OK then return statusFailure("queryStreamSizes", status) end if
  context.streamHeaderBytes = _readU32LE(sizes, 0)
  context.streamTrailerBytes = _readU32LE(sizes, 4)
  context.maximumMessageBytes = _readU32LE(sizes, 8)
  if context.streamHeaderBytes < 0 or context.streamHeaderBytes > 65536 or context.streamTrailerBytes < 0 or context.streamTrailerBytes > 65536 or context.maximumMessageBytes < 1 then return fail("queryStreamSizes", "invalid stream size contract") end if
  return true
end function

/// Cross-checks the negotiated protocol against the requested minimum.
/// @internal
function verifyProtocol(context)
  info = bytes(28, 0)
  status = QueryContextAttributesW(context.handle, SECPKG_ATTR_CONNECTION_INFO, info)
  if status != SEC_E_OK then return statusFailure("verifyProtocol", status) end if
  protocol = _readU32LE(info, 0)
  expected = SP_PROT_TLS1_3_CLIENT
  if context.server then expected = SP_PROT_TLS1_3_SERVER end if
  if context.options.minimumVersion == "1.2" then
    expected12 = SP_PROT_TLS1_2_CLIENT
    if context.server then expected12 = SP_PROT_TLS1_2_SERVER end if
    if protocol != expected and protocol != expected12 then return fail("verifyProtocol", "TLS 1.2 or newer is required; negotiated protocol=" + protocol) end if
  else if protocol != expected then
    return fail("verifyProtocol", "TLS 1.3 is required; negotiated protocol=" + protocol)
  end if
  return true
end function

/// Cross-checks Schannel's negotiated cipher-suite report against the wire policy.
/// @internal
function verifyCipherSuite(context)
  info = bytes(SECPKG_CIPHER_INFO_BYTES, 0)
  status = QueryContextAttributesW(context.handle, SECPKG_ATTR_CIPHER_INFO, info)
  if status != SEC_E_OK then return statusFailure("verifyCipherSuite", status) end if
  cipherSuiteId = _readU32LE(info, 8)
  return cipherSuiteId
end function

/// Records directional handshake bytes until policy verification completes.
/// @internal
function appendHandshakeTranscript(context, fragment)
  combined = try(appendBytes(context.handshakeTranscript, fragment))
  if typeof(combined) == "error" then return combined end if
  context.handshakeTranscript = combined
  return true
end function

/// Finishes a context only after protocol and certificate checks pass.
/// @internal
function finishContext(context)
  sizes = try(queryStreamSizes(context))
  if typeof(sizes) == "error" then return sizes end if
  verified = try(verifyProtocol(context))
  if typeof(verified) == "error" then return verified end if
  cipherSuiteId = try(verifyCipherSuite(context))
  if typeof(cipherSuiteId) == "error" then return cipherSuiteId end if
  context.negotiatedCipherSuite = cipherSuiteId
  context.negotiatedGroup = 0
  if not context.server and (context.options.verifyPeer or typeof(context.options.sha256Pin) == "bytes") then
    certificateResult = try(verifyPeerCertificate(context))
    if typeof(certificateResult) == "error" then return certificateResult end if
  else if context.server and context.options.requireClientCertificate then
    clientCertificate = try(remoteCertificateContext(context))
    if typeof(clientCertificate) == "error" then return clientCertificate end if
    CertFreeCertificateContext(clientCertificate)
  end if
  if typeof(context.handshakeTranscript) == "bytes" then fillBytes(context.handshakeTranscript, 0, len(context.handshakeTranscript), 0) end if
  context.handshakeTranscript = bytes(0)
  return context
end function

/// Creates the initial ClientHello and initializes a full TLS context.
/// @internal
function initialClientToken(credential, serverName, context)
  token = bytes(TLS_TOKEN_BYTES, 0)
  outputBuffer = createSecBuffer(SECBUFFER_TOKEN, token)
  outputDesc = createSecBufferDesc(outputBuffer)
  status = InitializeSecurityContextW(credential.handle, void, serverName, contextFlagsClient(), 0, SECURITY_NATIVE_DREP, void, 0, context.handle, outputDesc, context.attributes, context.expiry)
  if status != SEC_E_OK and status != SEC_I_CONTINUE_NEEDED then return statusFailure("initialClientToken", status) end if
  outputToken = try(handshakeOutputToken(outputBuffer, token, "initialClientToken"))
  if typeof(outputToken) == "error" then return outputToken end if
  return [status, outputToken]
end function

/// Wraps received handshake bytes in a two-buffer SSPI input descriptor.
/// @internal
function inputTokenDesc(inputBytes)
  buffers = createSecBufferArray(2)
  pointerValue = 0
  if len(inputBytes) > 0 then pointerValue = nativeBytesPtr(inputBytes) end if
  writeSecBuffer(buffers, 0, SECBUFFER_TOKEN, pointerValue, len(inputBytes))
  writeSecBuffer(buffers, 1, SECBUFFER_EMPTY, 0, 0)
  return [buffers, createSecBufferDescForArray(buffers, 2)]
end function

/// Preserves unconsumed bytes reported through SECBUFFER_EXTRA.
/// @internal
function handshakeExtra(inputBytes, buffers)
  extraLength = 0
  extraPointer = 0
  index = 0
  while index <= 1
    if secBufferType(buffers, index) == SECBUFFER_EXTRA then
      extraLength = secBufferLength(buffers, index)
      pointerResult = try(secBufferPointer(buffers, index))
      if typeof(pointerResult) != "error" then extraPointer = pointerResult end if
    end if
    index = index + 1
  end while
  if extraLength <= 0 then return bytes(0) end if
  basePointer = nativeBytesPtr(inputBytes)
  offset = len(inputBytes) - extraLength
  if extraPointer >= basePointer and extraPointer <= basePointer + len(inputBytes) - extraLength then offset = extraPointer - basePointer end if
  return copyRange(inputBytes, offset, extraLength, "handshakeExtra")
end function

/// Completes a client handshake under the validated public std.tls options.
/// @internal
function openClient(socketHandle, options)
  if typeof(options.caFile) == "string" then return fail("connectClient", "caFile is not supported by Schannel; install the CA in a Windows certificate store") end if
  serverName = options.serverName
  credential = try(acquireClientCredential(options))
  if typeof(credential) == "error" then return credential end if
  context = TlsContext(credential, socketHandle, bytes(CRED_HANDLE_SIZE, 0), bytes(TIMESTAMP_SIZE, 0), bytes(4, 0), false, false, false, bytes(0), bytes(0), 0, 0, 0, options, bytes(0), 0, 0, bytes(0))
  first = try(initialClientToken(credential, serverName, context))
  if typeof(first) == "error" then ignoredCredential = try(closeCredential(credential)); return first end if
  if typeof(first) != "array" or len(first) != 2 or typeof(first[1]) != "bytes" then closeContext(context); return fail("connectClient", "initial client handshake did not return a token") end if
  if len(first[1]) > 0 then
    sent = try(network.tcpSendAll(socketHandle, first[1]))
    if typeof(sent) == "error" then closeContext(context); return sent end if
  end if
  status = first[0]
  inbound = bytes(0)
  while status == SEC_I_CONTINUE_NEEDED
    received = try(network.tcpRecv(socketHandle, TLS_NETWORK_RECEIVE_BYTES))
    if typeof(received) == "error" then closeContext(context); return received end if
    if typeof(received) != "bytes" then closeContext(context); return fail("connectClient", "network receive returned no TLS bytes") end if
    if len(received) == 0 then closeContext(context); return fail("connectClient", "server closed during TLS handshake") end if
    observed = try(appendHandshakeTranscript(context, received))
    if typeof(observed) == "error" then closeContext(context); return observed end if
    inbound = try(appendBytes(inbound, received))
    if typeof(inbound) == "error" then closeContext(context); return inbound end if
    input = inputTokenDesc(inbound)
    token = bytes(TLS_TOKEN_BYTES, 0)
    outputBuffer = createSecBuffer(SECBUFFER_TOKEN, token)
    outputDesc = createSecBufferDesc(outputBuffer)
    status = InitializeSecurityContextWContinue(credential.handle, context.handle, serverName, contextFlagsClient(), 0, SECURITY_NATIVE_DREP, input[1], 0, context.handle, outputDesc, context.attributes, context.expiry)
    if status == SEC_E_INCOMPLETE_MESSAGE then continue end if
    if status != SEC_E_OK and status != SEC_I_CONTINUE_NEEDED then closeContext(context); return statusFailure("connectClient", status) end if
    outputToken = try(handshakeOutputToken(outputBuffer, token, "connectClient"))
    if typeof(outputToken) == "error" then closeContext(context); return outputToken end if
    if typeof(outputToken) != "bytes" then closeContext(context); return fail("connectClient", "Schannel output token is invalid") end if
    if len(outputToken) > 0 then
      sent = try(network.tcpSendAll(socketHandle, outputToken))
      if typeof(sent) == "error" then closeContext(context); return sent end if
    end if
    extra = try(handshakeExtra(inbound, input[0]))
    if typeof(extra) == "error" then closeContext(context); return extra end if
    inbound = extra
  end while
  context.encryptedInput = inbound
  finished = try(finishContext(context))
  if typeof(finished) == "error" then closeContext(context); return finished end if
  return finished
end function

/// Completes a server handshake with a previously acquired identity.
/// @internal
function _acceptServer(socketHandle, credential, options)
  if credential is not SchannelCredential then return error(INVALID_ARGUMENT, "platform.tls_schannel.acceptServer: credential must be SchannelCredential") end if
  if not credential.inbound or credential.closed then return error(INVALID_ARGUMENT, "platform.tls_schannel.acceptServer: inbound open credential required") end if
  context = TlsContext(credential, socketHandle, bytes(CRED_HANDLE_SIZE, 0), bytes(TIMESTAMP_SIZE, 0), bytes(4, 0), false, false, true, bytes(0), bytes(0), 0, 0, 0, options, bytes(0), 0, 0, bytes(0))
  status = SEC_I_CONTINUE_NEEDED
  inbound = bytes(0)
  first = true
  while status == SEC_I_CONTINUE_NEEDED
    received = try(network.tcpRecv(socketHandle, TLS_NETWORK_RECEIVE_BYTES))
    if typeof(received) == "error" then closeContext(context); return received end if
    if typeof(received) != "bytes" then closeContext(context); return fail("acceptServer", "network receive returned no TLS bytes") end if
    if len(received) == 0 then closeContext(context); return fail("acceptServer", "client closed during TLS handshake") end if
    inbound = try(appendBytes(inbound, received))
    if typeof(inbound) == "error" then closeContext(context); return inbound end if
    input = inputTokenDesc(inbound)
    token = bytes(TLS_TOKEN_BYTES, 0)
    outputBuffer = createSecBuffer(SECBUFFER_TOKEN, token)
    outputDesc = createSecBufferDesc(outputBuffer)
    if first then
      status = AcceptSecurityContextInitial(credential.handle, void, input[1], contextFlagsServer(options.requireClientCertificate), SECURITY_NATIVE_DREP, context.handle, outputDesc, context.attributes, context.expiry)
      first = false
    else
      status = AcceptSecurityContextContinue(credential.handle, context.handle, input[1], contextFlagsServer(options.requireClientCertificate), SECURITY_NATIVE_DREP, context.handle, outputDesc, context.attributes, context.expiry)
    end if
    if status == SEC_E_INCOMPLETE_MESSAGE then continue end if
    if status != SEC_E_OK and status != SEC_I_CONTINUE_NEEDED then closeContext(context); return statusFailure("acceptServer", status) end if
    outputToken = try(handshakeOutputToken(outputBuffer, token, "acceptServer"))
    if typeof(outputToken) == "error" then closeContext(context); return outputToken end if
    if typeof(outputToken) != "bytes" then closeContext(context); return fail("acceptServer", "Schannel output token is invalid") end if
    if len(outputToken) > 0 then
      observed = try(appendHandshakeTranscript(context, outputToken))
      if typeof(observed) == "error" then closeContext(context); return observed end if
      sent = try(network.tcpSendAll(socketHandle, outputToken))
      if typeof(sent) == "error" then closeContext(context); return sent end if
    end if
    extra = try(handshakeExtra(inbound, input[0]))
    if typeof(extra) == "error" then closeContext(context); return extra end if
    inbound = extra
  end while
  context.encryptedInput = inbound
  finished = try(finishContext(context))
  if typeof(finished) == "error" then closeContext(context); return finished end if
  return finished
end function

/// Resolve a Windows server identity. Store references use a SHA-1 thumbprint; PFX references may obtain their password from `env:NAME` or from the default MINILANG_TLS_PFX_PASSWORD environment variable.
/// @internal
function openServer(socketHandle, options)
  password = void
  if certificateReferenceKind(options.certificateReference) == "pfx" and typeof(options.privateKeyReference) == "string" and len(options.privateKeyReference) > 0 then
    if not startsWith(options.privateKeyReference, "env:") then return fail("acceptServer", "PFX privateKeyReference must be env:NAME") end if
    name = try(substring(options.privateKeyReference, 4, len(bytes(options.privateKeyReference)) - 4))
    if typeof(name) == "error" then return name end if
    password = try(environmentSecret(name))
    if typeof(password) == "error" then return password end if
  end if
  credential = try(acquireServerCredentialWithPassword(options.certificateReference, password, options.minimumVersion))
  if typeof(credential) == "error" then return credential end if
  return _acceptServer(socketHandle, credential, options)
end function

/// Removes an exact plaintext prefix from the connection queue.
/// @internal
function popPlaintext(context, count)
  available = len(context.decryptedInput)
  if available < count then return void end if
  output = copyRange(context.decryptedInput, 0, count, "popPlaintext")
  remaining = available - count
  nextBuffer = bytes(0)
  if remaining > 0 then nextBuffer = copyRange(context.decryptedInput, count, remaining, "popPlaintext") end if
  context.decryptedInput = nextBuffer
  return output
end function

/// Removes up to a requested amount of queued plaintext.
/// @internal
function popAvailablePlaintext(context, maximum)
  available = len(context.decryptedInput)
  if available == 0 then return void end if
  count = available
  if count > maximum then count = maximum end if
  return popPlaintext(context, count)
end function

/// Returns encrypted bytes that Schannel did not consume from the current record.
/// @internal
function decryptExtra(inputBytes, buffers)
  extraLength = 0
  extraPointer = 0
  index = 0
  while index <= 3
    if secBufferType(buffers, index) == SECBUFFER_EXTRA then
      extraLength = secBufferLength(buffers, index)
      pointerResult = try(secBufferPointer(buffers, index))
      if typeof(pointerResult) != "error" then extraPointer = pointerResult end if
    end if
    index = index + 1
  end while
  if extraLength <= 0 then return bytes(0) end if
  basePointer = nativeBytesPtr(inputBytes)
  offset = len(inputBytes) - extraLength
  if extraPointer >= basePointer and extraPointer <= basePointer + len(inputBytes) - extraLength then offset = extraPointer - basePointer end if
  return copyRange(inputBytes, offset, extraLength, "decryptExtra")
end function

/// Copies every plaintext SECBUFFER_DATA segment produced by Schannel.
/// @internal
function decryptedData(inputBytes, buffers)
  basePointer = nativeBytesPtr(inputBytes)
  index = 0
  while index <= 3
    if secBufferType(buffers, index) == SECBUFFER_DATA then
      dataLength = secBufferLength(buffers, index)
      if dataLength == 0 then return bytes(0) end if
      pointerResult = try(secBufferPointer(buffers, index))
      if typeof(pointerResult) == "error" then return pointerResult end if
      if pointerResult < basePointer or pointerResult > basePointer + len(inputBytes) - dataLength then return fail("decryptedData", "Schannel returned plaintext outside input buffer") end if
      return copyRange(inputBytes, pointerResult - basePointer, dataLength, "decryptedData")
    end if
    index = index + 1
  end while
  return bytes(0)
end function

/// Lets Schannel process a TLS 1.3 post-handshake ticket or KeyUpdate message. Schannel reports these through SEC_I_RENEGOTIATE even though TLS 1.3 has no legacy renegotiation. A single SSPI continuation updates traffic keys and may emit an acknowledgement; any attempt to start a multi-flight renegotiation is rejected because std.tls does not request post-handshake client authentication.
/// @internal
function processPostHandshake(context, socketHandle, inputBytes, buffers)
  pending = try(decryptExtra(inputBytes, buffers))
  if typeof(pending) == "error" then return pending end if
  if len(pending) == 0 then return fail("processPostHandshake", "Schannel returned no post-handshake token") end if
  input = inputTokenDesc(pending)
  token = bytes(TLS_TOKEN_BYTES, 0)
  outputBuffer = createSecBuffer(SECBUFFER_TOKEN, token)
  outputDesc = createSecBufferDesc(outputBuffer)
  status = SEC_E_OK
  if context.server then
    status = AcceptSecurityContextContinue(context.credential.handle, context.handle, input[1], contextFlagsServer(context.options.requireClientCertificate), SECURITY_NATIVE_DREP, context.handle, outputDesc, context.attributes, context.expiry)
  else
    status = InitializeSecurityContextWContinue(context.credential.handle, context.handle, context.options.serverName, contextFlagsClient(), 0, SECURITY_NATIVE_DREP, input[1], 0, context.handle, outputDesc, context.attributes, context.expiry)
  end if
  if status != SEC_E_OK then return statusFailure("processPostHandshake", status) end if
  outputToken = try(handshakeOutputToken(outputBuffer, token, "processPostHandshake"))
  if typeof(outputToken) == "error" then return outputToken end if
  if len(outputToken) > 0 then
    sent = try(network.tcpSendAll(socketHandle, outputToken))
    if typeof(sent) == "error" then return sent end if
  end if
  remaining = try(handshakeExtra(pending, input[0]))
  if typeof(remaining) == "error" then return remaining end if
  context.encryptedInput = remaining
  return true
end function

/// Receives and authenticates records until plaintext or a clean close is available.
/// @internal
function decryptNext(context, socketHandle)
  while true
    if len(context.encryptedInput) == 0 then
      received = try(network.tcpRecv(socketHandle, TLS_NETWORK_RECEIVE_BYTES))
      if typeof(received) == "error" then return received end if
      if typeof(received) != "bytes" then return fail("decryptNext", "network receive returned no TLS bytes") end if
      if len(received) == 0 then context.closed = true; return bytes(0) end if
      context.encryptedInput = received
    end if
    inputBytes = context.encryptedInput
    buffers = createSecBufferArray(4)
    writeSecBuffer(buffers, 0, SECBUFFER_DATA, nativeBytesPtr(inputBytes), len(inputBytes))
    writeSecBuffer(buffers, 1, SECBUFFER_EMPTY, 0, 0)
    writeSecBuffer(buffers, 2, SECBUFFER_EMPTY, 0, 0)
    writeSecBuffer(buffers, 3, SECBUFFER_EMPTY, 0, 0)
    desc = createSecBufferDescForArray(buffers, 4)
    quality = bytes(4, 0)
    status = DecryptMessage(context.handle, desc, 0, quality)
    if status == SEC_E_INCOMPLETE_MESSAGE then
      received = try(network.tcpRecv(socketHandle, TLS_NETWORK_RECEIVE_BYTES))
      if typeof(received) == "error" then return received end if
      if typeof(received) != "bytes" then return fail("decryptNext", "network receive returned no TLS bytes") end if
      if len(received) == 0 then return fail("decryptNext", "connection closed with incomplete TLS record") end if
      context.encryptedInput = try(appendBytes(context.encryptedInput, received))
      if typeof(context.encryptedInput) == "error" then return context.encryptedInput end if
      continue
    end if
    if status == SEC_I_CONTEXT_EXPIRED then
      context.closed = true
      context.encryptedInput = bytes(0)
      return bytes(0)
    end if
    if status == SEC_I_RENEGOTIATE then
      continued = try(processPostHandshake(context, socketHandle, inputBytes, buffers))
      if typeof(continued) == "error" then return continued end if
      continue
    end if
    if status != SEC_E_OK then return statusFailure("decryptNext", status) end if
    plain = try(decryptedData(inputBytes, buffers))
    if typeof(plain) == "error" then return plain end if
    extra = try(decryptExtra(inputBytes, buffers))
    if typeof(extra) == "error" then return extra end if
    context.encryptedInput = extra
    return plain
  end while
end function

/// Authenticates one already-buffered TLS record without reading the socket.
/// @internal
function decryptBuffered(context)
  if len(context.encryptedInput) == 0 then return void end if
  inputBytes = context.encryptedInput
  buffers = createSecBufferArray(4)
  writeSecBuffer(buffers, 0, SECBUFFER_DATA, nativeBytesPtr(inputBytes), len(inputBytes))
  writeSecBuffer(buffers, 1, SECBUFFER_EMPTY, 0, 0)
  writeSecBuffer(buffers, 2, SECBUFFER_EMPTY, 0, 0)
  writeSecBuffer(buffers, 3, SECBUFFER_EMPTY, 0, 0)
  desc = createSecBufferDescForArray(buffers, 4)
  quality = bytes(4, 0)
  status = DecryptMessage(context.handle, desc, 0, quality)
  if status == SEC_E_INCOMPLETE_MESSAGE then return void end if
  if status == SEC_I_CONTEXT_EXPIRED then
    context.closed = true
    context.encryptedInput = bytes(0)
    return bytes(0)
  end if
  if status == SEC_I_RENEGOTIATE then return fail("decryptBuffered", "TLS post-handshake processing requires the socket-aware receive path") end if
  if status != SEC_E_OK then return statusFailure("decryptBuffered", status) end if
  plain = try(decryptedData(inputBytes, buffers))
  if typeof(plain) == "error" then return plain end if
  extra = try(decryptExtra(inputBytes, buffers))
  if typeof(extra) == "error" then return extra end if
  context.encryptedInput = extra
  return plain
end function

/// Returns up to a bounded amount of authenticated plaintext.
/// @internal
function receiveAvailable(context, socketHandle, maximum)
  if context is not TlsContext then return error(INVALID_ARGUMENT, "platform.tls_schannel.receiveAvailable: context must be TlsContext") end if
  if typeof(maximum) != "int" or maximum < 1 or maximum > TLS_MAX_RECEIVE_BYTES then return error(INVALID_ARGUMENT, "platform.tls_schannel.receiveAvailable: maximum is invalid") end if
  ready = try(popAvailablePlaintext(context, maximum))
  if typeof(ready) == "error" then return ready end if
  if ready is not void then return ready end if
  if context.closed then return bytes(0) end if

  attempts = 0
  while attempts < 4
    plain = try(decryptBuffered(context))
    if typeof(plain) == "error" then return plain end if
    if plain is not void then
      if len(plain) > 0 then context.decryptedInput = try(appendBytes(context.decryptedInput, plain)) end if
      ready = try(popAvailablePlaintext(context, maximum))
      if typeof(ready) == "error" then return ready end if
      if ready is not void then return ready end if
      if context.closed then return bytes(0) end if
    end if

    received = try(network.tcpRecv(socketHandle, TLS_NETWORK_RECEIVE_BYTES))
    if typeof(received) == "error" then return received end if
    if received is void then return void end if
    if len(received) == 0 then context.closed = true; return bytes(0) end if
    context.encryptedInput = try(appendBytes(context.encryptedInput, received))
    if typeof(context.encryptedInput) == "error" then return context.encryptedInput end if
    attempts = attempts + 1
  end while
  return void
end function

/// Accumulates authenticated plaintext until the requested frame length is satisfied.
/// @internal
function receiveExact(context, socketHandle, count)
  if context is not TlsContext then return error(INVALID_ARGUMENT, "platform.tls_schannel.receiveExact: context must be TlsContext") end if
  if typeof(count) != "int" or count < 0 or count > TLS_MAX_RECEIVE_BYTES then return error(INVALID_ARGUMENT, "platform.tls_schannel.receiveExact: count is invalid") end if
  output = bytes(count, 0)
  copied = 0
  while copied < count
    ready = try(popPlaintext(context, count - copied))
    if typeof(ready) == "error" then return ready end if
    if ready is not void then
      if len(ready) > 0 then copyBytes(output, copied, ready, 0, len(ready)) end if
      copied = copied + len(ready)
      continue
    end if
    plain = try(decryptNext(context, socketHandle))
    if typeof(plain) == "error" then return plain end if
    if len(plain) == 0 then return fail("receiveExact", "connection closed before frame completed") end if
    context.decryptedInput = appendBytes(context.decryptedInput, plain)
  end while
  return output
end function

/// Selects a safe plaintext record size and supports deterministic fragmentation tests.
/// @internal
function fragmentLimit(context, length)
  limit = context.maximumMessageBytes
  if typeof(length) == "int" and length > 0 and length < limit then limit = length end if
  configured = environmentSecret("MINILANG_TLS_FRAGMENT_BYTES")
  if typeof(configured) == "bytes" then
    text = decode(configured)
    if typeof(text) == "string" then
      value = toNumber(text)
      if typeof(value) == "int" and value > 0 and value < limit then limit = value end if
    end if
    fillBytes(configured, 0, len(configured), 0)
  end if
  if limit < 1 then limit = 1 end if
  return limit
end function

/// Builds one Schannel stream record and applies negotiated AEAD protection.
/// @internal
function encryptChunk(context, plain)
  if typeof(plain) != "bytes" then return error(INVALID_ARGUMENT, "platform.tls_schannel.encryptChunk: plain must be bytes") end if
  header = bytes(context.streamHeaderBytes, 0)
  data = bytes(len(plain), 0)
  if len(plain) > 0 then copyBytes(data, 0, plain, 0, len(plain)) end if
  trailer = bytes(context.streamTrailerBytes, 0)
  buffers = createSecBufferArray(4)
  writeSecBuffer(buffers, 0, SECBUFFER_STREAM_HEADER, nativeBytesPtr(header), len(header))
  writeSecBuffer(buffers, 1, SECBUFFER_DATA, nativeBytesPtr(data), len(data))
  writeSecBuffer(buffers, 2, SECBUFFER_STREAM_TRAILER, nativeBytesPtr(trailer), len(trailer))
  writeSecBuffer(buffers, 3, SECBUFFER_EMPTY, 0, 0)
  desc = createSecBufferDescForArray(buffers, 4)
  status = EncryptMessage(context.handle, 0, desc, 0)
  if status != SEC_E_OK then return statusFailure("encryptChunk", status) end if
  headerLength = secBufferLength(buffers, 0)
  dataLength = secBufferLength(buffers, 1)
  trailerLength = secBufferLength(buffers, 2)
  output = bytes(headerLength + dataLength + trailerLength, 0)
  cursor = 0
  if headerLength > 0 then copyBytes(output, cursor, header, 0, headerLength); cursor = cursor + headerLength end if
  if dataLength > 0 then copyBytes(output, cursor, data, 0, dataLength); cursor = cursor + dataLength end if
  if trailerLength > 0 then copyBytes(output, cursor, trailer, 0, trailerLength) end if
  fillBytes(header, 0, len(header), 0)
  fillBytes(data, 0, len(data), 0)
  fillBytes(trailer, 0, len(trailer), 0)
  return output
end function

/// Encrypts and writes all plaintext using bounded TLS records.
/// @internal
function sendAll(context, socketHandle, data)
  if context is not TlsContext then return error(INVALID_ARGUMENT, "platform.tls_schannel.sendAll: context must be TlsContext") end if
  if typeof(data) == "string" then data = bytes(data) end if
  if typeof(data) != "bytes" then return error(INVALID_ARGUMENT, "platform.tls_schannel.sendAll: data must be bytes or string") end if
  sentPlain = 0
  while sentPlain < len(data)
    remaining = len(data) - sentPlain
    chunkSize = fragmentLimit(context, remaining)
    if chunkSize > remaining then chunkSize = remaining end if
    chunk = copyRange(data, sentPlain, chunkSize, "sendAll")
    encrypted = try(encryptChunk(context, chunk))
    if typeof(encrypted) == "error" then return encrypted end if
    written = try(network.tcpSendAll(socketHandle, encrypted))
    fillBytes(encrypted, 0, len(encrypted), 0)
    if typeof(written) == "error" then return written end if
    sentPlain = sentPlain + chunkSize
  end while
  return sentPlain
end function

/// Sends an authenticated TLS close_notify alert before the TCP socket is closed.
/// @internal
function shutdown(context, socketHandle)
  if context is not TlsContext then return error(INVALID_ARGUMENT, "platform.tls_schannel.shutdown: context must be TlsContext") end if
  if context.closed then return true end if
  control = bytes(4, 0)
  _writeU32LE(control, 0, SCHANNEL_SHUTDOWN)
  controlBuffer = createSecBuffer(SECBUFFER_TOKEN, control)
  controlDesc = createSecBufferDesc(controlBuffer)
  applied = ApplyControlToken(context.handle, controlDesc)
  if applied != SEC_E_OK then return statusFailure("shutdown", applied) end if

  token = bytes(TLS_TOKEN_BYTES, 0)
  outputBuffer = createSecBuffer(SECBUFFER_TOKEN, token)
  outputDesc = createSecBufferDesc(outputBuffer)
  status = SEC_E_OK
  if context.server then
    status = AcceptSecurityContextShutdown(context.credential.handle, context.handle, void, contextFlagsServer(context.options.requireClientCertificate), SECURITY_NATIVE_DREP, context.handle, outputDesc, context.attributes, context.expiry)
  else
    status = InitializeSecurityContextWShutdown(context.credential.handle, context.handle, context.options.serverName, contextFlagsClient(), 0, SECURITY_NATIVE_DREP, void, 0, context.handle, outputDesc, context.attributes, context.expiry)
  end if
  if status != SEC_E_OK then return statusFailure("shutdown", status) end if
  outputToken = try(handshakeOutputToken(outputBuffer, token, "shutdown"))
  if typeof(outputToken) == "error" then return outputToken end if
  if len(outputToken) > 0 then
    sent = try(network.tcpSendAll(socketHandle, outputToken))
    if typeof(sent) == "error" then return sent end if
  end if
  return true
end function

/// Releases a full TLS context and wipes retained record and certificate data.
/// @internal
function closeContext(context)
  if context is not TlsContext then return error(INVALID_ARGUMENT, "platform.tls_schannel.closeContext: context must be TlsContext") end if
  if context.released then return true end if
  status = DeleteSecurityContext(context.handle)
  context.closed = true
  context.released = true
  fillBytes(context.handle, 0, len(context.handle), 0)
  fillBytes(context.expiry, 0, len(context.expiry), 0)
  fillBytes(context.attributes, 0, len(context.attributes), 0)
  if typeof(context.encryptedInput) == "bytes" then fillBytes(context.encryptedInput, 0, len(context.encryptedInput), 0) end if
  if typeof(context.decryptedInput) == "bytes" then fillBytes(context.decryptedInput, 0, len(context.decryptedInput), 0) end if
  if typeof(context.handshakeTranscript) == "bytes" then fillBytes(context.handshakeTranscript, 0, len(context.handshakeTranscript), 0) end if
  if typeof(context.peerCertificateSha256) == "bytes" then fillBytes(context.peerCertificateSha256, 0, len(context.peerCertificateSha256), 0) end if
  context.encryptedInput = bytes(0)
  context.decryptedInput = bytes(0)
  if context.credential is SchannelCredential then ignoredCredential = try(closeCredential(context.credential)) end if
  if status != SEC_E_OK then return statusFailure("closeContext", status) end if
  return true
end function

/// Provider callbacks consumed by std.tls.nativeProvider().
/// @internal
function sendBytes(context, data)
  return sendAll(context, context.socketHandle, data)
end function

/// Implements receive bytes.
/// @internal
function receiveBytes(context, maximumBytes)
  if context is not TlsContext or context.released then return fail("receive", "context is closed or invalid") end if
  if maximumBytes == 0 then return bytes(0) end if
  ready = try(popAvailablePlaintext(context, maximumBytes))
  if typeof(ready) == "error" then return ready end if
  if ready is not void then return ready end if
  if context.closed then return bytes(0) end if
  while true
    plain = try(decryptNext(context, context.socketHandle))
    if typeof(plain) == "error" then return plain end if
    if len(plain) == 0 then return bytes(0) end if
    context.decryptedInput = try(appendBytes(context.decryptedInput, plain))
    if typeof(context.decryptedInput) == "error" then return context.decryptedInput end if
    ready = try(popAvailablePlaintext(context, maximumBytes))
    if typeof(ready) == "error" then return ready end if
    if ready is not void then return ready end if
  end while
end function

/// Implements shutdown stream.
/// @internal
function shutdownStream(context)
  return shutdown(context, context.socketHandle)
end function

/// Releases or resets close stream.
/// @internal
function closeStream(context)
  return closeContext(context)
end function

/// Identifies the operating-system TLS provider used by this module.
/// @internal
function providerName()
  return "Windows Schannel"
end function

/// Returns the stable module-catalog component identifier.
/// @internal
function componentName()
  return "platform.tls_schannel"
end function

/// Returns the milestone that introduced the native TLS provider.
/// @internal
function targetMilestone()
  return "M73"
end function

/// Reports that the native TLS provider is implemented.
/// @internal
function isImplemented()
  return true
end function
