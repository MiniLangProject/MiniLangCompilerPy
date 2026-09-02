/*
Copyright 2026 Nils Kopal

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Internal OpenSSL 3 transport used by std.tls on Linux.  The public module
// owns argument validation and the Stream wrapper; this module owns SSL_CTX
// and SSL handles but deliberately leaves the TCP socket owned by std.net.
//! Provides the std tls _openssl package.

package std.tls._openssl

/// Track the tls err value used by this standard-library module.
/// @internal
const TLS_ERR = 267
/// Track the ssl filetype pem value used by this standard-library module.
/// @internal
const SSL_FILETYPE_PEM = 1
/// Track the ssl verify none value used by this standard-library module.
/// @internal
const SSL_VERIFY_NONE = 0
/// Track the ssl verify peer value used by this standard-library module.
/// @internal
const SSL_VERIFY_PEER = 1
/// Track the ssl verify fail if no peer cert value used by this standard-library module.
/// @internal
const SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 2
/// Track the ssl error want read value used by this standard-library module.
/// @internal
const SSL_ERROR_WANT_READ = 2
/// Track the ssl error want write value used by this standard-library module.
/// @internal
const SSL_ERROR_WANT_WRITE = 3
/// Track the ssl ctrl set tlsext hostname value used by this standard-library module.
/// @internal
const SSL_CTRL_SET_TLSEXT_HOSTNAME = 55
/// Track the ssl ctrl set min proto version value used by this standard-library module.
/// @internal
const SSL_CTRL_SET_MIN_PROTO_VERSION = 123
/// Track the tlsext nametype host name value used by this standard-library module.
/// @internal
const TLSEXT_NAMETYPE_HOST_NAME = 0
/// Track the tls1 2 version value used by this standard-library module.
/// @internal
const TLS1_2_VERSION = 0x0303
/// Track the tls1 3 version value used by this standard-library module.
/// @internal
const TLS1_3_VERSION = 0x0304
/// Track the x509 v ok value used by this standard-library module.
/// @internal
const X509_V_OK = 0
/// Track the x509 purpose ssl server value used by this standard-library module.
/// @internal
const X509_PURPOSE_SSL_SERVER = 2

/// Represents open ssl state.
/// @internal
struct OpenSslState
  /// Context associated with `OpenSslState`.
  context
  /// Session associated with `OpenSslState`.
  session
  /// Socket associated with `OpenSslState`.
  socket
  /// Server associated with `OpenSslState`.
  server
  /// Closed associated with `OpenSslState`.
  closed
end struct

/// Provide the client method operation for this standard-library module.
/// @internal
extern function _clientMethod() from "libssl.so.3" symbol "TLS_client_method" returns ptr
/// Provide the server method operation for this standard-library module.
/// @internal
extern function _serverMethod() from "libssl.so.3" symbol "TLS_server_method" returns ptr
/// Provide the context new operation for this standard-library module.
/// @internal
extern function _contextNew(method as ptr) from "libssl.so.3" symbol "SSL_CTX_new" returns ptr
/// Provide the context free operation for this standard-library module.
/// @internal
extern function _contextFree(context as ptr) from "libssl.so.3" symbol "SSL_CTX_free" returns void
/// Provide the context control operation for this standard-library module.
/// @internal
extern function _contextControl(context as ptr, command as int, argument as i64, value as ptr) from "libssl.so.3" symbol "SSL_CTX_ctrl" returns i64
/// Provide the context set verify operation for this standard-library module.
/// @internal
extern function _contextSetVerify(context as ptr, mode as int, callback as ptr) from "libssl.so.3" symbol "SSL_CTX_set_verify" returns void
/// Provide the context default verify paths operation for this standard-library module.
/// @internal
extern function _contextDefaultVerifyPaths(context as ptr) from "libssl.so.3" symbol "SSL_CTX_set_default_verify_paths" returns i32
/// Provide the context load verify locations operation for this standard-library module.
/// @internal
extern function _contextLoadVerifyLocations(context as ptr, caFile as cstr, caPath as ptr) from "libssl.so.3" symbol "SSL_CTX_load_verify_locations" returns i32
/// Provide the context use certificate chain operation for this standard-library module.
/// @internal
extern function _contextUseCertificateChain(context as ptr, path as cstr) from "libssl.so.3" symbol "SSL_CTX_use_certificate_chain_file" returns i32
/// Provide the context use private key operation for this standard-library module.
/// @internal
extern function _contextUsePrivateKey(context as ptr, path as cstr, kind as int) from "libssl.so.3" symbol "SSL_CTX_use_PrivateKey_file" returns i32
/// Provide the context check private key operation for this standard-library module.
/// @internal
extern function _contextCheckPrivateKey(context as ptr) from "libssl.so.3" symbol "SSL_CTX_check_private_key" returns i32

/// Provide the session new operation for this standard-library module.
/// @internal
extern function _sessionNew(context as ptr) from "libssl.so.3" symbol "SSL_new" returns ptr
/// Provide the session free operation for this standard-library module.
/// @internal
extern function _sessionFree(session as ptr) from "libssl.so.3" symbol "SSL_free" returns void
/// Provide the session set fd operation for this standard-library module.
/// @internal
extern function _sessionSetFd(session as ptr, socket as int) from "libssl.so.3" symbol "SSL_set_fd" returns i32
/// Provide the session set server name operation for this standard-library module.
/// @internal
extern function _sessionSetServerName(session as ptr, command as int, argument as i64, value as cstr) from "libssl.so.3" symbol "SSL_ctrl" returns i64
/// Provide the session set host operation for this standard-library module.
/// @internal
extern function _sessionSetHost(session as ptr, host as cstr) from "libssl.so.3" symbol "SSL_set1_host" returns i32
/// Provide the session connect operation for this standard-library module.
/// @internal
extern function _sessionConnect(session as ptr) from "libssl.so.3" symbol "SSL_connect" returns i32
/// Provide the session accept operation for this standard-library module.
/// @internal
extern function _sessionAccept(session as ptr) from "libssl.so.3" symbol "SSL_accept" returns i32
/// Provide the session write operation for this standard-library module.
/// @internal
extern function _sessionWrite(session as ptr, input as ptr, length as u64, written as bytes) from "libssl.so.3" symbol "SSL_write_ex" returns i32
/// Provide the session read operation for this standard-library module.
/// @internal
extern function _sessionRead(session as ptr, output as ptr, length as u64, readCount as bytes) from "libssl.so.3" symbol "SSL_read_ex" returns i32
/// Provide the session error operation for this standard-library module.
/// @internal
extern function _sessionError(session as ptr, result as int) from "libssl.so.3" symbol "SSL_get_error" returns i32
/// Provide the session shutdown operation for this standard-library module.
/// @internal
extern function _sessionShutdown(session as ptr) from "libssl.so.3" symbol "SSL_shutdown" returns i32
/// Provide the session verify result operation for this standard-library module.
/// @internal
extern function _sessionVerifyResult(session as ptr) from "libssl.so.3" symbol "SSL_get_verify_result" returns i64
/// Provide the peer certificate operation for this standard-library module.
/// @internal
extern function _peerCertificate(session as ptr) from "libssl.so.3" symbol "SSL_get1_peer_certificate" returns ptr

/// Provide the certificate digest operation for this standard-library module.
/// @internal
extern function _certificateDigest(certificate as ptr, digest as ptr, output as ptr, outputLength as bytes) from "libcrypto.so.3" symbol "X509_digest" returns i32
/// Provide the certificate free operation for this standard-library module.
/// @internal
extern function _certificateFree(certificate as ptr) from "libcrypto.so.3" symbol "X509_free" returns void
/// Provide the certificate check host operation for this standard-library module.
/// @internal
extern function _certificateCheckHost(certificate as ptr, host as cstr, hostLength as u64, flags as u32, peerName as ptr) from "libcrypto.so.3" symbol "X509_check_host" returns i32
/// Provide the certificate check purpose operation for this standard-library module.
/// @internal
extern function _certificateCheckPurpose(certificate as ptr, purpose as int, ca as int) from "libcrypto.so.3" symbol "X509_check_purpose" returns i32
/// Provide the certificate not before operation for this standard-library module.
/// @internal
extern function _certificateNotBefore(certificate as ptr) from "libcrypto.so.3" symbol "X509_get0_notBefore" returns ptr
/// Provide the certificate not after operation for this standard-library module.
/// @internal
extern function _certificateNotAfter(certificate as ptr) from "libcrypto.so.3" symbol "X509_get0_notAfter" returns ptr
/// Provide the certificate compare current time operation for this standard-library module.
/// @internal
extern function _certificateCompareCurrentTime(time as ptr) from "libcrypto.so.3" symbol "X509_cmp_current_time" returns i32
/// Provide the sha256 operation for this standard-library module.
/// @internal
extern function _sha256() from "libcrypto.so.3" symbol "EVP_sha256" returns ptr
/// Provide the next error operation for this standard-library module.
/// @internal
extern function _nextError() from "libcrypto.so.3" symbol "ERR_get_error" returns u64
/// Provide the error text operation for this standard-library module.
/// @internal
extern function _errorText(code as u64, output as bytes, length as u64) from "libcrypto.so.3" symbol "ERR_error_string_n" returns void

/// Provide the fail operation for this standard-library module.
/// @internal
function _fail(operation, message)
  code = _nextError()
  if code != 0 then
    raw = bytes(256, 0)
    _errorText(code, raw, len(raw))
    used = 0
    while used < len(raw) and raw[used] != 0
      used = used + 1
    end while
    nativeMessage = ""
    if used > 0 then nativeMessage = decode(slice(raw, 0, used)) end if
    if typeof(nativeMessage) == "string" and len(nativeMessage) > 0 then message = message + " (" + nativeMessage + ")" end if
  end if
  return error(TLS_ERR, "std.tls/OpenSSL " + operation + ": " + message)
end function

/// Returns get u32.
/// @internal
function _getU32(buffer)
  return buffer[0] | (buffer[1] << 8) | (buffer[2] << 16) | (buffer[3] << 24)
end function

/// Returns get u64.
/// @internal
function _getU64(buffer)
  value = 0
  i = 0
  while i < 8
    value = value | (buffer[i] << (i * 8))
    i = i + 1
  end while
  return value
end function

/// Provide the minimum version operation for this standard-library module.
/// @internal
function _minimumVersion(value)
  if value == "1.2" then return TLS1_2_VERSION end if
  return TLS1_3_VERSION
end function

/// Provide the constant time equals operation for this standard-library module.
/// @internal
function _constantTimeEquals(left, right)
  if typeof(left) != "bytes" or typeof(right) != "bytes" or len(left) != len(right) then return false end if
  difference = 0
  i = 0
  while i < len(left)
    difference = difference | (left[i] ^ right[i])
    i = i + 1
  end while
  return difference == 0
end function

/// Releases or resets release.
/// @internal
function _release(context, session)
  if session != 0 then _sessionFree(session) end if
  if context != 0 then _contextFree(context) end if
end function

/// Provide the configure minimum operation for this standard-library module.
/// @internal
function _configureMinimum(context, version)
  return _contextControl(context, SSL_CTRL_SET_MIN_PROTO_VERSION, _minimumVersion(version), 0) == 1
end function

/// An exact leaf pin is its own trust anchor. Validate the independently useful X.509 properties manually so self-signed pinned deployments do not depend on a machine CA store while still rejecting wrong names, validity windows, and certificates that cannot be used for TLS server authentication.
/// @internal
function _verifyPin(session, expected, serverName)
  if typeof(expected) == "void" then return true end if
  certificate = _peerCertificate(session)
  if certificate == 0 then return _fail("verify", "peer did not provide a certificate") end if
  if _certificateCheckHost(certificate, serverName, len(bytes(serverName)), 0, 0) != 1 then _certificateFree(certificate); return _fail("verify", "pinned certificate hostname mismatch") end if
  if _certificateCheckPurpose(certificate, X509_PURPOSE_SSL_SERVER, 0) != 1 then _certificateFree(certificate); return _fail("verify", "pinned certificate is not valid for TLS server authentication") end if
  notBefore = _certificateNotBefore(certificate)
  notAfter = _certificateNotAfter(certificate)
  if notBefore == 0 or notAfter == 0 or _certificateCompareCurrentTime(notBefore) >= 0 or _certificateCompareCurrentTime(notAfter) <= 0 then _certificateFree(certificate); return _fail("verify", "pinned certificate is outside its validity period") end if
  digest = bytes(32, 0)
  digestLength = bytes(4, 0)
  ok = _certificateDigest(certificate, _sha256(), nativeBytesPtr(digest), digestLength) == 1
  _certificateFree(certificate)
  if not ok or _getU32(digestLength) != 32 then return _fail("verify", "could not hash peer certificate") end if
  if not _constantTimeEquals(digest, expected) then return _fail("verify", "peer certificate SHA-256 pin mismatch") end if
  return true
end function

/// Establish an authenticated client session over an already-connected socket.
/// @internal
function openClient(socket, options)
  context = _contextNew(_clientMethod())
  if context == 0 then return _fail("connect", "SSL_CTX_new failed") end if
  if not _configureMinimum(context, options.minimumVersion) then _release(context, 0); return _fail("connect", "minimum protocol configuration failed") end if

  pinning = typeof(options.sha256Pin) == "bytes"
  if options.verifyPeer and not pinning then
    _contextSetVerify(context, SSL_VERIFY_PEER, 0)
    trusted = 0
    if typeof(options.caFile) == "string" then
      trusted = _contextLoadVerifyLocations(context, options.caFile, 0)
    else
      trusted = _contextDefaultVerifyPaths(context)
    end if
    if trusted != 1 then _release(context, 0); return _fail("connect", "trust-store configuration failed") end if
  else
    _contextSetVerify(context, SSL_VERIFY_NONE, 0)
  end if

  session = _sessionNew(context)
  if session == 0 then _release(context, 0); return _fail("connect", "SSL_new failed") end if
  if _sessionSetFd(session, socket) != 1 then _release(context, session); return _fail("connect", "SSL_set_fd failed") end if
  if _sessionSetServerName(session, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_HOST_NAME, options.serverName) != 1 then
    _release(context, session)
    return _fail("connect", "SNI configuration failed")
  end if
  if options.verifyPeer and not pinning and _sessionSetHost(session, options.serverName) != 1 then _release(context, session); return _fail("connect", "hostname verification configuration failed") end if
  result = _sessionConnect(session)
  if result != 1 then
    sslError = _sessionError(session, result)
    _release(context, session)
    return _fail("connect", "handshake failed, SSL error " + sslError)
  end if
  if options.verifyPeer and not pinning and _sessionVerifyResult(session) != X509_V_OK then _release(context, session); return _fail("connect", "peer certificate validation failed") end if
  pinned = _verifyPin(session, options.sha256Pin, options.serverName)
  if typeof(pinned) == "error" then _release(context, session); return pinned end if
  return OpenSslState(context, session, socket, false, false)
end function

/// Accept a server session using PEM certificate-chain and private-key paths.
/// @internal
function openServer(socket, options)
  if typeof(options.privateKeyReference) != "string" or len(options.privateKeyReference) == 0 then return _fail("accept", "PEM private-key path is required") end if
  context = _contextNew(_serverMethod())
  if context == 0 then return _fail("accept", "SSL_CTX_new failed") end if
  if not _configureMinimum(context, options.minimumVersion) then _release(context, 0); return _fail("accept", "minimum protocol configuration failed") end if
  if _contextUseCertificateChain(context, options.certificateReference) != 1 then _release(context, 0); return _fail("accept", "certificate-chain loading failed") end if
  if _contextUsePrivateKey(context, options.privateKeyReference, SSL_FILETYPE_PEM) != 1 then _release(context, 0); return _fail("accept", "private-key loading failed") end if
  if _contextCheckPrivateKey(context) != 1 then _release(context, 0); return _fail("accept", "certificate and private key do not match") end if
  if options.requireClientCertificate then
    _contextSetVerify(context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0)
    if _contextDefaultVerifyPaths(context) != 1 then _release(context, 0); return _fail("accept", "client trust-store configuration failed") end if
  else
    _contextSetVerify(context, SSL_VERIFY_NONE, 0)
  end if
  session = _sessionNew(context)
  if session == 0 then _release(context, 0); return _fail("accept", "SSL_new failed") end if
  if _sessionSetFd(session, socket) != 1 then _release(context, session); return _fail("accept", "SSL_set_fd failed") end if
  result = _sessionAccept(session)
  if result != 1 then
    sslError = _sessionError(session, result)
    _release(context, session)
    return _fail("accept", "handshake failed, SSL error " + sslError)
  end if
  return OpenSslState(context, session, socket, true, false)
end function

/// Provide the send bytes operation for this standard-library module.
/// @internal
function sendBytes(state, data)
  if state is not OpenSslState or state.closed then return _fail("send", "session is closed or invalid") end if
  if len(data) == 0 then return 0 end if
  count = bytes(8, 0)
  result = _sessionWrite(state.session, nativeBytesPtr(data), len(data), count)
  if result != 1 then return _fail("send", "SSL_write_ex failed, SSL error " + _sessionError(state.session, result)) end if
  return _getU64(count)
end function

/// Provide the receive bytes operation for this standard-library module.
/// @internal
function receiveBytes(state, maximumBytes)
  if state is not OpenSslState or state.closed then return _fail("receive", "session is closed or invalid") end if
  if maximumBytes == 0 then return bytes(0) end if
  output = bytes(maximumBytes, 0)
  count = bytes(8, 0)
  result = _sessionRead(state.session, nativeBytesPtr(output), maximumBytes, count)
  if result == 1 then return slice(output, 0, _getU64(count)) end if
  sslError = _sessionError(state.session, result)
  // The internal provider is also used by event-loop adapters. A nonblocking
  // socket with no complete TLS record is not a transport failure.
  if sslError == SSL_ERROR_WANT_READ or sslError == SSL_ERROR_WANT_WRITE then return void end if
  if sslError == 6 then return bytes(0) end if
  return _fail("receive", "SSL_read_ex failed, SSL error " + sslError)
end function

/// Provide the shutdown stream operation for this standard-library module.
/// @internal
function shutdownStream(state)
  if state is not OpenSslState or state.closed then return true end if
  result = _sessionShutdown(state.session)
  if result < 0 then return _fail("shutdown", "SSL_shutdown failed, SSL error " + _sessionError(state.session, result)) end if
  return true
end function

/// Releases or resets close stream.
/// @internal
function closeStream(state)
  if state is not OpenSslState then return _fail("close", "session is invalid") end if
  if state.closed then return true end if
  _sessionFree(state.session)
  _contextFree(state.context)
  state.session = 0
  state.context = 0
  state.closed = true
  return true
end function

/// Provide the provider name operation for this standard-library module.
/// @internal
function providerName()
  return "OpenSSL 3"
end function
