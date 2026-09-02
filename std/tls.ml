/*
Copyright 2026 Nils Kopal

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Provider-neutral TLS transport contract.  Native providers (for example
// Schannel or OpenSSL) plug into this module without leaking provider handles
// into application code.
//! Provides the std tls package.

package std.tls
#if TARGET_OS == "windows"
import std.tls._schannel as native
#else
import std.tls._openssl as native
#endif

/// Stores the tls err.
const TLS_ERR = 267

/// Represents client options.
struct ClientOptions
  /// Stores the server name member of `ClientOptions`.
  serverName
  /// Stores the verify peer member of `ClientOptions`.
  verifyPeer
  /// Stores the sha256 pin member of `ClientOptions`.
  sha256Pin
  /// Stores the minimum version member of `ClientOptions`.
  minimumVersion
  /// Stores the ca file member of `ClientOptions`.
  caFile
end struct

/// Represents server options.
struct ServerOptions
  /// Stores the certificate reference member of `ServerOptions`.
  certificateReference
  /// Stores the private key reference member of `ServerOptions`.
  privateKeyReference
  /// Stores the minimum version member of `ServerOptions`.
  minimumVersion
  /// Stores the require client certificate member of `ServerOptions`.
  requireClientCertificate
end struct

/// Represents provider.
struct Provider
  /// Stores the name member of `Provider`.
  name
  /// Stores the open client member of `Provider`.
  openClient
  /// Stores the open server member of `Provider`.
  openServer
  /// Stores the send bytes member of `Provider`.
  sendBytes
  /// Stores the receive bytes member of `Provider`.
  receiveBytes
  /// Stores the shutdown stream member of `Provider`.
  shutdownStream
  /// Stores the close stream member of `Provider`.
  closeStream
end struct

/// Represents stream.
struct Stream
  /// Stores the provider member of `Stream`.
  provider
  /// Stores the state member of `Stream`.
  state
  /// Stores the server side member of `Stream`.
  serverSide
  /// Stores the closed member of `Stream`.
  closed
end struct

/// Implements error.
/// @internal
function _error(message)
  return error(TLS_ERR, message)
end function

/// Implements client options.
/// @param serverName Value supplied for `serverName`.
function clientOptions(serverName)
  return ClientOptions(serverName, true, void, "1.3", void)
end function

/// Implements pinned client options.
/// @param serverName Value supplied for `serverName`.
/// @param sha256Pin Value supplied for `sha256Pin`.
function pinnedClientOptions(serverName, sha256Pin)
  return ClientOptions(serverName, true, sha256Pin, "1.3", void)
end function

/// Implements server options.
/// @param certificateReference Value supplied for `certificateReference`.
/// @param privateKeyReference Value supplied for `privateKeyReference`.
function serverOptions(certificateReference, privateKeyReference)
  return ServerOptions(certificateReference, privateKeyReference, "1.3", false)
end function

/// Implements validate client options.
/// @param options Value supplied for `options`.
function validateClientOptions(options)
  if options is not ClientOptions then return _error("client options are invalid") end if
  if typeof(options.serverName) != "string" or len(options.serverName) == 0 then return _error("server name must be non-empty") end if
  if typeof(options.verifyPeer) != "bool" then return _error("verifyPeer must be bool") end if
  if typeof(options.sha256Pin) != "void" and (typeof(options.sha256Pin) != "bytes" or len(options.sha256Pin) != 32) then return _error("SHA-256 pin must contain 32 bytes") end if
  if typeof(options.sha256Pin) == "bytes" and not options.verifyPeer then return _error("SHA-256 pinning requires peer verification") end if
  if options.minimumVersion != "1.2" and options.minimumVersion != "1.3" then return _error("minimum TLS version must be 1.2 or 1.3") end if
  if typeof(options.caFile) != "void" and typeof(options.caFile) != "string" then return _error("caFile must be string or void") end if
  return true
end function

/// Implements validate server options.
/// @param options Value supplied for `options`.
function validateServerOptions(options)
  if options is not ServerOptions then return _error("server options are invalid") end if
  if typeof(options.certificateReference) != "string" or len(options.certificateReference) == 0 then return _error("certificate reference must be non-empty") end if
  if typeof(options.privateKeyReference) != "void" and typeof(options.privateKeyReference) != "string" then return _error("private-key reference must be string or void") end if
  if options.minimumVersion != "1.2" and options.minimumVersion != "1.3" then return _error("minimum TLS version must be 1.2 or 1.3") end if
  if typeof(options.requireClientCertificate) != "bool" then return _error("requireClientCertificate must be bool") end if
  return true
end function

/// Implements provider.
/// @param name Name of the requested item.
/// @param openClient Value supplied for `openClient`.
/// @param openServer Value supplied for `openServer`.
/// @param sendBytes Value supplied for `sendBytes`.
/// @param receiveBytes Value supplied for `receiveBytes`.
/// @param shutdownStream Value supplied for `shutdownStream`.
/// @param closeStream Value supplied for `closeStream`.
function provider(name, openClient, openServer, sendBytes, receiveBytes, shutdownStream, closeStream)
  if typeof(name) != "string" or len(name) == 0 then return _error("provider name must be non-empty") end if
  callbacks = [openClient, openServer, sendBytes, receiveBytes, shutdownStream, closeStream]
  for each callback in callbacks
    if typeof(callback) != "function" then return _error("provider callbacks must be functions") end if
  end for
  return Provider(name, openClient, openServer, sendBytes, receiveBytes, shutdownStream, closeStream)
end function

/// Return the target-native provider: Schannel on Windows or OpenSSL 3 on Linux.
function nativeProvider()
  return Provider(native.providerName(), native.openClient, native.openServer, native.sendBytes, native.receiveBytes, native.shutdownStream, native.closeStream)
end function

/// Implements native provider name.
function nativeProviderName()
  return native.providerName()
end function

/// Implements connect client.
/// @param activeProvider Value supplied for `activeProvider`.
/// @param socket Value supplied for `socket`.
/// @param options Value supplied for `options`.
function connectClient(activeProvider, socket, options)
  if activeProvider is not Provider then return _error("TLS provider is invalid") end if
  valid = validateClientOptions(options)
  if typeof(valid) == "error" then return valid end if
  state = activeProvider.openClient(socket, options)
  if typeof(state) == "error" then return state end if
  return Stream(activeProvider, state, false, false)
end function

/// Implements accept server.
/// @param activeProvider Value supplied for `activeProvider`.
/// @param socket Value supplied for `socket`.
/// @param options Value supplied for `options`.
function acceptServer(activeProvider, socket, options)
  if activeProvider is not Provider then return _error("TLS provider is invalid") end if
  valid = validateServerOptions(options)
  if typeof(valid) == "error" then return valid end if
  state = activeProvider.openServer(socket, options)
  if typeof(state) == "error" then return state end if
  return Stream(activeProvider, state, true, false)
end function

/// Establish a native TLS client stream over an already-connected std.net socket.
/// @param socket Value supplied for `socket`.
/// @param options Value supplied for `options`.
function connect(socket, options)
  return connectClient(nativeProvider(), socket, options)
end function

/// Accept a native TLS server stream over an already-accepted std.net socket.
/// @param socket Value supplied for `socket`.
/// @param options Value supplied for `options`.
function accept(socket, options)
  return acceptServer(nativeProvider(), socket, options)
end function

/// Reports whether is stream.
/// @param value Value to process.
function isStream(value)
  return value is Stream
end function

/// Implements send all.
/// @param stream Value supplied for `stream`.
/// @param data Data to process.
function sendAll(stream, data)
  if stream is not Stream or stream.closed then return _error("TLS stream is closed or invalid") end if
  if typeof(data) != "bytes" then return _error("TLS payload must be bytes") end if
  total = 0
  while total < len(data)
    written = try(stream.provider.sendBytes(stream.state, slice(data, total, len(data) - total)))
    if typeof(written) == "error" then return written end if
    if typeof(written) != "int" or written <= 0 or written > len(data) - total then
      return _error("TLS provider returned an invalid send count")
    end if
    total = total + written
  end while
  return total
end function

/// Implements receive.
/// @param stream Value supplied for `stream`.
/// @param maximumBytes Value supplied for `maximumBytes`.
function receive(stream, maximumBytes)
  if stream is not Stream or stream.closed then return _error("TLS stream is closed or invalid") end if
  if typeof(maximumBytes) != "int" or maximumBytes < 0 then return _error("maximum receive size is invalid") end if
  result = try(stream.provider.receiveBytes(stream.state, maximumBytes))
  if typeof(result) == "error" then return result end if
  if typeof(result) != "bytes" or len(result) > maximumBytes then return _error("TLS provider returned invalid receive data") end if
  return result
end function

/// Implements shutdown.
/// @param stream Value supplied for `stream`.
function shutdown(stream)
  if stream is not Stream or stream.closed then return true end if
  return stream.provider.shutdownStream(stream.state)
end function

/// Releases or resets close.
/// @param stream Value supplied for `stream`.
function close(stream)
  if stream is not Stream then return _error("TLS stream is invalid") end if
  if stream.closed then return true end if
  result = stream.provider.closeStream(stream.state)
  if typeof(result) == "error" then return result end if
  stream.closed = true
  return true
end function
