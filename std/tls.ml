/*
Copyright 2026 Nils Kopal

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Provider-neutral TLS transport contract.  Native providers (for example
// Schannel or OpenSSL) plug into this module without leaking provider handles
// into application code.
package std.tls

const TLS_ERR = 267

struct ClientOptions
  serverName
  verifyPeer
  sha256Pin
  minimumVersion
  caFile
end struct

struct ServerOptions
  certificateReference
  privateKeyReference
  minimumVersion
  requireClientCertificate
end struct

struct Provider
  name
  openClient
  openServer
  sendBytes
  receiveBytes
  shutdownStream
  closeStream
end struct

struct Stream
  provider
  state
  serverSide
  closed
end struct

function _error(message)
  return error(TLS_ERR, message)
end function

function clientOptions(serverName)
  return ClientOptions(serverName, true, void, "1.3", void)
end function

function pinnedClientOptions(serverName, sha256Pin)
  return ClientOptions(serverName, true, sha256Pin, "1.3", void)
end function

function serverOptions(certificateReference, privateKeyReference)
  return ServerOptions(certificateReference, privateKeyReference, "1.3", false)
end function

function validateClientOptions(options)
  if options is not ClientOptions then return _error("client options are invalid") end if
  if typeof(options.serverName) != "string" or len(options.serverName) == 0 then return _error("server name must be non-empty") end if
  if typeof(options.verifyPeer) != "bool" then return _error("verifyPeer must be bool") end if
  if typeof(options.sha256Pin) != "void" and (typeof(options.sha256Pin) != "bytes" or len(options.sha256Pin) != 32) then return _error("SHA-256 pin must contain 32 bytes") end if
  if options.minimumVersion != "1.2" and options.minimumVersion != "1.3" then return _error("minimum TLS version must be 1.2 or 1.3") end if
  if typeof(options.caFile) != "void" and typeof(options.caFile) != "string" then return _error("caFile must be string or void") end if
  return true
end function

function validateServerOptions(options)
  if options is not ServerOptions then return _error("server options are invalid") end if
  if typeof(options.certificateReference) != "string" or len(options.certificateReference) == 0 then return _error("certificate reference must be non-empty") end if
  if typeof(options.privateKeyReference) != "void" and typeof(options.privateKeyReference) != "string" then return _error("private-key reference must be string or void") end if
  if options.minimumVersion != "1.2" and options.minimumVersion != "1.3" then return _error("minimum TLS version must be 1.2 or 1.3") end if
  if typeof(options.requireClientCertificate) != "bool" then return _error("requireClientCertificate must be bool") end if
  return true
end function

function provider(name, openClient, openServer, sendBytes, receiveBytes, shutdownStream, closeStream)
  if typeof(name) != "string" or len(name) == 0 then return _error("provider name must be non-empty") end if
  callbacks = [openClient, openServer, sendBytes, receiveBytes, shutdownStream, closeStream]
  for each callback in callbacks
    if typeof(callback) != "function" then return _error("provider callbacks must be functions") end if
  end for
  return Provider(name, openClient, openServer, sendBytes, receiveBytes, shutdownStream, closeStream)
end function

function connectClient(activeProvider, socket, options)
  if activeProvider is not Provider then return _error("TLS provider is invalid") end if
  valid = validateClientOptions(options)
  if typeof(valid) == "error" then return valid end if
  state = activeProvider.openClient(socket, options)
  if typeof(state) == "error" then return state end if
  return Stream(activeProvider, state, false, false)
end function

function acceptServer(activeProvider, socket, options)
  if activeProvider is not Provider then return _error("TLS provider is invalid") end if
  valid = validateServerOptions(options)
  if typeof(valid) == "error" then return valid end if
  state = activeProvider.openServer(socket, options)
  if typeof(state) == "error" then return state end if
  return Stream(activeProvider, state, true, false)
end function

function isStream(value)
  return value is Stream
end function

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

function receive(stream, maximumBytes)
  if stream is not Stream or stream.closed then return _error("TLS stream is closed or invalid") end if
  if typeof(maximumBytes) != "int" or maximumBytes < 0 then return _error("maximum receive size is invalid") end if
  result = try(stream.provider.receiveBytes(stream.state, maximumBytes))
  if typeof(result) == "error" then return result end if
  if typeof(result) != "bytes" or len(result) > maximumBytes then return _error("TLS provider returned invalid receive data") end if
  return result
end function

function shutdown(stream)
  if stream is not Stream or stream.closed then return true end if
  return stream.provider.shutdownStream(stream.state)
end function

function close(stream)
  if stream is not Stream then return _error("TLS stream is invalid") end if
  if stream.closed then return true end if
  result = stream.provider.closeStream(stream.state)
  if typeof(result) == "error" then return result end if
  stream.closed = true
  return true
end function
