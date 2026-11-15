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
//! Native Mbed TLS provider for MinUX; sockets remain owned by std.net.
package std.tls._minux

/// Retain the native TLS session and its closed state.
/// @internal
struct State
  session
  closed
end struct

/// Create and negotiate a native TLS client session.
/// @internal
extern function _client(socket as int, hostname as cstr, verify as int, pin as ptr, pinLength as int, minimum as int, caFile as cstr) from "libminilang_minux.so" symbol "mlt_client" returns ptr
/// Create and negotiate a native TLS server session.
/// @internal
extern function _server(socket as int, certificate as cstr, key as cstr, minimum as int, requireClient as int) from "libminilang_minux.so" symbol "mlt_server" returns ptr
/// Send a native TLS application-data range.
/// @internal
extern function _write(session as ptr, input as ptr, length as u64) from "libminilang_minux.so" symbol "mlt_write" returns i32
/// Receive native TLS application data.
/// @internal
extern function _read(session as ptr, output as ptr, length as u64) from "libminilang_minux.so" symbol "mlt_read" returns i32
/// Send the native TLS close notification.
/// @internal
extern function _shutdown(session as ptr) from "libminilang_minux.so" symbol "mlt_shutdown" returns i32
/// Release a native TLS session.
/// @internal
extern function _close(session as ptr) from "libminilang_minux.so" symbol "mlt_close" returns void
/// Copy the last native session error.
/// @internal
extern function _errorText(session as ptr, output as bytes, length as u64) from "libminilang_minux.so" symbol "mlt_error" returns i32

/// Convert the native error into a standard-library error value.
/// @internal
function _failed(operation, session)
  text = bytes(256, 0)
  _errorText(session, text, len(text))
  return error(267, "MinUX TLS " + operation + ": " + decodeZ(text))
end function

/// Open a TLS client with the public client options.
/// @internal
function openClient(socket, options)
  pin = 0
  pinLength = 0
  if typeof(options.sha256Pin) == "bytes" then pin = nativeBytesPtr(options.sha256Pin); pinLength = len(options.sha256Pin) end if
  caFile = ""
  if typeof(options.caFile) == "string" then caFile = options.caFile end if
  minimum = 13
  if options.minimumVersion == "1.2" then minimum = 12 end if
  verify = 0
  if options.verifyPeer then verify = 1 end if
  session = _client(socket, options.serverName, verify, pin, pinLength, minimum, caFile)
  if session == 0 then return error(267, "MinUX TLS connect: handshake or certificate validation failed") end if
  return State(session, false)
end function

/// Accept TLS using the public server options.
/// @internal
function openServer(socket, options)
  if typeof(options.privateKeyReference) != "string" then return error(267, "MinUX TLS accept: private-key file required") end if
  minimum = 13
  if options.minimumVersion == "1.2" then minimum = 12 end if
  requireClient = 0
  if options.requireClientCertificate then requireClient = 1 end if
  session = _server(socket, options.certificateReference, options.privateKeyReference, minimum, requireClient)
  if session == 0 then return error(267, "MinUX TLS accept: credentials or handshake failed") end if
  return State(session, false)
end function

/// Send an entire managed byte buffer.
/// @internal
function sendBytes(state, data)
  return sendRange(state, data, 0, len(data))
end function
/// Send a validated managed byte range.
/// @internal
function sendRange(state, data, offset, length)
  if state is not State or state.closed then return error(267, "MinUX TLS send: closed stream") end if
  if typeof(data) != "bytes" or offset < 0 or length < 0 or offset > len(data) or length > len(data) - offset then return error(267, "MinUX TLS send: invalid range") end if
  if length == 0 then return 0 end if
  result = _write(state.session, nativeBytesPtr(data) + offset, length)
  if result < 0 then return _failed("send", state.session) end if
  return result
end function
/// Receive at most the requested number of TLS bytes.
/// @internal
function receiveBytes(state, maximumBytes)
  if state is not State or state.closed then return error(267, "MinUX TLS receive: closed stream") end if
  if maximumBytes == 0 then return bytes(0) end if
  output = bytes(maximumBytes, 0)
  result = _read(state.session, nativeBytesPtr(output), maximumBytes)
  if result < 0 then return _failed("receive", state.session) end if
  if result == maximumBytes then return output end if
  return slice(output, 0, result)
end function
/// Send close notification for an open stream.
/// @internal
function shutdownStream(state)
  if state is not State or state.closed then return true end if
  if _shutdown(state.session) < 0 then return _failed("shutdown", state.session) end if
  return true
end function
/// Release a provider stream once.
/// @internal
function closeStream(state)
  if state is not State then return error(267, "MinUX TLS close: invalid stream") end if
  if state.closed then return true end if
  _close(state.session)
  state.session = 0
  state.closed = true
  return true
end function
/// Identify the native TLS implementation.
/// @internal
function providerName()
  return "Mbed TLS 3.6 / MinUX"
end function
