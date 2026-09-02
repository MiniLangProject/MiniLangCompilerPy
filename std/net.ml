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

//! Provides the std net package.

package std.net

/// Track the max portable socket timeout ms value used by this standard-library module.
const MAX_PORTABLE_SOCKET_TIMEOUT_MS = 2147483647

/// Track the net err value used by this standard-library module.
const NET_ERR = 200

/// Construct a consistent networking argument or socket error.
/// @internal
function _netErr(msg)
  return error(NET_ERR, msg)
end function

// ------------------------------------------------------------
// std.net (native WinSock on Windows, BSD sockets on Linux)
//
// Design goals:
// - Minimal, dependency-free TCP/UDP helpers.
// - IPv4-only for now (simple + fast; no getaddrinfo yet).
// - Blocking sockets (simple). You can build higher-level protocols on top.
//
// Notes:
// - Always call init() once before using sockets (helpers do this for you).
// - Socket handles are exposed as MiniLang integers on both native ABIs.
// ------------------------------------------------------------

/// Portable socket constants plus the few target-specific option values.
const AF_INET = 2
/// Track the sock stream value used by this standard-library module.
const SOCK_STREAM = 1
/// Track the sock dgram value used by this standard-library module.
const SOCK_DGRAM = 2

/// Track the ipproto tcp value used by this standard-library module.
const IPPROTO_TCP = 6
/// Track the ipproto udp value used by this standard-library module.
const IPPROTO_UDP = 17

/// Track the invalid socket value used by this standard-library module.
const INVALID_SOCKET = -1
/// Track the socket error value used by this standard-library module.
const SOCKET_ERROR = -1

#if TARGET_OS == "windows"
/// Track the sol socket value used by this standard-library module.
const SOL_SOCKET = 0xFFFF
/// Track the so reuseaddr value used by this standard-library module.
const SO_REUSEADDR = 0x0004
/// Track the so exclusiveaddruse value used by this standard-library module.
const SO_EXCLUSIVEADDRUSE = -5
/// Track the so keepalive value used by this standard-library module.
const SO_KEEPALIVE = 0x0008
/// Track the so sndtimeo value used by this standard-library module.
const SO_SNDTIMEO = 0x1005
/// Track the so rcvtimeo value used by this standard-library module.
const SO_RCVTIMEO = 0x1006
#else
/// Track the sol socket value used by this standard-library module.
const SOL_SOCKET = 1
/// Track the so reuseaddr value used by this standard-library module.
const SO_REUSEADDR = 2
/// Track the so keepalive value used by this standard-library module.
const SO_KEEPALIVE = 9
/// Track the so sndtimeo value used by this standard-library module.
const SO_SNDTIMEO = 21
/// Track the so rcvtimeo value used by this standard-library module.
const SO_RCVTIMEO = 20
#endif
/// Track the tcp nodelay value used by this standard-library module.
const TCP_NODELAY = 1

/// Track the sd receive value used by this standard-library module.
const SD_RECEIVE = 0
/// Track the sd send value used by this standard-library module.
const SD_SEND = 1
/// Track the sd both value used by this standard-library module.
const SD_BOTH = 2

/// MAKEWORD(2,2).
const WSA_VERSION_2_2 = 0x0202

/// Sockaddr_in size.
const SOCKADDR_IN_SIZE = 16

// ---------------------------
// Platform socket externs. Public helpers below deliberately keep one API.
// ---------------------------

#if TARGET_OS == "windows"
/// Provide the wsastartup operation for this standard-library module.
/// @internal
extern function WSAStartup(version as int, wsaData as bytes) from "ws2_32.dll" returns int
/// Provide the wsacleanup operation for this standard-library module.
/// @internal
extern function WSACleanup() from "ws2_32.dll" returns int
/// Provide the wsaget last error operation for this standard-library module.
/// @internal
extern function WSAGetLastError() from "ws2_32.dll" returns int

/// Provide the socket operation for this standard-library module.
/// @internal
extern function socket(af as int, type as int, protocol as int) from "ws2_32.dll" returns ptr
/// Releases or resets closesocket.
/// @internal
extern function closesocket(s as ptr) from "ws2_32.dll" returns int

/// Provide the connect operation for this standard-library module.
/// @internal
extern function connect(s as ptr, addr as bytes, addrlen as int) from "ws2_32.dll" returns int
/// Provide the bind operation for this standard-library module.
/// @internal
extern function bind(s as ptr, addr as bytes, addrlen as int) from "ws2_32.dll" returns int
/// Provide the listen operation for this standard-library module.
/// @internal
extern function listen(s as ptr, backlog as int) from "ws2_32.dll" returns int
/// Provide the accept operation for this standard-library module.
/// @internal
extern function accept(s as ptr, addr as bytes, addrlen as bytes) from "ws2_32.dll" returns ptr
/// Provide the accept no address operation for this standard-library module.
/// @internal
extern function acceptNoAddress(s as ptr, addr as ptr, addrlen as ptr) from "ws2_32.dll" symbol "accept" returns ptr

/// Provide the send operation for this standard-library module.
/// @internal
extern function send(s as ptr, buf as bytes, len as int, flags as int) from "ws2_32.dll" returns int
/// Provide the recv operation for this standard-library module.
/// @internal
extern function recv(s as ptr, buf as bytes, len as int, flags as int) from "ws2_32.dll" returns int

/// Provide the sendto operation for this standard-library module.
/// @internal
extern function sendto(s as ptr, buf as bytes, len as int, flags as int, addr as bytes, addrlen as int) from "ws2_32.dll" returns int
/// Provide the recvfrom operation for this standard-library module.
/// @internal
extern function recvfrom(s as ptr, buf as bytes, len as int, flags as int, addr as bytes, addrlen as bytes) from "ws2_32.dll" returns int

/// Provide the shutdown operation for this standard-library module.
/// @internal
extern function shutdown(s as ptr, how as int) from "ws2_32.dll" returns int

/// Updates setsockopt.
/// @internal
extern function setsockopt(s as ptr, level as int, optname as int, optval as bytes, optlen as int) from "ws2_32.dll" returns int
/// Returns getsockopt.
/// @internal
extern function getsockopt(s as ptr, level as int, optname as int, optval as bytes, optlen as bytes) from "ws2_32.dll" returns int

/// Inet_addr parses dotted IPv4; returns address in network byte order (INADDR_NONE=0xFFFFFFFF on error).
/// @internal
extern function inet_addr(addr as cstr) from "ws2_32.dll" returns u32
#else
/// Provide the socket operation for this standard-library module.
/// @internal
extern function socket(af as int, type as int, protocol as int) from "libc.so.6" returns i32
/// Releases or resets closesocket.
/// @internal
extern function closesocket(s as int) from "libc.so.6" symbol "close" returns i32
/// Provide the connect operation for this standard-library module.
/// @internal
extern function connect(s as int, addr as bytes, addrlen as u32) from "libc.so.6" returns i32
/// Provide the bind operation for this standard-library module.
/// @internal
extern function bind(s as int, addr as bytes, addrlen as u32) from "libc.so.6" returns i32
/// Provide the listen operation for this standard-library module.
/// @internal
extern function listen(s as int, backlog as int) from "libc.so.6" returns i32
/// Provide the accept operation for this standard-library module.
/// @internal
extern function accept(s as int, addr as bytes, addrlen as bytes) from "libc.so.6" returns i32
/// Provide the accept no address operation for this standard-library module.
/// @internal
extern function acceptNoAddress(s as int, addr as ptr, addrlen as ptr) from "libc.so.6" symbol "accept" returns i32
/// Provide the send operation for this standard-library module.
/// @internal
extern function send(s as int, buf as bytes, len as u64, flags as int) from "libc.so.6" returns i64
/// Provide the recv operation for this standard-library module.
/// @internal
extern function recv(s as int, buf as bytes, len as u64, flags as int) from "libc.so.6" returns i64
/// Provide the sendto operation for this standard-library module.
/// @internal
extern function sendto(s as int, buf as bytes, len as u64, flags as int, addr as bytes, addrlen as u32) from "libc.so.6" returns i64
/// Provide the recvfrom operation for this standard-library module.
/// @internal
extern function recvfrom(s as int, buf as bytes, len as u64, flags as int, addr as bytes, addrlen as bytes) from "libc.so.6" returns i64
/// Provide the shutdown operation for this standard-library module.
/// @internal
extern function shutdown(s as int, how as int) from "libc.so.6" returns i32
/// Updates setsockopt.
/// @internal
extern function setsockopt(s as int, level as int, optname as int, optval as bytes, optlen as u32) from "libc.so.6" returns i32
/// Provide the inet addr operation for this standard-library module.
/// @internal
extern function inet_addr(addr as cstr) from "libc.so.6" returns u32
/// Provide the errno location operation for this standard-library module.
/// @internal
extern function _errnoLocation() from "libc.so.6" symbol "__errno_location" returns ptr
/// Provide the copy errno operation for this standard-library module.
/// @internal
extern function _copyErrno(destination as bytes, source as ptr, count as u64) from "libc.so.6" symbol "memcpy" returns ptr
#endif

// ---------------------------
// Internal state
// ---------------------------

// init() and cleanup() serialize this process-wide Winsock ownership flag on
// the same recursive monitor. Ordinary socket operations may call init()
// concurrently, but applications must not call cleanup() while sockets remain
// in use.
_wsaReady = false

/// In the native backend, extern return type `ptr` is represented as a MiniLang int (TAG_INT). Therefore socket handles appear as type "int" to MiniLang. We accept both "int" and "ptr" here to keep the API stable.
/// @internal
function _isSockHandle(x)
  t = typeof(x)
  return t == "int" or t == "ptr"
end function

/// Initializes the platform socket layer. Safe to call multiple times.
function synchronized init()
#if TARGET_OS == "windows"
  if _wsaReady == true then
    return true
  end if

  // NOTE: Imported modules require global initializers to be constexpr.
  // WSADATA is only needed during WSAStartup, so we allocate it locally.
  wsaBuf = bytes(512, 0)

  rc = WSAStartup(WSA_VERSION_2_2, wsaBuf)
  if rc != 0 then
    _wsaReady = false
    return false
  end if

  _wsaReady = true
  return true
#else
  _wsaReady = true
  return true
#endif
end function

/// Cleans up the platform socket layer.
function synchronized cleanup()
#if TARGET_OS == "windows"
  if _wsaReady == false then
    return true
  end if

  rc = WSACleanup()
  if rc != 0 then
    return false
  end if

  _wsaReady = false
  return true
#else
  _wsaReady = false
  return true
#endif
end function

/// Returns the last platform socket error code.
function lastError()
#if TARGET_OS == "windows"
  return WSAGetLastError()
#else
  location = _errnoLocation()
  if location == 0 then return 0 end if
  buffer = bytes(4, 0)
  _copyErrno(buffer, location, 4)
  return buffer[0] | (buffer[1] << 8) | (buffer[2] << 16) | (buffer[3] << 24)
#endif
end function

// ---------------------------
// sockaddr helpers (IPv4)
// ---------------------------

/// Builds a sockaddr_in (IPv4) for connect/bind.
/// @internal
function _isValidPort(port)
  return typeof(port) == "int" and port >= 0 and port <= 65535
end function

/// Provide the sockaddr in operation for this standard-library module.
/// @internal
function _sockaddrIn(ipv4, port)
  a = bytes(SOCKADDR_IN_SIZE, 0)

  // sin_family (u16) in host order (little endian on supported x64 targets)
  a[0] = AF_INET
  a[1] = 0

  // sin_port (u16) in network byte order (big endian)
  a[2] =(port >> 8) & 0xFF
  a[3] = port & 0xFF

  // sin_addr (u32) already in network order integer.
  // Store as little-endian bytes so the in-memory bytes become network order.
  a[4] = ipv4 & 0xFF
  a[5] =(ipv4 >> 8) & 0xFF
  a[6] =(ipv4 >> 16) & 0xFF
  a[7] =(ipv4 >> 24) & 0xFF

  // sin_zero[8] already zero.
  return a
end function

/// Parses a dotted IPv4 string (or "localhost") using inet_addr.
/// @internal
function _parseIPv4(host)
  if typeof(host) != "string" then
    return
  end if

  h = host
  if h == "localhost" then
    h = "127.0.0.1"
  end if

  ip = inet_addr(h)

  // inet_addr returns 0xFFFFFFFF for error and also for 255.255.255.255.
  if ip == 0xFFFFFFFF and h != "255.255.255.255" then
    return
  end if

  return ip
end function

/// Converts an IPv4 address stored in sockaddr_in bytes to dotted string.
/// @internal
function _ipv4ToStringFromSockaddr(addr)
  if typeof(addr) != "bytes" then
    return ""
  end if
  if len(addr) < 8 then
    return ""
  end if

  b0 = addr[4]
  b1 = addr[5]
  b2 = addr[6]
  b3 = addr[7]

  return b0 + "." + b1 + "." + b2 + "." + b3
end function

/// Extracts port (host order int) from sockaddr_in bytes.
/// @internal
function _portFromSockaddr(addr)
  if typeof(addr) != "bytes" then
    return 0
  end if
  if len(addr) < 4 then
    return 0
  end if

  // port is stored big-endian in bytes[2..3]
  return addr[2] * 256 + addr[3]
end function

/// Provide the put u32 operation for this standard-library module.
/// @internal
function _putU32(buffer, offset, value)
  buffer[offset] = value & 0xFF
  buffer[offset + 1] = (value >> 8) & 0xFF
  buffer[offset + 2] = (value >> 16) & 0xFF
  buffer[offset + 3] = (value >> 24) & 0xFF
end function

/// Provide the put i64 operation for this standard-library module.
/// @internal
function _putI64(buffer, offset, value)
  i = 0
  while i < 8
    buffer[offset + i] = (value >> (i * 8)) & 0xFF
    i = i + 1
  end while
end function

/// Updates set boolean option.
/// @internal
function _setBooleanOption(sock, level, option, enabled, operation)
  if not _isSockHandle(sock) or typeof(enabled) != "bool" then return _netErr(operation + ": invalid args") end if
  raw = bytes(4, 0)
  if enabled then raw[0] = 1 end if
  if setsockopt(sock, level, option, raw, len(raw)) != 0 then return _netErr(operation + ": setsockopt failed (" + lastError() + ")") end if
  return true
end function

#if TARGET_OS == "windows"
/// Returns get boolean option.
/// @internal
function _getBooleanOption(sock, level, option, operation)
  if not _isSockHandle(sock) then return _netErr(operation + ": invalid socket") end if
  raw = bytes(4, 0)
  rawLength = bytes(4, 0)
  _putU32(rawLength, 0, len(raw))
  if getsockopt(sock, level, option, raw, rawLength) != 0 then return _netErr(operation + ": getsockopt failed (" + lastError() + ")") end if
  return raw[0] != 0
end function
#endif

/// Enable or disable address reuse on an existing socket.
/// @param sock Value supplied for `sock`.
/// @param enabled Value supplied for `enabled`.
function setReuseAddress(sock, enabled)
#if TARGET_OS == "windows"
  // SO_REUSEADDR and SO_EXCLUSIVEADDRUSE are mutually exclusive on Winsock.
  // Explicit reuse therefore opts out of udpBind's exclusive default before
  // applying the caller's requested reuse state.
  if enabled == true then
    exclusive = _setBooleanOption(sock, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, false, "setReuseAddress")
    if typeof(exclusive) == "error" then return exclusive end if
  end if
#endif
  return _setBooleanOption(sock, SOL_SOCKET, SO_REUSEADDR, enabled, "setReuseAddress")
end function

/// Provide the prepare tcp listener operation for this standard-library module.
/// @internal
function _prepareTcpListener(sock, operation)
  // Winsock's SO_REUSEADDR permits unrelated processes to bind the same port
  // and receive each other's traffic. Linux uses the option for prompt restart
  // after TIME_WAIT, while Windows listeners request exclusive ownership.
#if TARGET_OS == "windows"
  return _setBooleanOption(sock, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, true, operation)
#else
  return _setBooleanOption(sock, SOL_SOCKET, SO_REUSEADDR, true, operation)
#endif
end function

/// Provide the prepare udp bind operation for this standard-library module.
/// @internal
function _prepareUdpBind(sock)
  // Winsock also permits overlapping UDP binds unless exclusive ownership is
  // requested. An explicit setReuseAddress(true) deliberately opts out;
  // Linux keeps the previous caller-controlled UDP behavior.
#if TARGET_OS == "windows"
  reuse = _getBooleanOption(sock, SOL_SOCKET, SO_REUSEADDR, "udpBind: inspect socket")
  if typeof(reuse) == "error" then return reuse end if
  if reuse then return true end if
  return _setBooleanOption(sock, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, true, "udpBind: configure socket")
#else
  return true
#endif
end function

/// Enable or disable TCP keepalive probes.
/// @param sock Value supplied for `sock`.
/// @param enabled Value supplied for `enabled`.
function setKeepAlive(sock, enabled)
  return _setBooleanOption(sock, SOL_SOCKET, SO_KEEPALIVE, enabled, "setKeepAlive")
end function

/// Disable or enable Nagle's algorithm for latency-sensitive protocols.
/// @param sock Value supplied for `sock`.
/// @param enabled Value supplied for `enabled`.
function setNoDelay(sock, enabled)
  return _setBooleanOption(sock, IPPROTO_TCP, TCP_NODELAY, enabled, "setNoDelay")
end function

/// Updates set timeout.
/// @internal
function _setTimeout(sock, option, milliseconds, operation)
  if not _isSockHandle(sock) or typeof(milliseconds) != "int" or milliseconds < 0 or milliseconds > MAX_PORTABLE_SOCKET_TIMEOUT_MS then return _netErr(operation + ": invalid args") end if
#if TARGET_OS == "windows"
  raw = bytes(4, 0)
  _putU32(raw, 0, milliseconds)
#else
  raw = bytes(16, 0)
  _putI64(raw, 0, milliseconds / 1000)
  _putI64(raw, 8, (milliseconds % 1000) * 1000)
#endif
  if setsockopt(sock, SOL_SOCKET, option, raw, len(raw)) != 0 then return _netErr(operation + ": setsockopt failed (" + lastError() + ")") end if
  return true
end function

/// Configure the maximum blocking receive duration. Zero restores no timeout.
/// @param sock Value supplied for `sock`.
/// @param milliseconds Maximum duration in milliseconds.
function setReceiveTimeout(sock, milliseconds)
  return _setTimeout(sock, SO_RCVTIMEO, milliseconds, "setReceiveTimeout")
end function

/// Configure the maximum blocking send duration. Zero restores no timeout.
/// @param sock Value supplied for `sock`.
/// @param milliseconds Maximum duration in milliseconds.
function setSendTimeout(sock, milliseconds)
  return _setTimeout(sock, SO_SNDTIMEO, milliseconds, "setSendTimeout")
end function

// ---------------------------
// TCP
// ---------------------------

/// Creates a TCP connection to an IPv4 address (dotted) or "localhost".
/// @param host Value supplied for `host`.
/// @param port Value supplied for `port`.
function tcpConnect(host, port)
  if init() == false then
    return _netErr("net.init failed")
  end if
  if not _isValidPort(port) then
    return _netErr("tcpConnect: port must be int in range 0..65535")
  end if

  ip = _parseIPv4(host)
  if typeof(ip) == "void" then
    return _netErr("tcpConnect: invalid IPv4 host")
  end if

  s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
  if s == INVALID_SOCKET then
    return _netErr("tcpConnect: socket failed (" + lastError() + ")")
  end if

  addr = _sockaddrIn(ip, port)
  rc = connect(s, addr, len(addr))
  if rc != 0 then
    err = lastError()
    closesocket(s)
    return _netErr("tcpConnect: connect failed (" + err + ")")
  end if

  return s
end function

/// Creates a TCP listening socket on 0.0.0.0:port.
/// @param port Value supplied for `port`.
/// @param backlog Value supplied for `backlog`.
function tcpListen(port, backlog)
  if init() == false then
    return _netErr("net.init failed")
  end if
  if not _isValidPort(port) then
    return _netErr("tcpListen: port must be int in range 0..65535")
  end if
  if typeof(backlog) != "int" then
    backlog = 16
  end if

  s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
  if s == INVALID_SOCKET then
    return _netErr("tcpListen: socket failed (" + lastError() + ")")
  end if

  configured = _prepareTcpListener(s, "tcpListen: configure listener")
  if typeof(configured) == "error" then closesocket(s); return configured end if

  addr = _sockaddrIn(0, port)
  rc = bind(s, addr, len(addr))
  if rc != 0 then
    err = lastError()
    closesocket(s)
    return _netErr("tcpListen: bind failed (" + err + ")")
  end if

  rc = listen(s, backlog)
  if rc != 0 then
    err = lastError()
    closesocket(s)
    return _netErr("tcpListen: listen failed (" + err + ")")
  end if

  return s
end function

/// Create an IPv4 listener bound to an explicit dotted address.
/// @param host Value supplied for `host`.
/// @param port Value supplied for `port`.
/// @param backlog Value supplied for `backlog`.
function tcpListenAddress(host, port, backlog)
  if init() == false then return _netErr("net.init failed") end if
  if not _isValidPort(port) then return _netErr("tcpListenAddress: port must be int in range 0..65535") end if
  if typeof(backlog) != "int" then backlog = 16 end if
  ip = _parseIPv4(host)
  if typeof(ip) == "void" then return _netErr("tcpListenAddress: invalid IPv4 host") end if
  server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
  if server == INVALID_SOCKET then return _netErr("tcpListenAddress: socket failed (" + lastError() + ")") end if
  configured = _prepareTcpListener(server, "tcpListenAddress: configure listener")
  if typeof(configured) == "error" then closesocket(server); return configured end if
  address = _sockaddrIn(ip, port)
  if bind(server, address, len(address)) != 0 then
    code = lastError()
    closesocket(server)
    return _netErr("tcpListenAddress: bind failed (" + code + ")")
  end if
  if listen(server, backlog) != 0 then
    code = lastError()
    closesocket(server)
    return _netErr("tcpListenAddress: listen failed (" + code + ")")
  end if
  return server
end function

/// Accepts a client connection on a listening socket.
/// @param serverSocket Value supplied for `serverSocket`.
function tcpAccept(serverSocket)
  if not _isSockHandle(serverSocket) then
    return _netErr("tcpAccept: serverSocket must be ptr")
  end if

  // Ignore peer address for this simple wrapper.
  c = acceptNoAddress(serverSocket, 0, 0)
  if c == INVALID_SOCKET then
    return _netErr("tcpAccept: accept failed (" + lastError() + ")")
  end if

  return c
end function

/// Accepts a client connection and returns peer info.
/// @param serverSocket Value supplied for `serverSocket`.
function tcpAcceptPeer(serverSocket)
  if not _isSockHandle(serverSocket) then
    return _netErr("tcpAcceptPeer: serverSocket must be ptr")
  end if

  addr = bytes(SOCKADDR_IN_SIZE, 0)
  addrLen = bytes(4, 0)
  // addrLen = 16 (little endian)
  addrLen[0] = SOCKADDR_IN_SIZE
  addrLen[1] = 0
  addrLen[2] = 0
  addrLen[3] = 0

  c = accept(serverSocket, addr, addrLen)
  if c == INVALID_SOCKET then
    return _netErr("tcpAcceptPeer: accept failed (" + lastError() + ")")
  end if

  ipStr = _ipv4ToStringFromSockaddr(addr)
  port = _portFromSockaddr(addr)

  return [c, ipStr, port]
end function

/// Sends all bytes on a TCP socket (loops until everything is sent).
/// @param sock Value supplied for `sock`.
/// @param data Data to process.
function tcpSendAll(sock, data)
  if not _isSockHandle(sock) then
    return _netErr("tcpSendAll: invalid socket handle")
  end if

  // Convenience: allow sending UTF-8 text directly.
  if typeof(data) == "string" then
    data = bytes(data)
  end if

  if typeof(data) != "bytes" then
    return _netErr("tcpSendAll: data must be bytes or string")
  end if

  total = 0
  n = len(data)
  if n == 0 then
    return 0
  end if

  // send() takes a pointer to the bytes buffer. We rely on the runtime to pass the internal pointer.
  while total < n
    sent = send(sock, slice(data, total, n - total), n - total, 0)
    if sent == SOCKET_ERROR then
      return _netErr("tcpSendAll: send failed (" + lastError() + ")")
    end if
    total = total + sent
  end while

  return total
end function

/// Receives up to maxBytes from a TCP socket.
/// @param sock Value supplied for `sock`.
/// @param maxBytes Value supplied for `maxBytes`.
function tcpRecv(sock, maxBytes)
  if not _isSockHandle(sock) then
    return _netErr("tcpRecv: invalid socket handle")
  end if
  if typeof(maxBytes) != "int" then
    return _netErr("tcpRecv: maxBytes must be int")
  end if
  if maxBytes <= 0 then
    return bytes(0)
  end if

  buf = bytes(maxBytes)
  got = recv(sock, buf, maxBytes, 0)

  if got == 0 then
    // graceful close
    return bytes(0)
  end if

  if got == SOCKET_ERROR then
    return _netErr("tcpRecv: recv failed (" + lastError() + ")")
  end if

  return slice(buf, 0, got)
end function

/// Shuts down a TCP socket (best-effort).
/// @param sock Value supplied for `sock`.
/// @param how Value supplied for `how`.
function tcpShutdown(sock, how)
  if not _isSockHandle(sock) then
    return false
  end if
  if typeof(how) != "int" then
    how = SD_BOTH
  end if

  rc = shutdown(sock, how)
  return rc == 0
end function

/// Closes a socket handle.
/// @param sock Value supplied for `sock`.
function close(sock)
  if not _isSockHandle(sock) then
    return false
  end if
  rc = closesocket(sock)
  return rc == 0
end function

// ---------------------------
// UDP
// ---------------------------

/// Opens a UDP socket.
function udpOpen()
  if init() == false then
    return _netErr("net.init failed")
  end if

  s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
  if s == INVALID_SOCKET then
    return _netErr("udpOpen: socket failed (" + lastError() + ")")
  end if

  return s
end function

/// Binds a UDP socket to 0.0.0.0:port.
/// @param sock Value supplied for `sock`.
/// @param port Value supplied for `port`.
function udpBind(sock, port)
  if not _isSockHandle(sock) then
    return _netErr("udpBind: invalid socket handle")
  end if
  if not _isValidPort(port) then
    return _netErr("udpBind: port must be int in range 0..65535")
  end if

  configured = _prepareUdpBind(sock)
  if typeof(configured) == "error" then return configured end if

  addr = _sockaddrIn(0, port)
  rc = bind(sock, addr, len(addr))
  if rc != 0 then
    return _netErr("udpBind: bind failed (" + lastError() + ")")
  end if

  return true
end function

/// Sends a UDP datagram to an IPv4 host.
/// @param sock Value supplied for `sock`.
/// @param host Value supplied for `host`.
/// @param port Value supplied for `port`.
/// @param data Data to process.
function udpSendTo(sock, host, port, data)
  if not _isSockHandle(sock) then
    return _netErr("udpSendTo: invalid socket handle")
  end if
  if not _isValidPort(port) then
    return _netErr("udpSendTo: port must be int in range 0..65535")
  end if
  // Convenience: allow sending UTF-8 text directly.
  if typeof(data) == "string" then
    data = bytes(data)
  end if

  if typeof(data) != "bytes" then
    return _netErr("udpSendTo: data must be bytes or string")
  end if

  ip = _parseIPv4(host)
  if typeof(ip) == "void" then
    return _netErr("udpSendTo: invalid IPv4 host")
  end if

  addr = _sockaddrIn(ip, port)
  sent = sendto(sock, data, len(data), 0, addr, len(addr))
  if sent == SOCKET_ERROR then
    return _netErr("udpSendTo: sendto failed (" + lastError() + ")")
  end if

  return sent
end function

/// Receives a UDP datagram.
/// @param sock Value supplied for `sock`.
/// @param maxBytes Value supplied for `maxBytes`.
function udpRecvFrom(sock, maxBytes)
  if not _isSockHandle(sock) then
    return _netErr("udpRecvFrom: invalid socket handle")
  end if
  if typeof(maxBytes) != "int" then
    return _netErr("udpRecvFrom: maxBytes must be int")
  end if
  if maxBytes <= 0 then
    return [bytes(0), "", 0]
  end if

  buf = bytes(maxBytes)

  addr = bytes(SOCKADDR_IN_SIZE, 0)
  addrLen = bytes(4, 0)
  addrLen[0] = SOCKADDR_IN_SIZE

  got = recvfrom(sock, buf, maxBytes, 0, addr, addrLen)
  if got == SOCKET_ERROR then
    return _netErr("udpRecvFrom: recvfrom failed (" + lastError() + ")")
  end if

  ipStr = _ipv4ToStringFromSockaddr(addr)
  port = _portFromSockaddr(addr)

  return [slice(buf, 0, got), ipStr, port]
end function
