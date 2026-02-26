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

package std.net

const NET_ERR = 200

function _netErr(msg)
  return error(NET_ERR, msg)
end function

// ------------------------------------------------------------
// std.net (native WinSock / Windows)
//
// Design goals:
// - Minimal, dependency-free TCP/UDP helpers.
// - IPv4-only for now (simple + fast; no getaddrinfo yet).
// - Blocking sockets (simple). You can build higher-level protocols on top.
//
// Notes:
// - Always call init() once before using sockets (helpers do this for you).
// - Socket handles are returned as `ptr` (Win64 SOCKET).
// ------------------------------------------------------------

// ---------------------------
// WinSock constants
// ---------------------------

const AF_INET = 2
const SOCK_STREAM = 1
const SOCK_DGRAM = 2

const IPPROTO_TCP = 6
const IPPROTO_UDP = 17

const INVALID_SOCKET = -1
const SOCKET_ERROR = -1

const SOL_SOCKET = 0xFFFF
const SO_REUSEADDR = 0x0004

const SD_RECEIVE = 0
const SD_SEND = 1
const SD_BOTH = 2

// MAKEWORD(2,2)
const WSA_VERSION_2_2 = 0x0202

// sockaddr_in size
const SOCKADDR_IN_SIZE = 16

// ---------------------------
// WinSock externs
// ---------------------------

extern function WSAStartup(version as int, wsaData as bytes) from "ws2_32.dll" returns int
extern function WSACleanup() from "ws2_32.dll" returns int
extern function WSAGetLastError() from "ws2_32.dll" returns int

extern function socket(af as int, type as int, protocol as int) from "ws2_32.dll" returns ptr
extern function closesocket(s as ptr) from "ws2_32.dll" returns int

extern function connect(s as ptr, addr as bytes, addrlen as int) from "ws2_32.dll" returns int
extern function bind(s as ptr, addr as bytes, addrlen as int) from "ws2_32.dll" returns int
extern function listen(s as ptr, backlog as int) from "ws2_32.dll" returns int
extern function accept(s as ptr, addr as bytes, addrlen as bytes) from "ws2_32.dll" returns ptr

extern function send(s as ptr, buf as bytes, len as int, flags as int) from "ws2_32.dll" returns int
extern function recv(s as ptr, buf as bytes, len as int, flags as int) from "ws2_32.dll" returns int

extern function sendto(s as ptr, buf as bytes, len as int, flags as int, addr as bytes, addrlen as int) from "ws2_32.dll" returns int
extern function recvfrom(s as ptr, buf as bytes, len as int, flags as int, addr as bytes, addrlen as bytes) from "ws2_32.dll" returns int

extern function shutdown(s as ptr, how as int) from "ws2_32.dll" returns int

extern function setsockopt(s as ptr, level as int, optname as int, optval as bytes, optlen as int) from "ws2_32.dll" returns int

// inet_addr parses dotted IPv4; returns address in network byte order (INADDR_NONE=0xFFFFFFFF on error)
extern function inet_addr(addr as cstr) from "ws2_32.dll" returns u32

// ---------------------------
// Internal state
// ---------------------------

_wsaReady = false

// In the native backend, extern return type `ptr` is represented as a MiniLang
// int (TAG_INT). Therefore socket handles appear as type "int" to MiniLang.
// We accept both "int" and "ptr" here to keep the API stable.
function _isSockHandle(x)
  t = typeof(x)
  return t == "int" or t == "ptr"
end function

/*
Initializes WinSock (WSAStartup). Safe to call multiple times.
input: (none)
returns: bool ready
*/
function init()
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
end function

/*
Cleans up WinSock (WSACleanup).
input: (none)
returns: bool success
*/
function cleanup()
  if _wsaReady == false then
    return true
  end if

  rc = WSACleanup()
  if rc != 0 then
    return false
  end if

  _wsaReady = false
  return true
end function

/*
Returns the last WinSock error code (WSAGetLastError).
input: (none)
returns: int errorCode
*/
function lastError()
  return WSAGetLastError()
end function

// ---------------------------
// sockaddr helpers (IPv4)
// ---------------------------

/*
Builds a sockaddr_in (IPv4) for connect/bind.
input: u32 ipv4NetworkOrder, int port
returns: bytes sockaddrIn (16 bytes)
*/
function _sockaddrIn(ipv4, port)
  a = bytes(SOCKADDR_IN_SIZE, 0)

  // sin_family (u16) in host order (little endian on Windows)
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

/*
Parses a dotted IPv4 string (or "localhost") using inet_addr.
input: string host
returns: u32 ipv4NetworkOrder OR void on failure
*/
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

/*
Converts an IPv4 address stored in sockaddr_in bytes to dotted string.
input: bytes sockaddrIn
returns: string ipv4
*/
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

/*
Extracts port (host order int) from sockaddr_in bytes.
input: bytes sockaddrIn
returns: int port
*/
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

// ---------------------------
// TCP
// ---------------------------

/*
Creates a TCP connection to an IPv4 address (dotted) or "localhost".
input: string host, int port
returns: Result socketPtr
*/
function tcpConnect(host, port)
  if init() == false then
    return _netErr("net.init failed")
  end if
  if typeof(port) != "int" then
    return _netErr("tcpConnect: port must be int")
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

/*
Creates a TCP listening socket on 0.0.0.0:port.
input: int port, int backlog
returns: Result serverSocketPtr
*/
function tcpListen(port, backlog)
  if init() == false then
    return _netErr("net.init failed")
  end if
  if typeof(port) != "int" then
    return _netErr("tcpListen: port must be int")
  end if
  if typeof(backlog) != "int" then
    backlog = 16
  end if

  s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
  if s == INVALID_SOCKET then
    return _netErr("tcpListen: socket failed (" + lastError() + ")")
  end if

  // Best-effort reuseaddr.
  opt = bytes(4, 0)
  opt[0] = 1
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, opt, 4)

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

/*
Accepts a client connection on a listening socket.
input: ptr serverSocket
returns: Result clientSocketPtr
*/
function tcpAccept(serverSocket)
  if not _isSockHandle(serverSocket) then
    return _netErr("tcpAccept: serverSocket must be ptr")
  end if

  // Ignore peer address for this simple wrapper.
  c = accept(serverSocket, 0, 0)
  if c == INVALID_SOCKET then
    return _netErr("tcpAccept: accept failed (" + lastError() + ")")
  end if

  return c
end function

/*
Accepts a client connection and returns peer info.
input: ptr serverSocket
returns: Result array [ptr clientSocket, string peerIp, int peerPort]
*/
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

/*
Sends all bytes on a TCP socket (loops until everything is sent).
input: ptr socket, bytes data
returns: Result int bytesSent
*/
function tcpSendAll(sock, data)
  if not _isSockHandle(sock) then
    return _netErr("tcpSendAll: sock must be ptr")
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

/*
Receives up to maxBytes from a TCP socket.
input: ptr socket, int maxBytes
returns: Result bytes data (empty bytes = connection closed)
*/
function tcpRecv(sock, maxBytes)
  if not _isSockHandle(sock) then
    return _netErr("tcpRecv: sock must be ptr")
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

/*
Shuts down a TCP socket (best-effort).
input: ptr socket, int how (SD_RECEIVE/SD_SEND/SD_BOTH)
returns: bool success
*/
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

/*
Closes a socket handle.
input: ptr socket
returns: bool success
*/
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

/*
Opens a UDP socket.
input: (none)
returns: Result socketPtr
*/
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

/*
Binds a UDP socket to 0.0.0.0:port.
input: ptr socket, int port
returns: Result bool success
*/
function udpBind(sock, port)
  if not _isSockHandle(sock) then
    return _netErr("udpBind: sock must be ptr")
  end if
  if typeof(port) != "int" then
    return _netErr("udpBind: port must be int")
  end if

  addr = _sockaddrIn(0, port)
  rc = bind(sock, addr, len(addr))
  if rc != 0 then
    return _netErr("udpBind: bind failed (" + lastError() + ")")
  end if

  return true
end function

/*
Sends a UDP datagram to an IPv4 host.
input: ptr socket, string host, int port, bytes data
returns: Result int bytesSent
*/
function udpSendTo(sock, host, port, data)
  if not _isSockHandle(sock) then
    return _netErr("udpSendTo: sock must be ptr")
  end if
  if typeof(port) != "int" then
    return _netErr("udpSendTo: port must be int")
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

/*
Receives a UDP datagram.
input: ptr socket, int maxBytes
returns: Result array [bytes data, string peerIp, int peerPort]
*/
function udpRecvFrom(sock, maxBytes)
  if not _isSockHandle(sock) then
    return _netErr("udpRecvFrom: sock must be ptr")
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
