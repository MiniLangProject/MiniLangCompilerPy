// Exercise the stateful standard-library facades without changing the raw APIs.
import std.fs as fs
import std.io.file as file
import std.net as net
import std.process as process
import std.tls as tls

function _check(condition, label)
  if condition then return true end if
  print "[FAIL] " + label
  return false
end function

function _openClient(socket, options) return socket end function
function _openServer(socket, options) return socket end function
function _send(state, data) return len(data) end function
function _receive(state, limit) return bytes("tls-ok") end function
function _shutdown(state) return true end function
// Deliberately shares the native libc symbol name: std.io.file must resolve
// its own qualified import rather than this unrelated user callback.
function _close(state) return true end function

function main(args)
  path = "stdlib-oop-" + process.id() + ".bin"
  handle = file.FileHandle.create(path)
  if typeof(handle) == "error" then return 1 end if
  payload = bytes([1, 2, 3, 4, 5])
  if not _check(handle.writeAt(0, payload, 0, len(payload)) == 5, "file method write") then return 2 end if
  if not _check(handle.size() == 5 and handle.flush() == true, "file method size/flush") then return 3 end if
  output = bytes(5, 0)
  if not _check(handle.readExactAt(0, output, 0, 5) == 5 and output == payload, "file method read") then return 4 end if
  if not _check(file.readAt(handle, 0, output, 0, 5) == 5, "file functional interop") then return 5 end if
  if not _check(handle.truncate(3) == true and handle.size() == 3, "file method truncate") then return 6 end if
  if not _check(handle.append(bytes([6, 7]), 0, 2) == 3 and handle.size() == 5, "file method append") then return 6 end if
  if not _check(handle.lock("exclusive", false) == true and handle.unlock() == true, "file method lock") then return 6 end if
  if not _check(handle.close() == true and handle.close() == true and handle.isClosed(), "file close idempotence") then return 7 end if
  if not _check(typeof(try(handle.readAt(0, output, 0, 1))) == "error", "closed file rejection") then return 8 end if
  reader = file.FileHandle.openRead(path)
  if not _check(typeof(reader) != "error" and reader.size() == 5 and reader.close(), "file static openRead") then return 8 end if
  durable = file.FileHandle.openReadWriteDurable(path, false)
  if not _check(typeof(durable) != "error" and durable.close(), "file static durable open") then return 8 end if
  newPath = path + ".new"
  created = file.FileHandle.createNewDurable(newPath)
  if not _check(typeof(created) != "error" and created.close() and fs.delete(newPath), "file static durable create") then return 8 end if
  if not _check(fs.delete(path), "file cleanup") then return 9 end if

  provider = tls.provider("oop-test", _openClient, _openServer, _send, _receive, _shutdown, _close)
  stream = tls.connectClient(provider, 7, tls.clientOptions("localhost"))
  if not _check(stream is tls.Stream and stream.sendAll(bytes("hello")) == 5, "TLS method send") then return 10 end if
  if not _check(stream.receive(8) == bytes("tls-ok") and stream.shutdown(), "TLS method receive/shutdown") then return 11 end if
  if not _check(stream.close() == true and stream.close() == true and stream.isClosed(), "TLS method close") then return 12 end if
  if not _check(typeof(try(stream.sendAll(bytes("x")))) == "error", "closed TLS rejection") then return 13 end if

  port = 21000 + (process.id() % 30000)
  listener = void
  for attempt = 0 to 10
    listener = net.TcpListener.listenAddress("127.0.0.1", port + attempt, 2)
    if typeof(listener) != "error" then port = port + attempt; break end if
  end for
  if typeof(listener) == "error" then return 14 end if
  client = net.TcpConnection.connect("127.0.0.1", port)
  if typeof(client) == "error" then listener.close(); return 15 end if
  borrowedStream = tls.connectClient(provider, client.rawHandle(), tls.clientOptions("localhost"))
  if not _check(borrowedStream.close() and not client.isClosed(), "TLS borrows TCP socket") then return 15 end if
  accepted = listener.acceptPeer()
  if typeof(accepted) == "error" then client.close(); listener.close(); return 16 end if
  server = accepted[0]
  if not _check(accepted[1] == "127.0.0.1" and accepted[2] > 0, "TCP peer") then return 17 end if
  if not _check(client.setNoDelay(true) and client.setReceiveTimeout(1000) and server.setReceiveTimeout(1000), "TCP options") then return 18 end if
  if not _check(client.sendAll(bytes("ping")) == 4, "TCP method send") then return 19 end if
  buffer = bytes(8, 0)
  if not _check(server.receiveInto(buffer, 2, 4) == 4 and buffer == bytes([0, 0, 112, 105, 110, 103, 0, 0]), "TCP method receiveInto") then return 20 end if
  if not _check(server.sendAll(bytes("pong")) == 4 and client.receive(4) == bytes("pong"), "TCP method receive") then return 21 end if

  client2 = net.TcpConnection.connect("127.0.0.1", port)
  server2 = listener.accept()
  if not _check(server2 is net.TcpConnection and client2.sendAll(bytes("ok")) == 2 and server2.receive(2) == bytes("ok"), "TCP accept method") then return 21 end if
  if not _check(client2.close() and server2.close(), "TCP accepted ownership") then return 21 end if

  if not _check(client.close() and client.close() and server.close() and listener.close(), "TCP method close") then return 22 end if
  if not _check(client.isClosed() and server.isClosed() and listener.isClosed(), "TCP closed state") then return 23 end if
  if not _check(typeof(try(client.rawHandle())) == "error" and typeof(try(listener.accept())) == "error", "closed TCP rejection") then return 24 end if

  udp = net.UdpSocket.open()
  if typeof(udp) == "error" then return 25 end if
  if not _check(udp.bind(port) and udp.setReceiveTimeout(1000), "UDP method bind") then return 26 end if
  if not _check(udp.sendTo("127.0.0.1", port, bytes("datagram")) == 8, "UDP method send") then return 27 end if
  datagram = udp.receiveFrom(16)
  if not _check(datagram[0] == bytes("datagram") and datagram[1] == "127.0.0.1", "UDP method receive") then return 28 end if
  if not _check(udp.sendTo("127.0.0.1", port, bytes("xy")) == 2, "UDP second send") then return 28 end if
  packet = bytes(4, 0)
  received = udp.receiveFromInto(packet, 1, 2)
  if not _check(received[0] == 2 and packet == bytes([0, 120, 121, 0]), "UDP receiveInto method") then return 28 end if
  if not _check(udp.close() and udp.close() and udp.isClosed(), "UDP method close") then return 29 end if
  if not _check(typeof(try(udp.sendTo("127.0.0.1", port, bytes("x")))) == "error", "closed UDP rejection") then return 30 end if

  print "STD OOP SERVICES [OK]"
  return 0
end function
