import std.net as net
import std.tls as tls
import std.fs as fs
import std.assert as t

function tlsCase(port, mode)
  socket = net.tcpConnect("10.0.2.2", port)
  net.setReceiveTimeout(socket, 15000)
  net.setSendTimeout(socket, 15000)
  options = tls.clientOptions("localhost")
  options.caFile = "/home/user/fixtures/server.crt"
  if mode == 1 then options.minimumVersion = "1.2" end if
  if mode == 2 then options.serverName = "wrong.invalid" end if
  if mode == 3 then options.caFile = "/home/user/fixtures/untrusted.crt" end if
  if mode == 4 or mode == 5 then
    options.sha256Pin = fs.readAllBytes("/home/user/fixtures/server.sha256")
    options.caFile = void
    if mode == 5 then options.sha256Pin[0] = options.sha256Pin[0] ^ 1 end if
  end if
  stream = try(tls.connect(socket, options))
  if mode == 2 or mode == 3 or mode == 5 then
    t.assertEq(typeof(stream), "error", "TLS rejects invalid peer " + mode)
  else
    if typeof(stream) == "error" then print stream.message; return false end if
    payload = bytes(70000, 90)
    t.assertEq(tls.sendAll(stream, payload), len(payload), "TLS bulk send " + mode)
    reply = bytes(0)
    while len(reply) < len(payload)
      chunk = tls.receive(stream, 4096)
      if len(chunk) == 0 then return false end if
      reply = reply + chunk
    end while
    t.assertEq(reply, payload, "TLS bulk echo " + mode)
    tls.shutdown(stream)
    tls.close(stream)
  end if
  net.close(socket)
  return true
end function
function main(args)
  ports = fs.readAllBytes("/home/user/fixtures/ports.bin")
  tcpPort = ports[0] | (ports[1] << 8)
  udpPort = ports[2] | (ports[3] << 8)
  tlsPort = ports[4] | (ports[5] << 8)
  socket = net.tcpConnect("10.0.2.2", tcpPort)
  net.setReceiveTimeout(socket, 15000)
  t.assertEq(net.tcpSendAll(socket, bytes("tcp-ping")), 8, "TCP send")
  t.assertEq(net.tcpRecv(socket, 64), bytes("tcp-pong"), "TCP receive")
  net.close(socket)
  socket = net.udpOpen()
  net.setReceiveTimeout(socket, 15000)
  t.assertEq(net.udpSendTo(socket, "10.0.2.2", udpPort, bytes("udp-ping")), 8, "UDP send")
  reply = net.udpRecvFrom(socket, 64)
  t.assertEq(reply[0], bytes("udp-pong"), "UDP receive")
  net.close(socket)
  for mode = 0 to 5
    if not tlsCase(tlsPort, mode) then return 1 end if
  end for
  listener = net.tcpListenAddress("0.0.0.0", 46544, 4)
  net.setReceiveTimeout(listener, 60000)
  socket = net.tcpAccept(listener)
  net.setReceiveTimeout(socket, 15000)
  net.setSendTimeout(socket, 15000)
  stream = tls.accept(socket, tls.serverOptions("/home/user/fixtures/server.crt", "/home/user/fixtures/server.key"))
  request = bytes(0)
  while len(request) < 70000
    part = tls.receive(stream, 4096)
    if len(part) == 0 then return 2 end if
    request = request + part
  end while
  t.assertEq(request, bytes(70000, 81), "TLS native server receive")
  t.assertEq(tls.sendAll(stream, request), 70000, "TLS native server send")
  tls.shutdown(stream)
  tls.close(stream)
  net.close(socket)
  net.close(listener)
  print "MINUX_NETWORK_TLS_OK"
  return 37
end function
