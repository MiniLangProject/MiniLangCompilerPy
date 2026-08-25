import std.net as net
import std.tls as tls

const PORT = 46543

function failResult(label, value)
  if typeof(value) == "error" then print "[FAIL] " + label + ": " + value.message else print "[FAIL] " + label end if
  return 1
end function

function main(args)
  listener = net.tcpListenAddress("127.0.0.1", PORT, 4)
  if typeof(listener) == "error" then return failResult("listen", listener) end if
  socket = net.tcpAccept(listener)
  if typeof(socket) == "error" then net.close(listener); return failResult("accept TCP", socket) end if
#if TARGET_OS == "windows"
  options = tls.serverOptions("pfx:build/tls-test/server.pfx", "env:MINILANG_TLS_TEST_PASSWORD")
#else
  options = tls.serverOptions("build/tls-test/server.crt", "build/tls-test/server.key")
#endif
  stream = tls.accept(socket, options)
  if typeof(stream) == "error" then net.close(socket); net.close(listener); return failResult("accept TLS", stream) end if
  request = tls.receive(stream, 64)
  if typeof(request) == "error" or request != bytes("ping") then tls.close(stream); net.close(socket); net.close(listener); return failResult("receive", request) end if
  sent = tls.sendAll(stream, bytes("pong"))
  if sent != 4 then tls.close(stream); net.close(socket); net.close(listener); return failResult("send", sent) end if
  tls.shutdown(stream)
  tls.close(stream)
  net.close(socket)
  net.close(listener)
  print "=== NATIVE TLS SERVER DONE ==="
  return 0
end function
