import std.fs as fs
import std.net as net
import std.tls as tls

const PORT = 46543

function failResult(label, value)
  if typeof(value) == "error" then print "[FAIL] " + label + ": " + value.message else print "[FAIL] " + label end if
  return 1
end function

function main(args)
  socket = net.tcpConnect("127.0.0.1", PORT)
  if typeof(socket) == "error" then return failResult("connect TCP", socket) end if
  serverName = "localhost"
  if len(args) > 0 and args[0] == "bad-host" then serverName = "not-localhost" end if
  options = tls.clientOptions(serverName)
#if TARGET_OS == "windows"
  pin = fs.readAllBytes("build/tls-test/server.sha256")
  if typeof(pin) == "error" then net.close(socket); return failResult("read pin", pin) end if
  options.sha256Pin = pin
#else
  options.caFile = "build/tls-test/server.crt"
#endif
  stream = tls.connect(socket, options)
  if typeof(stream) == "error" then net.close(socket); return failResult("connect TLS", stream) end if
  sent = tls.sendAll(stream, bytes("ping"))
  if sent != 4 then tls.close(stream); net.close(socket); return failResult("send", sent) end if
  response = tls.receive(stream, 64)
  if typeof(response) == "error" or response != bytes("pong") then tls.close(stream); net.close(socket); return failResult("receive", response) end if
  tls.shutdown(stream)
  tls.close(stream)
  net.close(socket)
  print "=== NATIVE TLS CLIENT DONE ==="
  return 0
end function
