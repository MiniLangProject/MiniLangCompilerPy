/*
Copyright 2026 Nils Kopal

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Measure std.tls.sendAll's first-call copying without network or crypto cost.
import std.time as time
import std.tls as tls

observed = 0

function benchmarkOpenClient(socket, options) return socket end function
function benchmarkOpenServer(socket, options) return socket end function
function benchmarkSendBytes(state, data)
  global observed
  observed = observed + data[0]
  return len(data)
end function
function benchmarkReceiveBytes(state, maximumBytes) return bytes(0) end function
function benchmarkShutdown(state) return true end function
function benchmarkClose(state) return true end function

function main(args)
  provider = tls.provider("benchmark", benchmarkOpenClient, benchmarkOpenServer, benchmarkSendBytes, benchmarkReceiveBytes, benchmarkShutdown, benchmarkClose)
  stream = tls.connectClient(provider, 7, tls.clientOptions("localhost"))
  if typeof(stream) == "error" then return 1 end if
  payload = bytes(65536, 0x5A)
  total = 0
  started = time.ticks()
  for i = 0 to 999999
    sent = tls.sendAll(stream, payload)
    if sent != len(payload) then return 2 end if
    total = total + sent
  end for
  elapsed = time.ticks() - started
  if not tls.shutdown(stream) or not tls.close(stream) or total != 65536000000 or observed != 90000000 then return 3 end if
  print "calls=1000000 bytes_per_call=65536 elapsed_ms=" + elapsed
  return 0
end function
