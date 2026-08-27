import std.console as console
import std.crypto as crypto
import std.encoding.hex as hex
import std.fs as fs
import std.io.file as file
import std.net as net
import std.path as path
import std.platform as platform
import std.process as process
import std.tls as tls
import std.uuid as uuid

function fakeTlsOpenClient(socket, options) return [socket, options.serverName] end function
function fakeTlsOpenServer(socket, options) return [socket, options.certificateReference] end function
// Deliberately short-write to verify that the public transport completes sends.
function fakeTlsSend(state, data)
  if len(data) > 2 then return 2 end if
  return len(data)
end function
function fakeTlsReceive(state, maximumBytes) return bytes("tls") end function
function fakeTlsShutdown(state) return true end function
function fakeTlsClose(state) return true end function

function check(condition, label)
  if not condition then print "[FAIL] " + label; return false end if
  print "[OK] " + label
  return true
end function

function main(args)
  failed = false
  if not check(platform.architecture() == "x64", "platform architecture") then failed = true end if
  if not check(path.fileName(path.join("alpha", "beta.txt")) == "beta.txt", "path join/name") then failed = true end if
  if not check(path.extension("alpha.beta") == ".beta", "path extension") then failed = true end if
  if not check(process.id() > 0, "process id") then failed = true end if
  executablePath = process.executablePath()
  if not check(typeof(executablePath) == "string" and len(executablePath) > 0, "process executable path") then failed = true end if
  if not check(typeof(process.currentDirectory()) == "string", "process current directory") then failed = true end if
  if not check(typeof(process.environment("PATH")) == "string", "process environment") then failed = true end if
  if not check(typeof(console.disableQuickEdit()) != "error", "console platform setup") then failed = true end if
  derived = crypto.pbkdf2Sha256(bytes("password"), bytes("salt"), 1, 32)
  if not check(hex.encode(derived) == "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b", "PBKDF2-SHA-256 vector") then failed = true end if
  identifier = uuid.v4()
  if not check(typeof(identifier) == "string" and uuid.isValid(identifier), "UUID v4") then failed = true end if
  listener = net.tcpListenAddress("127.0.0.1", 0, 4)
  if typeof(listener) == "error" then print "[FAIL] network listener: " + listener.message; return 6 end if
  if not check(net.setReceiveTimeout(listener, 1000) == true, "network receive timeout") then failed = true end if
  if not check(net.setSendTimeout(listener, 1000) == true, "network send timeout") then failed = true end if
  if not check(net.setKeepAlive(listener, true) == true, "network keepalive") then failed = true end if
  if not check(net.setNoDelay(listener, true) == true, "network no-delay") then failed = true end if
  if not check(net.close(listener), "network close") then failed = true end if
  provider = tls.provider("test", fakeTlsOpenClient, fakeTlsOpenServer, fakeTlsSend, fakeTlsReceive, fakeTlsShutdown, fakeTlsClose)
  stream = tls.connectClient(provider, 7, tls.clientOptions("localhost"))
  if not check(tls.isStream(stream), "TLS provider contract") then failed = true end if
  if not check(tls.sendAll(stream, bytes("abc")) == 3 and tls.receive(stream, 16) == bytes("tls"), "TLS stream contract") then failed = true end if
  if not check(tls.shutdown(stream) == true and tls.close(stream) == true, "TLS stream lifecycle") then failed = true end if
  if not check(typeof(tls.nativeProviderName()) == "string" and len(tls.nativeProviderName()) > 0, "TLS native provider selection") then failed = true end if
  invalidPinned = tls.clientOptions("localhost")
  invalidPinned.verifyPeer = false
  invalidPinned.sha256Pin = bytes(32, 0)
  invalidPinnedResult = try(tls.validateClientOptions(invalidPinned))
  if not check(typeof(invalidPinnedResult) == "error", "TLS pin validation is fail-closed") then failed = true end if

  directory = "platform-services-" + process.id()
  sourcePath = path.join(directory, "source.bin")
  destinationPath = path.join(directory, "published.bin")
  createdDirectory = file.createDirectory(directory)
  if not check(createdDirectory == true, "file create directory") then return 2 end if
  handle = file.createDurable(sourcePath)
  if typeof(handle) == "error" then print "[FAIL] file create: " + handle.message; return 3 end if
  payload = bytes([1, 2, 3, 4, 5, 6])
  if not check(file.writeAt(handle, 0, payload, 0, len(payload)) == len(payload), "file positional write") then failed = true end if
  if not check(file.flush(handle) == true, "file flush") then failed = true end if
  if not check(file.size(handle) == len(payload), "file size") then failed = true end if
  output = bytes(len(payload), 0)
  if not check(file.readExactAt(handle, 0, output, 0, len(output)) == len(output), "file positional read") then failed = true end if
  if not check(output == payload, "file roundtrip") then failed = true end if
  if not check(file.lock(handle, "exclusive", false) == true, "file exclusive lock") then failed = true end if
  contender = file.openReadWrite(sourcePath, false)
  conflict = try(file.lock(contender, "exclusive", false))
  if not check(typeof(conflict) == "error" and conflict.code == file.LOCK_CONFLICT, "file lock conflict") then failed = true end if
  ignoredContenderClose = file.close(contender)
  if not check(file.unlock(handle) == true, "file unlock") then failed = true end if
  if not check(file.truncate(handle, 3) == true and file.size(handle) == 3, "file truncate") then failed = true end if
  if not check(file.close(handle) == true, "file close") then failed = true end if
  if not check(file.atomicMove(sourcePath, destinationPath, true) == true, "file atomic move") then failed = true end if
  published = file.readAllBytes(destinationPath, 1024)
  if not check(typeof(published) == "bytes" and len(published) == 3, "bounded file read") then failed = true end if
  if not check(file.syncDirectory(directory) == true, "directory sync") then failed = true end if
  if not check(fs.delete(destinationPath), "file cleanup") then failed = true end if
  if not check(file.removeDirectory(directory) == true, "directory cleanup") then failed = true end if
  if failed then return 1 end if
  print "=== PLATFORM SERVICES DONE ==="
  return 0
end function
