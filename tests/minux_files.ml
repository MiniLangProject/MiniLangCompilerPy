import std.io.file as file
import std.console as console
import std.assert as t
import std.crypto as crypto
import std.encoding.hex as hex

function main(args)
  path = "/tmp/minilang-positional.dat"
  handle = file.openReadWriteDurable(path, true)
  t.assertEq(file.writeAt(handle, 4, bytes("abcdef"), 1, 3), 3, "durable positional write")
  t.assertEq(file.size(handle), 7, "MinUX native stat size")
  output = bytes(8, 0)
  t.assertEq(file.readExactAt(handle, 4, output, 2, 3), 3, "positional read")
  t.assertEq(slice(output, 2, 3), bytes("bcd"), "positional contents")
  second = file.openReadWrite(path, false)
  third = file.openReadWrite(path, false)
  t.assertEq(file.lock(handle, "shared", false), true, "shared lock")
  t.assertEq(file.lock(second, "shared", false), true, "second shared lock")
  t.assertEq(typeof(try(file.lock(third, "exclusive", false))), "error", "exclusive conflict")
  file.unlock(second)
  file.unlock(handle)
  t.assertEq(file.lock(third, "exclusive", false), true, "exclusive after unlock")
  t.assertEq(typeof(try(file.lock(handle, "shared", false))), "error", "shared conflict")
  file.close(second)
  file.close(third)
  t.assertEq(file.lock(handle, "exclusive", false), true, "final close releases lock")
  file.close(handle)
  file.deletePath(path)
  secret = bytes("secret")
  t.assertEq(console.wipe(secret), true, "secret wipe")
  t.assertEq(secret, bytes(6, 0), "wiped bytes")
  t.assertEq(crypto.pbkdf2Sha256(bytes("password"), bytes("salt"), 1, 32), hex.decode("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"), "PBKDF2 SHA256 vector")
  print "MINUX_FILES_OK"
  return 37
end function
