/* Copyright 2026 Nils Kopal. Licensed under the Apache License, Version 2.0. */
import std.math as math
import std.concurrent.shared_value as shared
import std.io.file as file
import std.assert as t

function mathChecks()
  if not t.assertApprox(math.sqrt(2.0), 1.4142135623730951, 0.000000000001, "sqrt") then return false end if
  large = math.exp(460.51701859880916)
  if not t.assertApprox(math.sqrt(large) / math.exp(230.25850929940458), 1.0, 0.000000000001, "large sqrt") then return false end if
  if not t.assertEq(math.sqrt(0.0), 0.0, "zero sqrt") then return false end if
  if not t.assertEq(math.exp(0.0), 1.0, "zero exp") then return false end if
  if not t.assertApprox(math.exp(1.0), 2.718281828459045, 0.000000000001, "exp") then return false end if
  if not t.assertApprox(math.exp(-10.0), 0.00004539992976248485, 0.000000000000001, "negative exp") then return false end if
  if not t.assertApprox(math.ln(2.0), 0.6931471805599453, 0.000000000001, "ln") then return false end if
  if not t.assertApprox(math.ln(large), 460.51701859880916, 0.000000001, "large ln") then return false end if
  if not t.assertEq(math.ln(0.0), void, "ln domain") then return false end if
  if not t.assertApprox(math.pow(9.0, 0.5), 3.0, 0.000000000001, "fractional power") then return false end if
  if not t.assertApprox(math.log10(1000.0), 3.0, 0.000000000001, "log10") then return false end if
  return true
end function

function snapshotChecks()
  if not t.assertEq(shared.allocate(0), 0, "reject zero allocation") then return false end if
  if not t.assertEq(shared.free(0), false, "reject null free") then return false end if
  record = shared.allocate(shared.RECORD_SIZE)
  if record == 0 then return false end if
  shared.clearRecordAt(record)
  values = [void, 0, -9223372036854775807, true, false, "", "MinUX äöü", bytes(0), bytes([0, 1, 127, 128, 255])]
  ok = true
  for index = 0 to len(values) - 1
    value = values[index]
    encoded = shared.encode(value)
    if not encoded[0] then ok = false end if
    if ok then
      if not shared.writeEncodedAt(record, encoded) then ok = false end if
      gc_collect()
      if not t.assertEq(shared.readAt(record), value, "native snapshot round trip") then ok = false end if
      shared.destroyAt(record)
      if not t.assertEq(shared.readAt(record), void, "destroy clears record") then ok = false end if
    end if
  end for
  encoded = shared.encode("released snapshot")
  if not encoded[0] or not shared.releaseEncoded(encoded) then ok = false end if
  shared.writeI64At(record, -123456789)
  if not t.assertEq(shared.readI64At(record), -123456789, "signed native integer") then ok = false end if
  shared.move(record + 1, record, 8)
  if not t.assertEq(shared.readI64At(record + 1), -123456789, "overlapping native memmove") then ok = false end if
  if not shared.free(record) then ok = false end if
  return ok
end function

function directoryChecks()
  directory = "/home/user/minilang-stdlib-test"
  source = directory + "/before"
  destination = directory + "/after"
  if not t.assertEq(file.createDirectory(directory), true, "create directory") then return false end if
  if not t.assertEq(typeof(try(file.syncDirectory(directory + "/missing"))), "error", "missing directory fails") then return false end if
  if not t.assertEq(typeof(try(file.syncDirectory(""))), "error", "empty directory fails") then return false end if
  if not t.assertEq(typeof(try(file.syncDirectory(42))), "error", "non-string directory fails") then return false end if
  handle = file.openReadWriteDurable(source, true)
  if not t.assertEq(file.writeAt(handle, 0, bytes("durable"), 0, 7), 7, "durable file write") then return false end if
  if not t.assertEq(file.close(handle), true, "close durable file") then return false end if
  if not t.assertEq(typeof(try(file.syncDirectory(source))), "error", "regular file rejected") then return false end if
  if not t.assertEq(file.syncDirectory(directory), true, "sync created entry") then return false end if
  if not t.assertEq(file.atomicMove(source, destination, false), true, "atomic rename") then return false end if
  if not t.assertEq(file.syncDirectory(directory), true, "sync renamed entry") then return false end if
  if not t.assertEq(file.deletePath(destination), true, "unlink entry") then return false end if
  for i = 0 to 127
    if file.syncDirectory(directory) != true then return false end if
  end for
  if not t.assertEq(file.removeDirectory(directory), true, "remove directory") then return false end if
  if not t.assertEq(file.syncDirectory("/home/user"), true, "sync removed entry") then return false end if
  return true
end function

function main(args)
  if not mathChecks() then return 1 end if
  if not snapshotChecks() then return 2 end if
  if not directoryChecks() then return 3 end if
  print "MINUX_STDLIB_OK"
  return 37
end function
