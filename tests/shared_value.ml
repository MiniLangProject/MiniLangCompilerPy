import std.concurrent.shared_value as shared

function main(args)
  record = shared.allocate(shared.RECORD_SIZE)
  if record == 0 then return 1 end if

  shared.writeI64At(record, -123456789)
  if shared.readI64At(record) != -123456789 then return 2 end if

  encoded = shared.encode("shared snapshot")
  if not encoded[0] or not shared.writeEncodedAt(record, encoded) then return 3 end if
  if shared.readAt(record) != "shared snapshot" then return 4 end if
  shared.destroyAt(record)

  encodedBytes = shared.encode(bytes("payload"))
  if not encodedBytes[0] or not shared.writeEncodedAt(record, encodedBytes) then return 5 end if
  restored = shared.readAt(record)
  if typeof(restored) != "bytes" or decode(restored) != "payload" then return 6 end if
  shared.destroyAt(record)

  if not shared.free(record) then return 7 end if
  print "[OK] portable native shared-value snapshots"
  return 0
end function
