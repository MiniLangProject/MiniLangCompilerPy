import tests.package_global_resolution.state as state

packageImportedRatio = state.packageGlobalRatio

function main(args)
  if not state.aWrite() then return 1 end if
  state.bRewriteHandle()
  values = state.zReadArray()
  if typeof(values) != "array" or len(values) != 2 then return 2 end if
  if values[0] != 41 or values[1] != 42 then return 3 end if
  if not state.zReadReady() then return 4 end if
  if state.zReadHandle() != 74 then return 5 end if
  if state.zReadRatio() != 1.5 then return 6 end if
  if typeof(state.zReadNegativeWhole()) != "float" then return 7 end if
  if state.zReadNegativeWhole() != -16.0 then return 8 end if
  if typeof(state.zReadNegativeFraction()) != "float" then return 9 end if
  if state.zReadNegativeFraction() != -16.25 then return 10 end if
  if typeof(state.zReadAssignedNegativeWhole()) != "float" then return 11 end if
  if state.zReadAssignedNegativeWhole() != -1.0 then return 12 end if
  if typeof(state.zReadAssignedNegativeFraction()) != "float" then return 13 end if
  if state.zReadAssignedNegativeFraction() != -1.25 then return 14 end if
  if state.zBitNot(15) != -16 then return 15 end if
  protocolBytes = bytes(state.zProtocolEscape())
  if len(protocolBytes) != 9 or protocolBytes[0] != 2 or protocolBytes[1] != 10 then return 16 end if
  unicodeBytes = bytes(state.zUnicodeEscape())
  if len(unicodeBytes) != 6 then return 17 end if
  if unicodeBytes[0] != 0xC3 or unicodeBytes[1] != 0xA4 then return 18 end if
  if unicodeBytes[2] != 0xF0 or unicodeBytes[3] != 0x9F or unicodeBytes[4] != 0x98 or unicodeBytes[5] != 0x80 then return 19 end if
  if typeof(packageImportedRatio) != "float" or packageImportedRatio != 0.0 then return 20 end if
  state.cWriteNestedGlobals(true)
  nestedValues = state.cReadNestedGlobals()
  if nestedValues[0] != 82 then return 21 end if
  if nestedValues[1][0] != 81 or nestedValues[2][0] != "nested" then return 22 end if
  print "package global resolution [OK]"
  return 0
end function
