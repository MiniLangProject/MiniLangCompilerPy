package tests.package_global_resolution.state

packageGlobalArray = []
packageGlobalReady = false
packageGlobalHandle = void
packageGlobalRatio = 0.0
packageAssignedNegativeWhole = -1.0
packageAssignedNegativeFraction = -1.25
const packageNegativeWhole = -16.0
const packageNegativeFraction = -16.25
const packageProtocolEscape = "\u0002\nVERSION"
const packageUnicodeEscape = "\u00E4\U0001F600"
packageNestedOuter = 0
packageNestedRoots = []
packageNestedNames = []

// Write through explicit global declarations, as stateful modules commonly do.
function aWrite()
  global packageGlobalArray, packageGlobalReady, packageGlobalHandle, packageGlobalRatio
  packageGlobalArray = [41, 42]
  packageGlobalReady = true
  packageGlobalHandle = 73
  packageGlobalRatio = 1.5
  return true
end function

// Repeating a global declaration in another function must reuse the same slot.
function bRewriteHandle()
  global packageGlobalHandle
  packageGlobalHandle = packageGlobalHandle + 1
end function

// Keep nested declarations in the compiler's deterministic LIFO pre-scan.
// This mirrors real modules that declare one global before a branch and more
// globals inside that branch.
function cWriteNestedGlobals(enabled)
  global packageNestedOuter
  if enabled then
    global packageNestedRoots, packageNestedNames
    packageNestedRoots = [81]
    packageNestedNames = ["nested"]
  end if
  packageNestedOuter = 82
end function

function cReadNestedGlobals()
  return [packageNestedOuter, packageNestedRoots, packageNestedNames]
end function

// Read the same module globals implicitly from separate functions.
function zReadArray()
  return packageGlobalArray
end function

function zReadReady()
  return packageGlobalReady
end function

function zReadHandle()
  return packageGlobalHandle
end function

function zReadRatio()
  return packageGlobalRatio
end function

function zReadNegativeWhole()
  return packageNegativeWhole
end function

function zReadNegativeFraction()
  return packageNegativeFraction
end function

function zReadAssignedNegativeWhole()
  return packageAssignedNegativeWhole
end function

function zReadAssignedNegativeFraction()
  return packageAssignedNegativeFraction
end function

function zBitNot(value)
  return ~value
end function

function zProtocolEscape()
  return packageProtocolEscape
end function

function zUnicodeEscape()
  return packageUnicodeEscape
end function
