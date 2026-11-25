/// Native byte-length, overlap-copy and scalar-semantic regressions.
/// Keep this fixture identical in both native compiler repositories.
import std.cpu as cpu
import std.string_builder as sb

failures = 0
outerValue = 9
const greeting = "Grüße 🌍"

/// Report one failure per check, keeping successful runs quiet.
function checkEq(actual, expected, label)
  global failures
  if actual != expected then
    failures += 1
    print "[FAIL] " + label
    print actual
    print expected
  end if
end function

/// An argument prevents literal-only constant folding.
function stringLength(value)
  return len(value)
end function

/// Exercise a builtin as a first-class value rather than a direct call.
function callCopy(operation, destination, destinationOffset, source, sourceOffset, count)
  operation(destination, destinationOffset, source, sourceOffset, count)
end function

/// Different values at neighboring positions expose copy-direction mistakes.
function pattern(index)
  return ((index * 37) + (index div 251) + 19) % 251
end function

/// Compare against the original index mapping, without using any copy helper
/// to construct the expected result. Effective is explicit for clipped/no-op cases.
function checkCopy(kind, total, dst, src, requested, effective, indirect)
  global failures
  data = void
  if kind == "bytes" then
    data = bytes(total)
  else
    data = array(total, 0)
  end if
  for i = 0 to total - 1
    data[i] = pattern(i)
  end for
  alias = data
  if kind == "bytes" then
    if indirect then
      callCopy(copyBytes, alias, dst, data, src, requested)
    else
      copyBytes(alias, dst, data, src, requested)
    end if
  else
    if indirect then
      callCopy(copyArray, alias, dst, data, src, requested)
    else
      copyArray(alias, dst, data, src, requested)
    end if
  end if
  for i = 0 to total - 1
    original = i
    if i >= dst and i < dst + effective then
      original = src + i - dst
    end if
    if data[i] != pattern(original) then
      failures += 1
      print "[FAIL] overlapping " + kind
      print [total, dst, src, requested, effective, indirect, i]
      return
    end if
  end for
end function

/// Separate source/destination objects must still use correct fast-copy paths.
function checkDisjoint(kind, count, indirect)
  global failures
  source = void
  destination = void
  if kind == "bytes" then
    source = bytes(count + 40)
    destination = bytes(count + 40, 241)
  else
    source = array(count + 40, 0)
    destination = array(count + 40, 241)
  end if
  for i = 0 to len(source) - 1
    source[i] = pattern(i)
  end for
  if kind == "bytes" then
    if indirect then
      callCopy(copyBytes, destination, 7, source, 3, count)
    else
      copyBytes(destination, 7, source, 3, count)
    end if
  else
    if indirect then
      callCopy(copyArray, destination, 7, source, 3, count)
    else
      copyArray(destination, 7, source, 3, count)
    end if
  end if
  for i = 0 to len(destination) - 1
    expected = 241
    if i >= 7 and i < 7 + count then expected = pattern(i - 4) end if
    if destination[i] != expected or source[i] != pattern(i) then
      failures += 1
      print "[FAIL] disjoint " + kind
      print [count, indirect, i]
      return
    end if
  end for
end function

/// UTF-8 bytes are the native string-length contract, including literal folds.
function checkLengths()
  checkEq(len(""), 0, "empty literal length")
  checkEq(len("ASCII"), 5, "ASCII literal length")
  checkEq(len("ä"), 2, "two-byte literal length")
  checkEq(len("€"), 3, "three-byte literal length")
  checkEq(len("🌍"), 4, "four-byte literal length")
  checkEq(len("a\0🌍"), 6, "embedded NUL literal length")
  checkEq(len("é"), 3, "combining sequence byte length")
  checkEq(len("Grüße 🌍"), 12, "Unicode literal length")
  checkEq(len(greeting), 12, "named constant length")
  checkEq(len("Grüße " + "🌍"), 12, "constant expression length")
  local = "Grüße 🌍"
  checkEq(len(local), 12, "local string length")
  checkEq(stringLength(local), 12, "argument string length")
  values = [local, "a\0🌍", "é", ""]
  checkEq(len(values[0]), 12, "array element string length")
  checkEq(stringLength(values[1]), 6, "embedded NUL dynamic length")
  checkEq(stringLength(values[2]), 3, "combining sequence dynamic length")
  checkEq(stringLength(values[3]), 0, "empty dynamic length")
  lengthFunction = len
  checkEq(lengthFunction(local), 12, "first-class len")
  checkEq(len(bytes(local)), 12, "byte buffer length")
  checkEq(len([1, 2, 3]), 3, "array element count")
  builder = sb.StringBuilder.new()
  builder.appendString(local)
  builder.appendString("a\0🌍")
  checkEq(builder.toString(), local + "a\0🌍", "byte-oriented StringBuilder remains intact")
end function

/// A new binding's initializer observes the existing outer binding.
function readOuterInitializer()
  outerValue = outerValue + 1
  return outerValue
end function

/// Force comparisons through runtime operands as well as literal expressions.
function equalArguments(left, right)
  return left == right
end function

/// Preserve scalar semantics that the Wasm implementation previously differed on.
function checkScalarSemantics()
  checkEq(readOuterInitializer(), 10, "initializer sees outer binding")
  checkEq(outerValue, 9, "local initializer leaves outer binding intact")
  checkEq(true == 1, true, "literal true equals one")
  checkEq(false == 0, true, "literal false equals zero")
  checkEq(equalArguments(true, 1), true, "runtime true equals one")
  checkEq(equalArguments(false, 0), true, "runtime false equals zero")
  checkEq(equalArguments(true, 2), false, "runtime true differs from two")
  checkEq(equalArguments(false, 1), false, "runtime false differs from one")
end function

/// Reference-valued copies must retain full tagged cells and remain GC-visible.
function checkReferenceCopies()
  values = [bytes(3, 11), bytes(3, 22), bytes(3, 33), bytes(3, 44)]
  copyArray(values, 1, values, 0, 3)
  gc_collect()
  checkEq(values[0][1], 11, "reference original retained")
  checkEq(values[1][1], 11, "reference right overlap first")
  checkEq(values[2][1], 22, "reference right overlap middle")
  checkEq(values[3][1], 33, "reference right overlap last")
  values[0][1] = 91
  checkEq(values[1][1], 91, "copied references preserve alias identity")
  callCopy(copyArray, values, 0, values, 1, 3)
  gc_collect()
  checkEq(values[0][1], 91, "reference left overlap first")
  checkEq(values[1][1], 22, "reference left overlap middle")
  checkEq(values[2][1], 33, "reference left overlap last")
  // Promote a formerly scalar destination into a scanned reference array.
  destination = [1, 2, 3, 4]
  copyArray(destination, 1, values, 0, 3)
  values = void
  gc_collect()
  checkEq(destination[1][1], 91, "reference destination survives GC")
  checkEq(destination[2][1], 22, "reference middle survives GC")
  checkEq(destination[3][1], 33, "reference tail survives GC")
end function

/// Exercise scalar/SSE2/available CPU dispatch without enabling unsupported ISA.
function main(args)
  checkLengths()
  checkScalarSemantics()
  checkReferenceCopies()
  previousMask = cpu.activeFeatures()
  for each mask in [0, cpu.SSE2, -1]
    cpu.setDispatchMaskForTesting(mask)
    for each indirect in [false, true]
      for each kind in ["bytes", "array"]
        sizes = [0, 1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513]
        if kind == "bytes" then
          sizes = sizes + [4095, 4096, 4097, 65535, 65536, 65537]
        else
          sizes = sizes + [8191, 8192, 8193]
        end if
        for each size in sizes
          checkCopy(kind, size + 40, 17, 16, size, size, indirect)
          checkCopy(kind, size + 40, 16, 17, size, size, indirect)
          checkCopy(kind, size + 40, 16, 16, size, size, indirect)
        end for
        for each size in [0, 1, 7, 8, 17, 33, 257]
          checkDisjoint(kind, size, indirect)
          // Non-overlapping ranges can also belong to the same object.
          checkCopy(kind, size * 2 + 40, size + 16, 8, size, size, indirect)
          checkCopy(kind, size * 2 + 40, 8, size + 16, size, size, indirect)
        end for
        checkCopy(kind, 12, 8, 5, 100, 4, indirect)
        checkCopy(kind, 12, 5, 8, 100, 4, indirect)
        checkCopy(kind, 12, 1, 0, 0, 0, indirect)
        checkCopy(kind, 12, -1, 0, 3, 0, indirect)
        checkCopy(kind, 12, 0, -1, 3, 0, indirect)
        checkCopy(kind, 12, 1, 0, -1, 0, indirect)
        checkCopy(kind, 12, 12, 0, 1, 0, indirect)
        checkCopy(kind, 12, 0, 12, 1, 0, indirect)
      end for
    end for
  end for
  cpu.setDispatchMaskForTesting(previousMask)
  if failures != 0 then
    print "[FAIL] Native semantics regressions"
    print failures
    return 1
  end if
  print "[OK] Native semantics regressions"
  return 0
end function
