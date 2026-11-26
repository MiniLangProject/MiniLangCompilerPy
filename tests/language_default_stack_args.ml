// Default arguments beyond the register ABI must not overwrite caller locals.
struct Marker
  values
end struct

function tenArguments(a, b, c, d = 4, e = 5, f = 6, g = 7, h = 8, i = 9, j = 10)
  return [a, b, c, d, e, f, g, h, i, j]
end function

function preservesCallerLocals()
  marker = Marker([101, 102])
  result = tenArguments(1, 2, 3)
  if typeof(marker) != "struct" then return 1 end if
  if marker.values[0] != 101 or marker.values[1] != 102 then return 2 end if
  if len(result) != 10 or result[9] != 10 then return 3 end if
  return 0
end function

namespace DefaultScope
  function ten(a, b, c, d = 4, e = 5, f = 6, g = 7, h = 8, i = 9, j = 10)
    return [a, b, c, d, e, f, g, h, i, j]
  end function

  function preservesNamedCaller()
    marker = Marker([201, 202])
    result = ten(c = 3, a = 1, b = 2)
    if typeof(marker) != "struct" then return 11 end if
    if marker.values[0] != 201 or marker.values[1] != 202 then return 12 end if
    if result[0] != 1 or result[2] != 3 or result[9] != 10 then return 13 end if
    return 0
  end function
end namespace

class ManyDefaults
  tag = 40

  function values(a, b, c, d = 4, e = 5, f = 6, g = 7, h = 8, i = 9)
    return [a, b, c, d, e, f, g, h, i, this.tag]
  end function

  static function staticValues(a, b, c, d = 4, e = 5, f = 6, g = 7, h = 8, i = 9, j = 10)
    return [a, b, c, d, e, f, g, h, i, j]
  end function
end class

class DefaultConstructor
  last = 0

  function init(a, b, c, d = 4, e = 5, f = 6, g = 7, h = 8, i = 9, j = 10)
    this.last = a + b + c + d + e + f + g + h + i + j
  end function
end class

function preservesMethodCaller()
  marker = Marker([301, 302])
  instance = ManyDefaults()
  result = instance.values(1, 2, 3)
  if typeof(marker) != "struct" then return 21 end if
  if marker.values[0] != 301 or marker.values[1] != 302 then return 22 end if
  if result[8] != 9 or result[9] != 40 then return 23 end if
  return 0
end function

function preservesStaticCaller()
  marker = Marker([401, 402])
  result = ManyDefaults.staticValues(1, 2, 3)
  if typeof(marker) != "struct" then return 31 end if
  if marker.values[0] != 401 or marker.values[1] != 402 then return 32 end if
  if result[9] != 10 then return 33 end if
  return 0
end function

function preservesConstructorCaller()
  marker = Marker([501, 502])
  result = DefaultConstructor(1, 2, 3)
  if typeof(marker) != "struct" then return 41 end if
  if marker.values[0] != 501 or marker.values[1] != 502 then return 42 end if
  if result.last != 55 then return 43 end if
  return 0
end function

// This source call has zero arguments, but its default evaluates a ten-arg call.
function hiddenCall(value = tenArguments(1, 2, 3, 4, 5, 6, 7, 8, 9, 10))
  return value
end function

function preservesHiddenDefaultCaller()
  marker = Marker([601, 602])
  result = hiddenCall()
  if typeof(marker) != "struct" then return 51 end if
  if marker.values[0] != 601 or marker.values[1] != 602 then return 52 end if
  if result[9] != 10 then return 53 end if
  return 0
end function

function preservesTypedCaller()
  marker = Marker([701, 702])
  result as array = tenArguments(1, 2, 3)
  if typeof(marker) != "struct" then return 61 end if
  if marker.values[0] != 701 or marker.values[1] != 702 then return 62 end if
  if result[9] != 10 then return 63 end if
  return 0
end function

namespace DefaultProvider
  function result(value = scopedValues(1, 2, 3))
    return value
  end function

  function scopedValues(a, b, c)
    return [a, b, c]
  end function
end namespace

namespace DefaultCaller
  function scopedValues(a, b, c, d = 4, e = 5, f = 6, g = 7, h = 8, i = 9, j = 10)
    return [a, b, c, d, e, f, g, h, i, j]
  end function

  function preservesDefaultContext()
    marker = Marker([801, 802])
    // Match the existing call-site resolution of expanded default expressions.
    result = DefaultProvider.result()
    if typeof(marker) != "struct" then return 81 end if
    if marker.values[0] != 801 or marker.values[1] != 802 then return 82 end if
    if len(result) != 10 or result[9] != 10 then return 83 end if
    return 0
  end function
end namespace

// Exercise the module initializer frame as well as ordinary function frames.
startup = tenArguments(1, 2, 3)

function main(args)
  if len(startup) != 10 or startup[9] != 10 then return 71 end if
  result = preservesCallerLocals()
  if result != 0 then return result end if
  result = DefaultScope.preservesNamedCaller()
  if result != 0 then return result end if
  result = preservesMethodCaller()
  if result != 0 then return result end if
  result = preservesStaticCaller()
  if result != 0 then return result end if
  result = preservesConstructorCaller()
  if result != 0 then return result end if
  result = preservesHiddenDefaultCaller()
  if result != 0 then return result end if
  result = preservesTypedCaller()
  if result != 0 then return result end if
  result = DefaultCaller.preservesDefaultContext()
  if result != 0 then return result end if
  print "[OK] default stack arguments preserve caller locals"
  return 0
end function
