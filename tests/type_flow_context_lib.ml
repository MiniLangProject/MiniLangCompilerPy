// Unqualified typed callees must be resolved in their owning module.
package regression.type_flow_context

function packed(value as int) returns int
  if value < 0 then return 0 end if
  return value
end function

function rebound() returns int
  result = 5
  return result
end function

function inspectRebound()
  value = rebound()
  return typeof(value)
end function

function replaceRebound(callback)
  global rebound
  rebound = callback
end function

function unpack(value)
  bounds = packed(value)
  if bounds == 0 then return 0 end if
  x = bounds & 255
  y = (bounds >> 8) & 255
  result = (x + y) div 2
  return result
end function
