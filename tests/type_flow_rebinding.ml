// Return contracts belong to immutable function bindings, not their replacements.
import "type_flow_context_lib.ml" as encoded

function original() returns int
  value = 7
  return value
end function

function inline tiny() returns int
  return 1
end function

function replacement()
  return "changed"
end function

function inspectGlobal()
  value = original()
  return typeof(value)
end function

function inspectParameter(original)
  value = original()
  return typeof(value)
end function

function inspectLocal()
  original = replacement
  value = original()
  return typeof(value)
end function

function inspectClosure()
  original = replacement
  function nested()
    value = original()
    return typeof(value)
  end function
  return nested()
end function

function main(args)
  global original, tiny
  original = replacement
  tiny = replacement
  encoded.replaceRebound(replacement)
  if inspectGlobal() != "string" then return 1 end if
  if inspectParameter(replacement) != "string" then return 2 end if
  if inspectLocal() != "string" then return 3 end if
  if inspectClosure() != "string" then return 4 end if
  if typeof(tiny()) != "string" then return 5 end if
  if encoded.inspectRebound() != "string" then return 6 end if
  if typeof(encoded.rebound()) != "string" then return 7 end if
  print("[OK] callable rebinding type flow")
  return 0
end function
