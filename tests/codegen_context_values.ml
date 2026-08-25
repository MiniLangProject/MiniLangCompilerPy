package tests.codegen_context_values

// Value-enum assignments exercise package-aware function-wide integer flow.
enum ContextKind
  Unknown = 0
  Ready = 1
end enum

function enumValueFlow(selectReady)
  kind = ContextKind.Unknown
  if selectReady then kind = ContextKind.Ready end if
  return kind == ContextKind.Unknown
end function
