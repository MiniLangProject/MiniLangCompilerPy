package regression.struct_identity.fallback

/// Existing unqualified entry-type fallback is valid when no lexical type exists.
function entryValue()
  return EntryOnly(88)
end function

/// Existing fallback also applies when the constructor is used as a value.
function entryConstructor()
  return EntryOnly
end function
