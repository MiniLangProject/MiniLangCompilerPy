package regression.struct_identity.builtins

struct InstanceMeasure
  data

  /// Bare len inside a type with a len method still names the core builtin.
  function len()
    return len(this.data)
  end function

  function lengthOf(value)
    return len(value)
  end function
end struct

struct StaticMeasure
  /// Explicit qualified access selects the method, not the builtin.
  static function len(value)
    return 700
  end function

  static function lengthOf(value)
    return len(value)
  end function

  static function increment(value)
    return value + 1
  end function

  /// Existing bare static-sibling lookup remains available as a fallback.
  static function throughSibling(value)
    return increment(value)
  end function
end struct
