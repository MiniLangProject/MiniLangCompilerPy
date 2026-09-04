struct AmbiguousOperator
  value as int,

  operator +(left as AmbiguousOperator, right as int) returns AmbiguousOperator
    return AmbiguousOperator(left.value + right)
  end operator

  operator +(left as AmbiguousOperator, right as integer) returns AmbiguousOperator
    return AmbiguousOperator(left.value + right)
  end operator
end struct

function main(args)
  value = AmbiguousOperator(1) + 2
  print value.value
end function
