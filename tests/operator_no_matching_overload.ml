struct MissingOperatorMatch
  value as int,

  operator +(left as MissingOperatorMatch, right as int) returns MissingOperatorMatch
    return MissingOperatorMatch(left.value + right)
  end operator
end struct

function main(args)
  left = MissingOperatorMatch(1)
  right = MissingOperatorMatch(2)
  result = left + right
  print result.value
end function
