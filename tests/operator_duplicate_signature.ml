struct DuplicateOperator
  value as int,

  operator +(left as DuplicateOperator, right as int) returns DuplicateOperator
    return DuplicateOperator(left.value + right)
  end operator

  operator +(left as DuplicateOperator, right as int) returns DuplicateOperator
    return DuplicateOperator(left.value + right)
  end operator
end struct

function main(args)
end function
