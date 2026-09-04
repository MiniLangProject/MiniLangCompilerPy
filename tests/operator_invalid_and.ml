struct InvalidLogicalOperator
  value as bool,

  operator and(left as InvalidLogicalOperator, right as InvalidLogicalOperator) returns bool
    return left.value and right.value
  end operator
end struct

function main(args)
end function
