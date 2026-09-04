struct InvalidVoidOperator
  value as int,

  operator +(left as InvalidVoidOperator, right as InvalidVoidOperator) returns void
    print left.value + right.value
  end operator
end struct

function main(args)
end function
