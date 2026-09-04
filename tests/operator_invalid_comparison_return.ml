struct InvalidComparison
  value as int,

  operator ==(left as InvalidComparison, right as InvalidComparison) returns int
    return 1
  end operator
end struct

function main(args)
end function
