struct InvalidOwner
  value as int,

  operator +(left as int, right as InvalidOwner) returns InvalidOwner
    return right
  end operator
end struct

function main(args)
end function
