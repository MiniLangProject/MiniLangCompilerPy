function classify(value)
  match value
    case 0
      return "zero"
    end case
    case 1 to 3
      return "small"
    end case
    case default
      return "other"
    end case
  end match
end function

function main(args)
  if classify(0) != "zero" then return 1 end if
  if classify(2) != "small" then return 2 end if
  if classify(9) != "other" then return 3 end if
  return 0
end function
