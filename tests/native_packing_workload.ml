// Exercise a generated OOP call and an imported library from a packed image.
import std.string_builder as sb

class PackedValue
  value = 17

  function number()
    return this.value
  end function
end class

function main(args)
  item = PackedValue()
  text = sb.StringBuilder.new()
  text.append("native pack ")
  text.append(item.number())
  text.append(" [OK]")
  print text.toString()
  return 0
end function
