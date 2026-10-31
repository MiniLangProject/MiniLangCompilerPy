interface Measurable
  function area() returns int
end interface

abstract class Shape implements Measurable
  protected width as int = 0
  private serial as int = 0

  abstract function area() returns int

  final function widthValue() returns int
    return this.width
  end function

  function serialValue() returns int
    return this.serial
  end function

  function init()
    this.width = 2
    this.serial = 7
  end function
end class

final class Square extends Shape
  private static function secret() returns int
    return 11
  end function

  static function reveal() returns int
    return Square.secret()
  end function

  override function area() returns int
    return this.width * this.width
  end function

  override function init()
    super.init()
    this.width = 3
  end function
end class

function main(args)
  square = Square()
  if square.area() != 9 then return 1 end if
  if square.widthValue() != 3 then return 2 end if
  if square.serialValue() != 7 then return 3 end if
  if not (square is Shape) then return 4 end if
  if not (square is Measurable) then return 5 end if
  constructor = Square
  indirect = constructor()
  if indirect.area() != 9 then return 6 end if
  if Square.reveal() != 11 then return 7 end if
  print "[OK] class initialization, visibility, abstract and final"
  return 0
end function
