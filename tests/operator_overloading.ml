// Shared cross-compiler coverage for statically resolved struct operators.
struct Vector2
  x as int,
  y as int,

  operator inline +(left as Vector2, right as Vector2) returns Vector2
    return Vector2(left.x + right.x, left.y + right.y)
  end operator

  operator +(left as Vector2, scale as int) returns Vector2
    return Vector2(left.x + scale, left.y + scale)
  end operator

  operator -(value as Vector2) returns Vector2
    return Vector2(-value.x, -value.y)
  end operator

  operator +(value as Vector2) returns Vector2
    return value
  end operator

  operator -(left as Vector2, right as Vector2) returns Vector2
    return Vector2(left.x - right.x, left.y - right.y)
  end operator

  operator *(left as Vector2, scale as int) returns Vector2
    return Vector2(left.x * scale, left.y * scale)
  end operator

  operator /(left as Vector2, divisor as int) returns Vector2
    if divisor == 0 then return Vector2(0, 0) end if
    return left
  end operator

  operator %(left as Vector2, divisor as int) returns Vector2
    return Vector2(left.x % divisor, left.y % divisor)
  end operator

  operator ==(left as Vector2, right as Vector2) returns bool
    return left.x == right.x and left.y == right.y
  end operator

  operator !=(left as Vector2, right as Vector2) returns bool
    return left.x != right.x or left.y != right.y
  end operator

  operator <(left as Vector2, right as Vector2) returns bool
    return left.x + left.y < right.x + right.y
  end operator

  operator <=(left as Vector2, right as Vector2) returns bool
    return left.x + left.y <= right.x + right.y
  end operator

  operator >(left as Vector2, right as Vector2) returns bool
    return left.x + left.y > right.x + right.y
  end operator

  operator >=(left as Vector2, right as Vector2) returns bool
    return left.x + left.y >= right.x + right.y
  end operator
end struct

struct Bits
  value as int,

  operator &(left as Bits, right as Bits) returns Bits
    return Bits(left.value & right.value)
  end operator

  operator |(left as Bits, right as Bits) returns Bits
    return Bits(left.value | right.value)
  end operator

  operator ^(left as Bits, right as Bits) returns Bits
    return Bits(left.value ^ right.value)
  end operator

  operator <<(left as Bits, count as int) returns Bits
    return Bits(left.value << count)
  end operator

  operator >>(left as Bits, count as int) returns Bits
    return Bits(left.value >> count)
  end operator

  operator ~(value as Bits) returns Bits
    return Bits(~value.value)
  end operator

  operator not(value as Bits) returns bool
    return value.value == 0
  end operator
end struct

evaluationCount = 0

function evaluatedVector(value as int) returns Vector2
  global evaluationCount
  evaluationCount += 1
  return Vector2(value, evaluationCount)
end function

function typedAdd(left as Vector2, right as Vector2) returns Vector2
  result = left + right
  result += right
  return result
end function

function main(args)
  a = Vector2(2, 4)
  b = Vector2(3, 5)
  sum = typedAdd(a, b)
  shifted = a + 3
  shifted *= 2
  difference = b
  difference -= a
  quotient = Vector2(12, 14) / 2
  quotient /= 2
  remainder = Vector2(13, 17) % 5
  remainder %= 5
  negated = -a
  positive = +a
  evaluated = evaluatedVector(1) + evaluatedVector(2)
  bits = (Bits(6) & Bits(3)) | Bits(8)
  bits &= Bits(15)
  bits |= Bits(1)
  bits ^= Bits(3)
  bits <<= 1
  bits >>= 1

  ok = sum == Vector2(8, 14)
  ok = ok and shifted == Vector2(10, 14)
  ok = ok and difference == Vector2(1, 1)
  ok = ok and quotient == Vector2(12, 14)
  ok = ok and remainder == Vector2(3, 2)
  ok = ok and negated == Vector2(-2, -4)
  ok = ok and positive == a
  ok = ok and evaluationCount == 2 and evaluated == Vector2(3, 3)
  ok = ok and bits.value == 8
  ok = ok and (Bits(7) ^ Bits(3)).value == 4
  ok = ok and (~Bits(0)).value == -1
  ok = ok and not Bits(0)
  ok = ok and +5 == 5
  ok = ok and a != b and a < b and a <= b and b > a and b >= a
  n = 2
  n += 3
  n *= 4
  n -= 1
  ok = ok and n == 19
  if ok then
    print "[OK] operator overloading"
  else
    print "operator overloading failed"
  end if
end function
