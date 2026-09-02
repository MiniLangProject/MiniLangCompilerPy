/*
Copyright 2026 Nils Kopal

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

//! Provides the std math package.

package std.math

// Numeric predicates, integer helpers and native transcendental functions.

/// Checks whether a value is a numeric type.
/// @param x Value supplied for `x`.
function isNumber(x)
  t = typeof(x)
  return t == "int" or t == "float"
end function

/// Absolute value.
/// @param x Value supplied for `x`.
function abs(x)
  if not std.math.isNumber(x) then
    return
  end if
  if x < 0 then
    return - x
  end if
  return x
end function

/// Sign of a number.
/// @param x Value supplied for `x`.
function sign(x)
  if not std.math.isNumber(x) then
    return
  end if
  if x < 0 then
    return -1
  end if
  if x > 0 then
    return 1
  end if
  return 0
end function

/// Clamp a number to [lo, hi].
/// @param x Value supplied for `x`.
/// @param lo Value supplied for `lo`.
/// @param hi Value supplied for `hi`.
function clamp(x, lo, hi)
  if x < lo then
    return lo
  end if
  if x > hi then
    return hi
  end if
  return x
end function

/// Minimum of two values.
/// @param a First input value.
/// @param b Second input value.
function min(a, b)
  if a < b then
    return a
  end if
  return b
end function

/// Maximum of two values.
/// @param a First input value.
/// @param b Second input value.
function max(a, b)
  if a > b then
    return a
  end if
  return b
end function

/// Floor(x) -> integer-valued number.
/// @param x Value supplied for `x`.
function floor(x)
  // Fast path for int
  if typeof(x) == "int" then
    return x
  end if

  // Use x - (x % 1) with a correction for runtimes where remainder can be negative.
  r = x % 1
  if r == 0 then
    return x
  end if
  if r > 0 then
    return x - r
  end if
  // r < 0
  return (x - r) - 1
end function

/// Ceil(x) -> integer-valued number.
/// @param x Value supplied for `x`.
function ceil(x)
  if typeof(x) == "int" then
    return x
  end if
  f = std.math.floor(x)
  if f == x then
    return f
  end if
  return f + 1
end function

/// Truncates towards 0.
/// @param x Value supplied for `x`.
function trunc(x)
  if typeof(x) == "int" then
    return x
  end if
  if x >= 0 then
    return x -(x % 1)
  end if
  // for negatives: trunc(-3.2) = -3
  return 0 -(0 - x -((0 - x) % 1))
end function

/// Rounds to the nearest integer (half away from zero).
/// @param x Value supplied for `x`.
function round(x)
  if typeof(x) == "int" then
    return x
  end if
  if x >= 0 then
    return std.math.floor(x + 0.5)
  end if
  return std.math.ceil(x - 0.5)
end function

/// Mathematical constant pi.
function pi()
  return 3.141592653589793
end function

/// Mathematical constant tau (2*pi).
function tau()
  return 2.0 * std.math.pi()
end function

/// Converts degrees to radians.
/// @param deg Value supplied for `deg`.
function degToRad(deg)
  return deg *(std.math.pi() / 180.0)
end function

/// Converts radians to degrees.
/// @param rad Value supplied for `rad`.
function radToDeg(rad)
  return rad *(180.0 / std.math.pi())
end function

/// Square root (Newton iteration).
/// @param x Value supplied for `x`.
function sqrt(x)
  if x <= 0 then
    return 0.0
  end if

  // Newton iteration. Good compromise between speed and precision.
  g = x
  if g < 1.0 then
    g = 1.0
  end if

  i = 0
  while i < 12
    ng = 0.5 *(g +(x / g))
    if std.math.abs(ng - g) < 0.000000000001 then
      g = ng
      break
    end if
    g = ng
    i = i + 1
  end while
  return g
end function

/// Integer power (exponentiation by squaring).
/// @param base Value supplied for `base`.
/// @param exp Value supplied for `exp`.
function powi(base, exp)
  if typeof(exp) != "int" then
    return
  end if
  if not std.math.isNumber(base) then
    return
  end if

  if exp == 0 then
    // keep type stable for int bases
    if typeof(base) == "int" then
      return 1
    end if
    return 1.0
  end if
  if exp < 0 then
    // negative exponent -> reciprocal
    return 1.0 / std.math.powi(base, 0 - exp)
  end if

  // Use float accumulator if the base is float; otherwise keep int if possible.
  result = 1
  if typeof(base) == "float" then
    result = 1.0
  end if
  b = base
  e = exp
  while e > 0
    if (e & 1) == 1 then
      result = result * b
    end if
    b = b * b
    e = e >> 1
  end while
  return result
end function

/// Greatest common divisor (Euclidean algorithm).
/// @param a First input value.
/// @param b Second input value.
function gcd(a, b)
  if typeof(a) != "int" or typeof(b) != "int" then
    return
  end if

  a = std.math.abs(a)
  b = std.math.abs(b)

  while b != 0
    t = a % b
    a = b
    b = t
  end while
  return a
end function

/// Least common multiple.
/// @param a First input value.
/// @param b Second input value.
function lcm(a, b)
  if typeof(a) != "int" or typeof(b) != "int" then
    return
  end if
  if a == 0 or b == 0 then
    return 0
  end if

  g = std.math.gcd(a, b)
  // Avoid division by 0 (shouldn't happen if a,b != 0)
  if g == 0 then
    return
  end if

  prod = std.math.abs(a * b)
  return prod / g
end function

/// Internal: range reduce to (-pi, pi].
/// @internal
function _wrapPi(x)
  p = std.math.pi()
  twoPi = 2.0 * p
  // Reduce using floor division to avoid slow looping for large values.
  k = std.math.floor(x / twoPi)
  v = x -(k * twoPi)
  if v > p then
    v = v - twoPi
  end if
  return v
end function

/// Sine (fast approximation).
/// @param x Value supplied for `x`.
function sin(x)
  v = std.math._wrapPi(x)

  // Use symmetry: sin(-x) = -sin(x)
  sgn = 1.0
  if v < 0.0 then
    v = 0.0 - v
    sgn = 0.0 - 1.0
  end if

  p = std.math.pi()
  halfPi = 0.5 * p
  if v > halfPi then
    // sin(x) = sin(pi - x)
    v = p - v
  end if

  // 9th order Taylor on [0, pi/2] (no loop; fast)
  x2 = v * v
  x3 = v * x2
  x5 = x3 * x2
  x7 = x5 * x2
  x9 = x7 * x2
  r = v -(x3 / 6.0) +(x5 / 120.0) -(x7 / 5040.0) +(x9 / 362880.0)
  return sgn * r
end function

/// Cosine (fast approximation).
/// @param x Value supplied for `x`.
function cos(x)
  v = std.math._wrapPi(x)

  // cos is even
  if v < 0.0 then
    v = 0.0 - v
  end if

  p = std.math.pi()
  halfPi = 0.5 * p
  negate = 1.0
  if v > halfPi then
    // cos(x) = -cos(pi - x)
    v = p - v
    negate = 0.0 - 1.0
  end if

  // 8th order Taylor on [0, pi/2]
  x2 = v * v
  x4 = x2 * x2
  x6 = x4 * x2
  x8 = x4 * x4
  r = 1.0 -(x2 / 2.0) +(x4 / 24.0) -(x6 / 720.0) +(x8 / 40320.0)
  return negate * r
end function

/// Tangent (sin/cos).
/// @param x Value supplied for `x`.
function tan(x)
  c = std.math.cos(x)
  if std.math.abs(c) < 0.0000001 then
    // near asymptote; return a large number
    if x >= 0 then
      return 99999999.0
    end if
    return 0.0 - 99999999.0
  end if
  return std.math.sin(x) / c
end function

/// Arctangent (fast approximation).
/// @param x Value supplied for `x`.
function atan(x)
  ax = std.math.abs(x)
  s = 1.0
  if x < 0.0 then
    s = 0.0 - 1.0
  end if

  p = std.math.pi()
  halfPi = 0.5 * p

  // Approximation: atan(z) ~= z*(pi/4 + 0.273*(1 - z)) for z in [0,1]
  if ax <= 1.0 then
    z = ax
    r = z *((p / 4.0) + 0.273 *(1.0 - z))
    return s * r
  end if

  z = 1.0 / ax
  r = z *((p / 4.0) + 0.273 *(1.0 - z))
  return s *(halfPi - r)
end function

/// Arctangent with quadrant handling.
/// @param y Value supplied for `y`.
/// @param x Value supplied for `x`.
function atan2(y, x)
  if x > 0 then
    return std.math.atan(y / x)
  end if

  p = std.math.pi()

  if x < 0 then
    if y >= 0 then
      return std.math.atan(y / x) + p
    end if
    return std.math.atan(y / x) - p
  end if

  // x == 0
  if y > 0 then
    return 0.5 * p
  end if
  if y < 0 then
    return 0.0 -(0.5 * p)
  end if
  return 0.0
end function

/// Hypotenuse: sqrt(x*x + y*y).
/// @param x Value supplied for `x`.
/// @param y Value supplied for `y`.
function hypot(x, y)
  return std.math.sqrt((x * x) +(y * y))
end function

/// Mathematical constant e.
function e()
  return 2.718281828459045
end function

/// Natural logarithm of 2.
function ln2()
  return 0.6931471805599453
end function

/// Natural logarithm of 10.
function ln10()
  return 2.302585092994046
end function

/// Checks whether a numeric value is an integer value.
/// @param x Value supplied for `x`.
function isIntValue(x)
  if typeof(x) == "int" then
    return true
  end if
  if typeof(x) != "float" then
    return false
  end if
  return x == std.math.floor(x)
end function

/// Exponential function exp(x).
/// @param x Value supplied for `x`.
function exp(x)
  // Range reduction: x = k*ln2 + r, r in [-ln2/2, ln2/2]
  ln2v = std.math.ln2()
  // k = round(x / ln2)
  k = std.math.round(x / ln2v)
  r = x -(k * ln2v)

  // Polynomial approximation for exp(r) around 0
  // 1 + r + r^2/2 + r^3/6 + r^4/24 + r^5/120 + r^6/720
  r2 = r * r
  r3 = r2 * r
  r4 = r2 * r2
  r5 = r4 * r
  r6 = r3 * r3
  er = 1.0 + r +(r2 / 2.0) +(r3 / 6.0) +(r4 / 24.0) +(r5 / 120.0) +(r6 / 720.0)

  // exp(x) = exp(r) * 2^k
  return er * std.math.powi(2.0, k)
end function

/// Expm1(x) = exp(x) - 1, with good accuracy near 0.
/// @param x Value supplied for `x`.
function expm1(x)
  ax = std.math.abs(x)
  if ax < 0.000001 then
    // Series: x + x^2/2 + x^3/6
    x2 = x * x
    x3 = x2 * x
    return x +(x2 / 2.0) +(x3 / 6.0)
  end if
  return std.math.exp(x) - 1.0
end function

/// Natural logarithm ln(x).
/// @param x Value supplied for `x`.
function ln(x)
  if x <= 0 then
    return
  end if

  // Reduce to [0.5, 2] using powers of 2
  ln2v = std.math.ln2()
  r = 0.0
  v = x

  while v > 2.0
    v = v / 2.0
    r = r + ln2v
  end while

  while v < 0.5
    v = v * 2.0
    r = r - ln2v
  end while

  // Use atanh series: ln(v) = 2 * (y + y^3/3 + y^5/5 + ...)
  y =(v - 1.0) /(v + 1.0)
  y2 = y * y

  y3 = y * y2
  y5 = y3 * y2
  y7 = y5 * y2
  y9 = y7 * y2

  ln_v = 2.0 *(y +(y3 / 3.0) +(y5 / 5.0) +(y7 / 7.0) +(y9 / 9.0))
  return r + ln_v
end function

/// Ln1p(x) = ln(1+x), with good accuracy near 0.
/// @param x Value supplied for `x`.
function ln1p(x)
  ax = std.math.abs(x)
  if ax < 0.000001 then
    // Series: x - x^2/2 + x^3/3
    x2 = x * x
    x3 = x2 * x
    return x -(x2 / 2.0) +(x3 / 3.0)
  end if
  return std.math.ln(1.0 + x)
end function

/// Base-10 logarithm log10(x).
/// @param x Value supplied for `x`.
function log10(x)
  return std.math.ln(x) / std.math.ln10()
end function

/// Base-2 logarithm log2(x).
/// @param x Value supplied for `x`.
function log2(x)
  return std.math.ln(x) / std.math.ln2()
end function

/// Pow(base, exponent).
/// @param base Value supplied for `base`.
/// @param exponent Value supplied for `exponent`.
function pow(base, exponent)
  // Integer exponent -> use fast powi
  if typeof(exponent) == "int" then
    return std.math.powi(base, exponent)
  end if

  // Allow float exponents that are integer-valued for negative bases
  if base < 0.0 then
    if std.math.isIntValue(exponent) then
      return std.math.powi(base, exponent)
    end if
    return
  end if

  if base == 0.0 then
    if exponent > 0.0 then
      return 0.0
    end if
    if exponent == 0.0 then
      return 1.0
    end if
    return
  end if

  // base > 0
  return std.math.exp(exponent * std.math.ln(base))
end function

/// Inverse square root 1/sqrt(x).
/// @param x Value supplied for `x`.
function invSqrt(x)
  s = std.math.sqrt(x)
  if s == 0.0 then
    return 0.0
  end if
  return 1.0 / s
end function

/// Arcsine asin(x).
/// @param x Value supplied for `x`.
function asin(x)
  v = std.math.clamp(x, -1.0, 1.0)
  return std.math.atan2(v, std.math.sqrt(1.0 -(v * v)))
end function

/// Arccosine acos(x).
/// @param x Value supplied for `x`.
function acos(x)
  v = std.math.clamp(x, -1.0, 1.0)
  return std.math.atan2(std.math.sqrt(1.0 -(v * v)), v)
end function

/// Hyperbolic sine sinh(x).
/// @param x Value supplied for `x`.
function sinh(x)
  ex = std.math.exp(x)
  emx = 1.0 / ex
  return 0.5 *(ex - emx)
end function

/// Hyperbolic cosine cosh(x).
/// @param x Value supplied for `x`.
function cosh(x)
  ex = std.math.exp(x)
  emx = 1.0 / ex
  return 0.5 *(ex + emx)
end function

/// Hyperbolic tangent tanh(x).
/// @param x Value supplied for `x`.
function tanh(x)
  ex = std.math.exp(x)
  emx = 1.0 / ex
  return (ex - emx) /(ex + emx)
end function

/// Fractional part of x.
/// @param x Value supplied for `x`.
function fract(x)
  return x - std.math.trunc(x)
end function

/// Linear interpolation.
/// @param a First input value.
/// @param b Second input value.
/// @param t Value supplied for `t`.
function lerp(a, b, t)
  return a +((b - a) * t)
end function

/// Smoothstep interpolation (Hermite).
/// @param edge0 Value supplied for `edge0`.
/// @param edge1 Value supplied for `edge1`.
/// @param x Value supplied for `x`.
function smoothstep(edge0, edge1, x)
  if edge0 == edge1 then
    return 0.0
  end if
  t =(x - edge0) /(edge1 - edge0)
  t = std.math.clamp(t, 0.0, 1.0)
  return t * t *(3.0 - 2.0 * t)
end function


