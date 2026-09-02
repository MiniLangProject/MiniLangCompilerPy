# `std/math.ml`

[Home](README.md) · [Files](Files.md)

Provides the std math package.

Package: [`std.math`](Package-std-math-653491218.md)

Reachable from entry: **no**

## Declarations

<a id="function-function-std-math-abs-function-abs-x-std-math-ml-573377840"></a>
### abs

```ml
function abs(x)
```

Absolute value.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |


Source: `std/math.ml:32`

<a id="function-function-std-math-acos-function-acos-x-std-math-ml-1386598144"></a>
### acos

```ml
function acos(x)
```

Arccosine acos(x).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |


Source: `std/math.ml:592`

<a id="function-function-std-math-asin-function-asin-x-std-math-ml-224541764"></a>
### asin

```ml
function asin(x)
```

Arcsine asin(x).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |


Source: `std/math.ml:585`

<a id="function-function-std-math-atan-function-atan-x-std-math-ml-2132826072"></a>
### atan

```ml
function atan(x)
```

Arctangent (fast approximation).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |


Source: `std/math.ml:364`

<a id="function-function-std-math-atan2-function-atan2-y-x-std-math-ml-1842524175"></a>
### atan2

```ml
function atan2(y, x)
```

Arctangent with quadrant handling.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `y` | `dynamic` | — | Value supplied for `y`. |
| `x` | `dynamic` | — | Value supplied for `x`. |


Source: `std/math.ml:389`

<a id="function-function-std-math-ceil-function-ceil-x-std-math-ml-1435593484"></a>
### ceil

```ml
function ceil(x)
```

Ceil(x) -> integer-valued number.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |


Source: `std/math.ml:113`

<a id="function-function-std-math-clamp-function-clamp-x-lo-hi-std-math-ml-473254544"></a>
### clamp

```ml
function clamp(x, lo, hi)
```

Clamp a number to [lo, hi].

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |
| `lo` | `dynamic` | — | Value supplied for `lo`. |
| `hi` | `dynamic` | — | Value supplied for `hi`. |


Source: `std/math.ml:61`

<a id="function-function-std-math-cos-function-cos-x-std-math-ml-638965610"></a>
### cos

```ml
function cos(x)
```

Cosine (fast approximation).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |


Source: `std/math.ml:322`

<a id="function-function-std-math-cosh-function-cosh-x-std-math-ml-981216312"></a>
### cosh

```ml
function cosh(x)
```

Hyperbolic cosine cosh(x).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |


Source: `std/math.ml:607`

<a id="function-function-std-math-degtorad-function-degtorad-deg-std-math-ml-600428704"></a>
### degToRad

```ml
function degToRad(deg)
```

Converts degrees to radians.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `deg` | `dynamic` | — | Value supplied for `deg`. |


Source: `std/math.ml:161`

<a id="function-function-std-math-e-function-e-std-math-ml-1291905090"></a>
### e

```ml
function e()
```

Mathematical constant e.


Source: `std/math.ml:421`

<a id="function-function-std-math-exp-function-exp-x-std-math-ml-847392178"></a>
### exp

```ml
function exp(x)
```

Exponential function exp(x).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |


Source: `std/math.ml:449`

<a id="function-function-std-math-expm1-function-expm1-x-std-math-ml-671119542"></a>
### expm1

```ml
function expm1(x)
```

Expm1(x) = exp(x) - 1, with good accuracy near 0.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |


Source: `std/math.ml:471`

<a id="function-function-std-math-floor-function-floor-x-std-math-ml-1858376096"></a>
### floor

```ml
function floor(x)
```

Floor(x) -> integer-valued number.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |


Source: `std/math.ml:93`

<a id="function-function-std-math-fract-function-fract-x-std-math-ml-123616796"></a>
### fract

```ml
function fract(x)
```

Fractional part of x.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |


Source: `std/math.ml:623`

<a id="function-function-std-math-gcd-function-gcd-a-b-std-math-ml-520129697"></a>
### gcd

```ml
function gcd(a, b)
```

Greatest common divisor (Euclidean algorithm).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | First input value. |
| `b` | `dynamic` | — | Second input value. |


Source: `std/math.ml:240`

<a id="function-function-std-math-hypot-function-hypot-x-y-std-math-ml-336937453"></a>
### hypot

```ml
function hypot(x, y)
```

Hypotenuse: sqrt(x*x + y*y).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |
| `y` | `dynamic` | — | Value supplied for `y`. |


Source: `std/math.ml:416`

<a id="function-function-std-math-invsqrt-function-invsqrt-x-std-math-ml-1022224274"></a>
### invSqrt

```ml
function invSqrt(x)
```

Inverse square root 1/sqrt(x).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |


Source: `std/math.ml:575`

<a id="function-function-std-math-isintvalue-function-isintvalue-x-std-math-ml-23293032"></a>
### isIntValue

```ml
function isIntValue(x)
```

Checks whether a numeric value is an integer value.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |


Source: `std/math.ml:437`

<a id="function-function-std-math-isnumber-function-isnumber-x-std-math-ml-2115637864"></a>
### isNumber

```ml
function isNumber(x)
```

Checks whether a value is a numeric type.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |


Source: `std/math.ml:25`

<a id="function-function-std-math-lcm-function-lcm-a-b-std-math-ml-2106405213"></a>
### lcm

```ml
function lcm(a, b)
```

Least common multiple.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | First input value. |
| `b` | `dynamic` | — | Second input value. |


Source: `std/math.ml:259`

<a id="function-function-std-math-lerp-function-lerp-a-b-t-std-math-ml-1477438275"></a>
### lerp

```ml
function lerp(a, b, t)
```

Linear interpolation.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | First input value. |
| `b` | `dynamic` | — | Second input value. |
| `t` | `dynamic` | — | Value supplied for `t`. |


Source: `std/math.ml:631`

<a id="function-function-std-math-ln-function-ln-x-std-math-ml-120611688"></a>
### ln

```ml
function ln(x)
```

Natural logarithm ln(x).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |


Source: `std/math.ml:484`

<a id="function-function-std-math-ln10-function-ln10-std-math-ml-177958864"></a>
### ln10

```ml
function ln10()
```

Natural logarithm of 10.


Source: `std/math.ml:431`

<a id="function-function-std-math-ln1p-function-ln1p-x-std-math-ml-858417300"></a>
### ln1p

```ml
function ln1p(x)
```

Ln1p(x) = ln(1+x), with good accuracy near 0.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |


Source: `std/math.ml:519`

<a id="function-function-std-math-ln2-function-ln2-std-math-ml-236134708"></a>
### ln2

```ml
function ln2()
```

Natural logarithm of 2.


Source: `std/math.ml:426`

<a id="function-function-std-math-log10-function-log10-x-std-math-ml-1652022478"></a>
### log10

```ml
function log10(x)
```

Base-10 logarithm log10(x).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |


Source: `std/math.ml:532`

<a id="function-function-std-math-log2-function-log2-x-std-math-ml-559981656"></a>
### log2

```ml
function log2(x)
```

Base-2 logarithm log2(x).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |


Source: `std/math.ml:538`

<a id="function-function-std-math-max-function-max-a-b-std-math-ml-1771960409"></a>
### max

```ml
function max(a, b)
```

Maximum of two values.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | First input value. |
| `b` | `dynamic` | — | Second input value. |


Source: `std/math.ml:84`

<a id="function-function-std-math-min-function-min-a-b-std-math-ml-1964626413"></a>
### min

```ml
function min(a, b)
```

Minimum of two values.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `a` | `dynamic` | — | First input value. |
| `b` | `dynamic` | — | Second input value. |


Source: `std/math.ml:74`

<a id="function-function-std-math-pi-function-pi-std-math-ml-108227704"></a>
### pi

```ml
function pi()
```

Mathematical constant pi.


Source: `std/math.ml:150`

<a id="function-function-std-math-pow-function-pow-base-exponent-std-math-ml-903671006"></a>
### pow

```ml
function pow(base, exponent)
```

Pow(base, exponent).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `base` | `dynamic` | — | Value supplied for `base`. |
| `exponent` | `dynamic` | — | Value supplied for `exponent`. |


Source: `std/math.ml:545`

<a id="function-function-std-math-powi-function-powi-base-exp-std-math-ml-456187076"></a>
### powi

```ml
function powi(base, exp)
```

Integer power (exponentiation by squaring).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `base` | `dynamic` | — | Value supplied for `base`. |
| `exp` | `dynamic` | — | Value supplied for `exp`. |


Source: `std/math.ml:200`

<a id="function-function-std-math-radtodeg-function-radtodeg-rad-std-math-ml-511407857"></a>
### radToDeg

```ml
function radToDeg(rad)
```

Converts radians to degrees.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `rad` | `dynamic` | — | Value supplied for `rad`. |


Source: `std/math.ml:167`

<a id="function-function-std-math-round-function-round-x-std-math-ml-891501820"></a>
### round

```ml
function round(x)
```

Rounds to the nearest integer (half away from zero).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |


Source: `std/math.ml:139`

<a id="function-function-std-math-sign-function-sign-x-std-math-ml-1470077816"></a>
### sign

```ml
function sign(x)
```

Sign of a number.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |


Source: `std/math.ml:44`

<a id="function-function-std-math-sin-function-sin-x-std-math-ml-77784832"></a>
### sin

```ml
function sin(x)
```

Sine (fast approximation).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |


Source: `std/math.ml:293`

<a id="function-function-std-math-sinh-function-sinh-x-std-math-ml-1215837824"></a>
### sinh

```ml
function sinh(x)
```

Hyperbolic sine sinh(x).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |


Source: `std/math.ml:599`

<a id="function-function-std-math-smoothstep-function-smoothstep-edge0-edge1-x-std-math-ml-541762641"></a>
### smoothstep

```ml
function smoothstep(edge0, edge1, x)
```

Smoothstep interpolation (Hermite).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `edge0` | `dynamic` | — | Value supplied for `edge0`. |
| `edge1` | `dynamic` | — | Value supplied for `edge1`. |
| `x` | `dynamic` | — | Value supplied for `x`. |


Source: `std/math.ml:639`

<a id="function-function-std-math-sqrt-function-sqrt-x-std-math-ml-760602576"></a>
### sqrt

```ml
function sqrt(x)
```

Square root (Newton iteration).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |


Source: `std/math.ml:173`

<a id="function-function-std-math-tan-function-tan-x-std-math-ml-1295707230"></a>
### tan

```ml
function tan(x)
```

Tangent (sin/cos).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |


Source: `std/math.ml:350`

<a id="function-function-std-math-tanh-function-tanh-x-std-math-ml-933610836"></a>
### tanh

```ml
function tanh(x)
```

Hyperbolic tangent tanh(x).

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |


Source: `std/math.ml:615`

<a id="function-function-std-math-tau-function-tau-std-math-ml-722341156"></a>
### tau

```ml
function tau()
```

Mathematical constant tau (2*pi).


Source: `std/math.ml:155`

<a id="function-function-std-math-trunc-function-trunc-x-std-math-ml-1042085096"></a>
### trunc

```ml
function trunc(x)
```

Truncates towards 0.

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `x` | `dynamic` | — | Value supplied for `x`. |


Source: `std/math.ml:126`
