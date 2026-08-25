import std.assert as t
import tests.codegen_context_values as context_values

const FOLDED_SHIFT = 1 << 65
const FOLDED_WRAP = 1152921504606846975 + 1

type_query_effects = 0

function inline pruned_add(x)
  return x + 1
end function

function inline kept_add(x)
  return x + 2
end function

function inline budget_add(x)
  return x + 1
end function

function inline loop_inline(n)
  i = 0
  total = 0
  while i < n
    total = total + i
    i = i + 1
  end while
  return total
end function

function leaf_frame()
  x = 41
  return x + 1
end function

function int_flow()
  i = 0
  total = 0
  while i < 100
    total = total + i
    i = i + 1
  end while
  return total
end function

function promoted_leaf(value)
  i = 0
  total = 0
  while i < 3
    total = total + value
    i = i + 1
  end while
  return total
end function

function promoted_across_user_call()
  i = 0
  total = 0
  while i < 5
    total = total + promoted_leaf(i)
    i = i + 1
  end while
  return total
end function

function const_loop()
  total = 0
  for i = 0 to 64
    total = total + i
  end for
  return total
end function

function int_ops()
  x = 123
  y = 7
  return ((x % y) << 2) | 1
end function

function constant_strength_reduction()
  x = 123
  return (x * 8) + (x % 16) + (x >> 2) + (x + 123)
end function

// Parameter operands keep these helpers on the generic checked paths. The
// assertions below compare them with operations specialized from a proven
// local, including tagged wraparound and sign-sensitive edge cases.
function generic_add(a, b) return a + b end function
function generic_sub(a, b) return a - b end function
function generic_mul(a, b) return a * b end function
function generic_div(a, b) return a / b end function
function generic_mod(a, b) return a % b end function
function generic_and(a, b) return a & b end function
function generic_shl(a, b) return a << b end function
function generic_shr(a, b) return a >> b end function

function strength_reduction_edge_cases()
  ok = true
  x = -1152921504606846976
  if not t.assertEq(x * 8, generic_mul(x, 8), "strength edge: minimum tagged int multiply") then ok = false end if
  if not t.assertEq(x + -268435456, generic_add(x, -268435456), "strength edge: minimum imm32 add") then ok = false end if
  if not t.assertEq(x - -268435456, generic_sub(x, -268435456), "strength edge: minimum imm32 subtract") then ok = false end if
  if not t.assertEq(x % 16, generic_mod(x, 16), "strength edge: negative power-of-two modulo") then ok = false end if
  if not t.assertEq(x % 2147483648, generic_mod(x, 2147483648), "strength edge: largest masked divisor") then ok = false end if
  if not t.assertEq(x % -1, generic_mod(x, -1), "strength edge: minimum int modulo negative one") then ok = false end if
  if not t.assertEq(x >> 65, generic_shr(x, 65), "strength edge: masked right shift") then ok = false end if
  if not t.assertEq(x << 65, generic_shl(x, 65), "strength edge: masked left shift") then ok = false end if

  x = 1152921504606846975
  if not t.assertEq(x * -2147483648, generic_mul(x, -2147483648), "strength edge: signed imm32 multiply") then ok = false end if
  if not t.assertEq(123 + x, generic_add(123, x), "strength edge: constant left addition") then ok = false end if
  if not t.assertEq(x % -8, generic_mod(x, -8), "strength edge: negative divisor modulo") then ok = false end if
  if not t.assertEq(x * 0, generic_mul(x, 0), "strength edge: multiply by zero") then ok = false end if
  if not t.assertEq(x * -1, generic_mul(x, -1), "strength edge: multiply by negative one") then ok = false end if
  if not t.assertEq(typeof(x % 0), typeof(generic_mod(x, 0)), "strength edge: zero divisor fallback") then ok = false end if
  if not t.assertEq(typeof(x << -1), typeof(generic_shl(x, -1)), "strength edge: negative shift fallback") then ok = false end if
  return ok
end function

function type_query_effect()
  global type_query_effects
  type_query_effects = type_query_effects + 1
  return 1
end function

function optimizer_semantic_edges()
  ok = true
  x = 7
  if not t.assertEq(FOLDED_SHIFT, 2, "constant folding masks x64 shift counts") then ok = false end if
  if not t.assertEq(FOLDED_WRAP, -1152921504606846976, "constant folding wraps signed tagged ints") then ok = false end if
  if not t.assertEq((1152921504606846975 + 1) > 0, false, "nested folding compares wrapped ints") then ok = false end if
  if not t.assertEq(typeof(x / 0), typeof(generic_div(x, 0)), "type flow keeps division-by-zero fallible") then ok = false end if
  if not t.assertEq(typeof(try((x % 0) & 1)), typeof(try(generic_and(generic_mod(x, 0), 1))), "known-int flow keeps modulo fallible") then ok = false end if
  if not t.assertEq(typeof(try((x << -1) & 1)), typeof(try(generic_and(generic_shl(x, -1), 1))), "known-int flow keeps shifts fallible") then ok = false end if
  if not t.assertEq(typeof(x << 0x1000000000000000), typeof(generic_shl(x, 0x1000000000000000)), "large literal shift parity") then ok = false end if
  if not t.assertEq(typeof(bytes(-1)), "void", "invalid byte size has no bytes type fact") then ok = false end if
  if not t.assertEq(typeof(bytes(2147483648)), "void", "oversized byte buffer has no bytes type fact") then ok = false end if
  if not t.assertEq(typeof(bytes(1, 300)), "void", "invalid byte fill has no bytes type fact") then ok = false end if
  if not t.assertEq(typeof(type_query_effect() == 1), "bool", "static type query result") then ok = false end if
  if not t.assertEq(type_query_effects, 1, "static type query preserves operand effects") then ok = false end if
  return ok
end function

function float_fallback()
  x = 1.0
  return x + 2
end function

struct Slot
  value,
end struct

struct FlowPoint
  x,
  y,
end struct

struct MethodPoint
  value,

  function inline bumped(delta)
    return this.value + delta
  end function

  function scaled(factor)
    return this.value * factor
  end function
end struct

struct WideMethodPoint
  base,

  function consume(a, b, c, d, e)
    return this.base + len(a) + len(b) + len(c) + len(d) + len(e)
  end function
end struct

function known_method_calls()
  point = MethodPoint(21)
  return point.bumped(1) + point.scaled(2)
end function

function known_wide_method_call()
  point = WideMethodPoint(10)
  return point.consume([1], [1, 2], [1, 2, 3], [1, 2, 3, 4], [1, 2, 3, 4, 5])
end function

function extended_type_flow()
  values = [1, 2, 3, 4, 5, 6, 7, 8]
  data = bytes(8, 0)
  point = FlowPoint(40, 0)
  gate = true
  left = 1.5
  right = 2.5
  total = 0

  // Both loops exceed the small-loop unroll budget. Their fixed-length
  // containers can therefore exercise invariant-base hoisting and BCE.
  for i = 0 to len(values) - 1
    total = total + values[i]
  end for
  for j = 0 to len(data) - 1
    data[j] = j + 1
    total = total + data[j]
  end for

  if gate then total = total + point.x end if
  point.y = 8
  return total + point.y + (left + right)
end function

function fixed_negative_index()
  values = [11, 22]
  return values[-1]
end function

function invalid_bytes_index()
  data = bytes(-1)
  return data[0]
end function

function checked_bytes_roundtrip(value)
  data = bytes(value)
  data[0] = data[0] + 1
  return data[0]
end function

function checked_bytes_value_flow(value)
  data = bytes(value)
  first = data[0]
  return first + 1
end function

function tenth(a, b, c, d, e, f, g, h, i, j)
  return j
end function

function inline hidden_wide_call(x)
  return tenth(x, 2, 3, 4, 5, 6, 7, 8, 9, 10)
end function

function narrow_inline_caller()
  return hidden_wide_call(1)
end function

// A qualified explicit global must not consume a phantom local stack slot.
// The structural listing test also checks the compact disp8 temp access.
namespace qualified_global_layout
  value = 0

  function identity(x)
    return x
  end function

  function writeAndCall(x, y)
    global value
    value = y
    return identity(x)
  end function
end namespace

// These callers sort after main and cross multiple eight-function object
// batches. Their shared callee budget must stay cumulative across fragments.
function zz_budget_caller01() return budget_add(41) end function
function zz_budget_caller02() return budget_add(41) end function
function zz_budget_caller03() return budget_add(41) end function
function zz_budget_caller04() return budget_add(41) end function
function zz_budget_caller05() return budget_add(41) end function
function zz_budget_caller06() return budget_add(41) end function
function zz_budget_caller07() return budget_add(41) end function
function zz_budget_caller08() return budget_add(41) end function
function zz_budget_caller09() return budget_add(41) end function

function main(args)
  t.assertEq(pruned_add(41), 42, "single-use inline function")

  f = kept_add
  t.assertEq(f(40), 42, "address-taken inline function")

  budget_total = 0
  budget_total = budget_total + budget_add(0)
  budget_total = budget_total + budget_add(1)
  budget_total = budget_total + budget_add(2)
  budget_total = budget_total + budget_add(3)
  budget_total = budget_total + budget_add(4)
  budget_total = budget_total + budget_add(5)
  budget_total = budget_total + budget_add(6)
  budget_total = budget_total + budget_add(7)
  budget_total = budget_total + budget_add(8)
  budget_total = budget_total + budget_add(9)
  budget_total = budget_total + budget_add(10)
  budget_total = budget_total + budget_add(11)
  budget_total = budget_total + budget_add(12)
  budget_total = budget_total + budget_add(13)
  budget_total = budget_total + budget_add(14)
  budget_total = budget_total + budget_add(15)
  budget_total = budget_total + budget_add(16)
  budget_total = budget_total + budget_add(17)
  budget_total = budget_total + budget_add(18)
  budget_total = budget_total + budget_add(19)
  budget_total = budget_total + budget_add(20)
  budget_total = budget_total + budget_add(21)
  budget_total = budget_total + budget_add(22)
  budget_total = budget_total + budget_add(23)
  budget_total = budget_total + budget_add(24)
  budget_total = budget_total + budget_add(25)
  budget_total = budget_total + budget_add(26)
  budget_total = budget_total + budget_add(27)
  budget_total = budget_total + budget_add(28)
  budget_total = budget_total + budget_add(29)
  budget_total = budget_total + budget_add(30)
  budget_total = budget_total + budget_add(31)
  budget_total = budget_total + budget_add(32)
  budget_total = budget_total + budget_add(33)
  budget_total = budget_total + budget_add(34)
  budget_total = budget_total + budget_add(35)
  budget_total = budget_total + budget_add(36)
  budget_total = budget_total + budget_add(37)
  budget_total = budget_total + budget_add(38)
  budget_total = budget_total + budget_add(39)
  t.assertEq(budget_total, 820, "native inline expansion budget fallback")
  t.assertEq(loop_inline(7), 21, "complex inline fallback body")

  t.assertEq(leaf_frame(), 42, "small root-frame prologue")
  t.assertEq(int_flow(), 4950, "local integer type flow")
  t.assertEq(promoted_across_user_call(), 30, "promoted locals survive promoted user call")
  t.assertEq(const_loop(), 2080, "constant-bound loop fast path")
  t.assertEq(int_ops(), 17, "integer operator fast paths")
  t.assertEq(constant_strength_reduction(), 1271, "constant integer strength reduction")
  if not t.assertEq(strength_reduction_edge_cases(), true, "strength reduction matches generic edge semantics") then return 1 end if
  if not t.assertEq(optimizer_semantic_edges(), true, "optimizer preserves fallible and wrapped semantics") then return 1 end if
  t.assertEq(known_method_calls(), 64, "known struct method devirtualization and inlining")
  t.assertEq(known_wide_method_call(), 25, "known method wide-call rooting")
  t.assertEq(float_fallback(), 3.0, "non-integer arithmetic fallback")
  t.assertEq(extended_type_flow(), 124, "extended local type flow and loop BCE")
  t.assertEq(fixed_negative_index(), 22, "negative fixed index keeps normalization")
  t.assertEq(checked_bytes_roundtrip("A"), 66, "checked bytes type flow read and write")
  t.assertEq(checked_bytes_value_flow("A"), 66, "checked bytes result type flows through locals")
  t.assertEq(typeof(try(checked_bytes_value_flow(-1))), "error", "checked bytes local flow preserves target error")
  t.assertEq(typeof(try(invalid_bytes_index())), "error", "checked bytes type flow preserves target error")
  t.assertEq(context_values.enumValueFlow(false), true, "package enum constants retain integer type flow")
  t.assertEq(context_values.enumValueFlow(true), false, "package enum type flow tracks every assignment")
  slot = Slot(0)
  slot.value = tenth(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)
  t.assertEq(slot.value, 10, "member assignment call-arity sizing")
  t.assertEq(narrow_inline_caller(), 10, "hidden inline call-arity sizing")
  indexed = [0]
  indexed[0] = tenth(1, 2, 3, 4, 5, 6, 7, 8, 9, 11)
  t.assertEq(indexed[0], 11, "index assignment call-arity sizing")
  t.assertEq(qualified_global_layout.writeAndCall(42, 7), 42, "qualified global stack layout")
  t.assertEq(qualified_global_layout.value, 7, "qualified global write")
  t.assertEq(zz_budget_caller09(), 42, "inline budget survives object batches")
  print "[OK] codegen optimizations"
  return 0
end function
