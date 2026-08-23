import std.assert as t

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
  t.assertEq(const_loop(), 2080, "constant-bound loop fast path")
  t.assertEq(int_ops(), 17, "integer operator fast paths")
  t.assertEq(float_fallback(), 3.0, "non-integer arithmetic fallback")
  t.assertEq(extended_type_flow(), 124, "extended local type flow and loop BCE")
  t.assertEq(fixed_negative_index(), 22, "negative fixed index keeps normalization")
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
