// Regression: unrelated imported-style overloads must not make ordinary
// left-associated mixed concatenation or nested unary inference exponential.
struct ConcatToken
  value as int
  operator +(left as ConcatToken, right as int) returns string
    return "token=" + (left.value + right)
  end operator
  operator -(value as ConcatToken) returns ConcatToken
    return ConcatToken(-value.value)
  end operator
end struct

struct MenuState
  page
end struct

visits = 0
evaluationOrder = ""

function observed(value)
  global visits
  global evaluationOrder
  visits += 1
  evaluationOrder = evaluationOrder + ":" + value
  return value
end function

function failure()
  return error(9876, "concat failure")
end function

function failingChain()
  return observed(1) + ":" + failure() + ":" + observed(2)
end function

function main(args)
  global visits
  global evaluationOrder
  state = MenuState(7)
  // Forty additions, starting with an untyped member rather than a literal.
  text = state.page + ":" + observed(0) + ":" + observed(1) + ":" + observed(2) + ":" + observed(3) + ":" + observed(4) + ":" + observed(5) + ":" + observed(6) + ":" + observed(7) + ":" + observed(8) + ":" + observed(9) + ":" + observed(10) + ":" + observed(11) + ":" + observed(12) + ":" + observed(13) + ":" + observed(14) + ":" + observed(15) + ":" + observed(16) + ":" + observed(17) + ":" + observed(18) + ":" + observed(19)
  expected = "7:0:1:2:3:4:5:6:7:8:9:10:11:12:13:14:15:16:17:18:19"
  if text != expected or visits != 20 then return 1 end if
  if "7" + evaluationOrder != expected then return 9 end if

  // Literal-first chains still pass overload analysis before the fast path.
  visits = 0
  literal = "" + observed(0) + observed(1) + observed(2) + observed(3) + observed(4) + observed(5) + observed(6) + observed(7) + observed(8) + observed(9) + observed(0) + observed(1) + observed(2) + observed(3) + observed(4) + observed(5) + observed(6) + observed(7) + observed(8) + observed(9) + observed(0) + observed(1) + observed(2) + observed(3) + observed(4) + observed(5) + observed(6) + observed(7) + observed(8) + observed(9) + observed(0) + observed(1)
  if literal != "01234567890123456789012345678901" or visits != 32 then return 2 end if

  visits = 0
  evaluationOrder = ""
  ordered = observed(1) + observed(2) + ":" + observed(true) + ":" + observed(1.5)
  if ordered != "3:true:1.5" or visits != 4 then return 3 end if
  if evaluationOrder != ":1:2:true:1.5" then return 10 end if
  if 1 + (2 + "x") != "12x" then return 4 end if

  visits = 0
  evaluationOrder = ""
  problem = try(failingChain())
  if typeof(problem) != "error" or visits != 1 then return 5 end if
  if evaluationOrder != ":1" then return 11 end if
  if problem.message != "concat failure" then return 6 end if

  // Qualified struct facts must survive the shared analysis for both unary
  // and binary overload resolution; only builtin inference uses base types.
  token = ConcatToken(3)
  overloaded = (-(-token)) + 4 + ":" + true
  if overloaded != "token=7:true" then return 7 end if
  number = observed(5)
  negated = -(-(-(-(-(-(-(-(-(-(-(-(-(-(-(-(-(-(-(-(-(-(-(-(-(-(-(-(-(-(-(-(number))))))))))))))))))))))))))))))))
  if negated != 5 then return 8 end if
  print "[OK] mixed concat with operator overloads"
  return 0
end function
