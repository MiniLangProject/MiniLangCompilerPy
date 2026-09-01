// Regression coverage for gradual types, richer calls, closures, generators,
// structural interfaces and the thread-backed async syntax.

function fail(message)
  print "[FAIL] " + message
  return 1
end function

function sum3(a as int, b as int = 2, c as int = 3) returns int
  return a + b + c
end function

function restCount(first, rest...)
  return [first, len(rest), rest[0], rest[1]]
end function

interface Named
  function name() returns string
end interface

struct Person implements Named
  value as string

  function name() returns string
    return this.value
  end function

  function label(prefix as string = "Hello") returns string
    return prefix + " " + this.value
  end function
end struct

iterator function numbers(limit as int) returns int
  for i = 0 to limit
    yield i
  end for
end function

async function doubled(value as int) returns int
  return value * 2
end function

function wrongReturn() returns int
  return "not an int"
end function

function invalidPerson()
  return Person(value = 9)
end function

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

// `match` and `select` remain legal identifiers outside their contextual forms.
function contextualNames(match)
  select = match + 1
  return select
end function

function main(args)
sentinelText = "void"
if "x" + sentinelText != "xvoid" then return fail("literal void string concatenation") end if
sentinelText = "<unsupported>"
if sentinelText + "x" != "<unsupported>x" then return fail("literal unsupported string concatenation") end if

if sum3(4) != 9 then return fail("default arguments") end if
if sum3(c = 8, a = 1, b = 2) != 11 then return fail("named arguments") end if
paramError = try(sum3("wrong"))
if typeof(paramError) != "error" or paramError.code != 1308 then return fail("parameter type guard") end if

rest = restCount(7, 8, 9)
if rest[0] != 7 or rest[1] != 2 or rest[2] != 8 or rest[3] != 9 then
  return fail("variadic arguments")
end if

factor = 4
multiply = function(value as int) returns int => value * factor
if multiply(3) != 12 then return fail("lambda closure") end if

maybe as Person? = void
if (maybe?.value ?? "fallback") != "fallback" then return fail("optional chaining/coalescing") end if
maybe = Person(value = "MiniLang")
if maybe?.name() != "MiniLang" then return fail("safe method call") end if
person = Person(value = "MiniLang")
if person.label() != "Hello MiniLang" or person.label(prefix = "Hi") != "Hi MiniLang" then return fail("method default/named arguments") end if
badPerson = try(invalidPerson())
if typeof(badPerson) != "error" or badPerson.code != 1308 then return fail("typed struct field guard") end if

seq = numbers(4)
if len(seq) != 5 or seq[0] != 0 or seq[4] != 4 then return fail("iterator yield") end if
if classify(0) != "zero" or classify(2) != "small" or classify(9) != "other" then return fail("match cases") end if
if contextualNames(4) != 5 then return fail("contextual match/select names") end if

typeError = try(wrongReturn())
if typeof(typeError) != "error" or typeError.code != 1308 then return fail("runtime type guard") end if

one = doubled(10)
two = doubled(value = 11)
winner = select(one, two)
if winner < 0 or winner > 1 then return fail("async select") end if
if await one != 20 or await two != 22 then return fail("async await") end if
if await 17 != 17 or select() != -1 then return fail("async immediate/empty") end if

print "[OK] language extensions"
return 0
end function
