#option FORMAT_ENABLED: bool = true
#const FORMAT_LIMIT = 3
#if not FORMAT_ENABLED
#error "formatter feature disabled"
#endif

import std.threading as threading

//! Formatter regression fixture for the complete modern language surface.
/// A declaration comment containing =>, ??, ?. and #if verbatim.
interface Named
  function name() returns string
end interface

/**
 * Block comments remain opaque to the token formatter.
 */
struct Person implements Named
  value
  function name() returns string
    return this.value
  end function
  static function create(value as string) returns Person
    return Person(value = value)
  end function
end struct

struct Counter
  value as int,
  operator inline +(left as Counter, right as Counter) returns Counter
    return Counter(left.value + right.value)
  end operator
end struct

function inline increment(value as int) returns int
  return value + 1
end function

function synchronized synchronizedValue(value as int) returns int
  return value
end function

iterator function eagerNumbers(limit as int) returns int
  for i = 0 to limit - 1
    yield i
  end for
end function

lazy iterator function lazyNumbers(limit as int) returns int
  for i = 0 to limit - 1
    yield i + 10
  end for
end function

async function doubled(value as int) returns int
  return value * 2
end function

function cleanup()
  return 0
end function

function deferredValue()
  defer cleanup()
  return 7
end function

function guardedClassify(value as int, guard) returns string
  synchronized(guard)
    match value
      case 0
        return "zero"
      end case
      case 1 to 2
        return "small"
      end case
      case default
        return "other"
      end case
    end match
  end synchronized
end function

function loopValue()
  value = 0
  loop
    value = value + 1
  while value < 2
  end loop
  loop
    value = value + 1
  end loop while value < 4
  return value
end function

function branchValue(value)
  if value == 0 then
    return "zero"
  else if value == 1 then
    return "one"
  else
    return "many"
  end if
end function

function main(args)
  guard = threading.Lock.new()
  person = Person.create("MiniLang")
  maybe as Person? = void
  fallback = maybe?.value ?? "fallback"
  transform = function(value as int) returns int => value + 2
  eager = eagerNumbers(3)
  pull = lazyNumbers(2)
  job = doubled(6)
  url = "http://example.test/*not-a-comment*/"
  counter = Counter(2)
  counter += Counter(3)
  flags = +1
  flags <<= 2
  if person.name() != "MiniLang" or fallback != "fallback" then return 1 end if
  if transform(3) != 5 or increment(4) != 5 then return 2 end if
  if len(eager) != 3 or eager[2] != 2 or pull() != 10 or pull() != 11 then return 3 end if
  if await job != 12 or synchronizedValue(8) != 8 then return 4 end if
  if guardedClassify(2, guard) != "small" or deferredValue() != 7 then return 5 end if
  if loopValue() != 4 or branchValue(1) != "one" then return 6 end if
  if url != "http://example.test/*not-a-comment*/" then return 7 end if
  if counter.value != 5 or flags != 4 then return 8 end if
  guard.close()
  print "[OK] formatter modern syntax"
  return 0
end function
