// Defer's synthesized replay must keep the declaring module's name context.
package optimizer_support.defer_scope
saved = ""

function record(value)
  global saved
  saved = value
end function

function exercise()
  defer record("module")
  return 1
end function

function result()
  return saved
end function
