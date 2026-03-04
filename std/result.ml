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

package std.result

// ------------------------------------------------------------
// std.result
// Minimal Option/Result data structures.
//
// NOTE (important for packages):
// Inside a `package`, names are qualified (e.g. std.result.Option).
// Therefore constructors inside this file must use fully-qualified names.
// ------------------------------------------------------------

struct Option
  has
  value

  /*
  creates an Option with a value
  input: any v
  returns: std.result.Option some
  */
  static function Some(v)
  return std.result.Option(true, v)
end function

/*
creates an empty Option
input: none
returns: std.result.Option none
*/
static function None()
return std.result.Option(false, 0)
end function

/*
checks whether this Option contains a value
input: none
returns: bool isSome
*/
function isSome()
  return this.has
end function

/*
checks whether this Option is empty
input: none
returns: bool isNone
*/
function isNone()
  return not this.has
end function

/*
returns the contained value or fallback
input: any fallback
returns: any value
*/
function unwrapOr(fallback)
  if this.has then
    return this.value
  end if
  return fallback
end function

/*
returns the contained value or void
input: none
returns: any value (void if none)
*/
function unwrap()
  if this.has then
    return this.value
  end if
  return
end function

/*
returns the contained value or computes a fallback
input: function thunk() -> any
returns: any value
*/
function unwrapOrElse(thunk)
  if this.has then
    return this.value
  end if
  return thunk()
end function

/*
transforms the contained value
input: function f(any) -> any
returns: std.result.Option mapped
*/
function map(f)
  if this.has then
    return std.result.Option.Some(f(this.value))
  end if
  return std.result.Option.None()
end function

/*
chains Options (flatMap)
input: function f(any) -> std.result.Option
returns: std.result.Option chained
*/
function andThen(f)
  if this.has then
    return f(this.value)
  end if
  return std.result.Option.None()
end function
end struct

struct Result
  ok
  value
  message

  /*
  creates a successful Result
  input: any v
  returns: std.result.Result ok
  */
  static function Ok(v)
  return std.result.Result(true, v, "")
end function

/*
creates a failed Result
input: string msg
returns: std.result.Result err
*/
static function Err(msg)
return std.result.Result(false, 0, msg)
end function

/*
checks whether this Result is ok
input: none
returns: bool isOk
*/
function isOk()
  return this.ok
end function

/*
checks whether this Result is an error
input: none
returns: bool isErr
*/
function isErr()
  return not this.ok
end function

/*
returns the value if ok, otherwise fallback
input: any fallback
returns: any value
*/
function unwrapOr(fallback)
  if this.ok then
    return this.value
  end if
  return fallback
end function

/*
returns the value if ok, otherwise void
input: none
returns: any value (void if err)
*/
function unwrap()
  if this.ok then
    return this.value
  end if
  return
end function

/*
transforms the ok value
input: function f(any) -> any
returns: std.result.Result mapped
*/
function map(f)
  if this.ok then
    return std.result.Result.Ok(f(this.value))
  end if
  return this
end function

/*
chains Results (flatMap)
input: function f(any) -> std.result.Result
returns: std.result.Result chained
*/
function andThen(f)
  if this.ok then
    return f(this.value)
  end if
  return this
end function
end struct


