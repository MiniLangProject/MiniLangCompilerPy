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

//! Provides the std result package.

package std.result

/// Std.result Minimal Option/Result data structures. NOTE (important for packages): Inside a `package`, names are qualified (e.g. std.result.Option). Therefore constructors inside this file must use fully-qualified names.
struct Option
  /// Has associated with `Option`.
  has
  /// Value associated with `Option`.
  value

  /// Creates an Option with a value.
  /// @param v Value supplied for `v`.
  static function Some(v)
  return std.result.Option(true, v)
end function

/// Creates an empty Option.
static function None()
return std.result.Option(false, 0)
end function

/// Checks whether this Option contains a value.
function isSome()
  return this.has
end function

/// Checks whether this Option is empty.
function isNone()
  return not this.has
end function

/// Returns the contained value or fallback.
/// @param fallback Value supplied for `fallback`.
function unwrapOr(fallback)
  if this.has then
    return this.value
  end if
  return fallback
end function

/// Returns the contained value or void.
function unwrap()
  if this.has then
    return this.value
  end if
  return
end function

/// Returns the contained value or computes a fallback.
/// @param thunk Value supplied for `thunk`.
function unwrapOrElse(thunk)
  if this.has then
    return this.value
  end if
  return thunk()
end function

/// Transforms the contained value.
/// @param f Function invoked by the operation.
function map(f)
  if this.has then
    return std.result.Option.Some(f(this.value))
  end if
  return std.result.Option.None()
end function

/// Chains Options (flatMap).
/// @param f Function invoked by the operation.
function andThen(f)
  if this.has then
    return f(this.value)
  end if
  return std.result.Option.None()
end function
end struct

/// Explicit success/error container for APIs that avoid automatic propagation.
struct Result
  /// Whether `Result` represents a successful result.
  ok
  /// Value associated with `Result`.
  value
  /// Diagnostic message carried by `Result`.
  message

  /// Creates a successful Result.
  /// @param v Value supplied for `v`.
  static function Ok(v)
  return std.result.Result(true, v, "")
end function

/// Creates a failed Result.
/// @param msg Value supplied for `msg`.
static function Err(msg)
return std.result.Result(false, 0, msg)
end function

/// Checks whether this Result is ok.
function isOk()
  return this.ok
end function

/// Checks whether this Result is an error.
function isErr()
  return not this.ok
end function

/// Returns the value if ok, otherwise fallback.
/// @param fallback Value supplied for `fallback`.
function unwrapOr(fallback)
  if this.ok then
    return this.value
  end if
  return fallback
end function

/// Returns the value if ok, otherwise void.
function unwrap()
  if this.ok then
    return this.value
  end if
  return
end function

/// Transforms the ok value.
/// @param f Function invoked by the operation.
function map(f)
  if this.ok then
    return std.result.Result.Ok(f(this.value))
  end if
  return this
end function

/// Chains Results (flatMap).
/// @param f Function invoked by the operation.
function andThen(f)
  if this.ok then
    return f(this.value)
  end if
  return this
end function
end struct


