/*
Copyright 2026 Nils Kopal

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0
*/

//! Verifies that documentation comments remain compile-time-only source data.

/// Adds two integers.
/// @param left Text may contain parser tokens such as `)`, `=>`, and `#if`.
/// @param right Second input value.
/// @returns The integer sum.
function documentedAdd(left as int, right as int) returns int
  return left + right
end function

/** A documented record whose block comment must also remain inert. */
struct DocumentedValue
  value as int,
end struct

/// Runs the declaration-comment regression test.
/// @param args Process arguments, which are unused.
function main(args)
  item = DocumentedValue(documentedAdd(19, 23))
  if item.value != 42 then return 1 end if
  print "[OK] declaration comments"
  return 0
end function
