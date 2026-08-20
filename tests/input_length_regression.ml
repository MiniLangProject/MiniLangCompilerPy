// Copyright 2026 MiniLangProject contributors
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0; see the LICENSE file.

// Verifies that the native input helper preserves its byte count across the
// allocator call required to materialize the returned MiniLang string.
function main(args)
  line = input()
  if line != "show tables;" then
    print "[FAIL] input content mismatch"
    return 1
  end if
  if len(line) != 12 then
    print "[FAIL] input length mismatch: " + len(line)
    return 1
  end if
  combined = "prefix:" + line + ":suffix"
  if combined != "prefix:show tables;:suffix" then
    print "[FAIL] concatenation after input"
    return 1
  end if
  print "[OK] input ABI length"
  return 0
end function
