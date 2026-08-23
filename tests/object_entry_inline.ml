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

import std.assert as t

function inline entryIncrement(value)
  return value + 1
end function

entryInlineValue = entryIncrement(41)

function main(args)
  t.assertEq(entryInlineValue, 42, "entry initializer inline call")
  print "[OK] object entry inline"
end function
