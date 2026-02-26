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

print "baseline committed"
print heap_bytes_committed()
print "baseline used"
print heap_bytes_used()

keep =[0, 0, 0, 0, 0, 0, 0, 0]

for i = 1 to 20000
  s = "xxxxxxxx" + i
  t = "yyyyyyyy" +(i * 7)
  obj =[s, t, i, i + 1]
  keep[i % 8] = obj

  if (i % 500) == 0 then
    gc_collect()
    print "committed"
    print heap_bytes_committed()
    print "used"
    print heap_bytes_used()
  end if
end for

