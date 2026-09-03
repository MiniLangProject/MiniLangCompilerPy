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

import std.string as strings
import std.test as test

_failures = 0
_before_all = 0
_after_all = 0
_before_each = 0
_after_each = 0

function check(condition, label)
  global _failures
  if condition then print label + " [OK]"; return true end if
  _failures = _failures + 1
  print label + " [FAIL]"
  return false
end function

function beforeAll()
  global _before_all
  _before_all = _before_all + 1
end function

function afterAll()
  global _after_all
  _after_all = _after_all + 1
end function

function beforeEach()
  global _before_each
  _before_each = _before_each + 1
end function

function afterEach()
  global _after_each
  _after_each = _after_each + 1
end function

function passingTest()
  test.assertTrue(true)
  test.assertFalse(false)
  test.assertEqual([1, 2], [1, 2])
  test.assertNotEqual(1, 2)
  test.assertNull(void)
  test.assertNotNull(1)
  test.assertType("value", "string")
  test.assertContains("MiniLang", "Lang")
  test.assertContains([1, 2, 3], 2)
  test.assertApproxEqual(1.01, 1.0, 0.02)
  shared = [1]
  test.assertSame(shared, shared)
end function

function failingTest()
  return test.fail("intentional failure")
end function

function skippedTest()
  return test.fail("skipped callback must not run")
end function

function expectedError()
  return error(77, "expected")
end function

function main(args)
  check(test.assertError(expectedError) == true, "assertError")
  check(test.assertErrorCode(expectedError, 77) == true, "assertErrorCode")
  caught = try(test.assertEqual(1, 2, "numbers"))
  check(typeof(caught) == "error" and caught.code == test.ASSERTION_ERROR and strings.contains(caught.message, "numbers"), "captured assertion detail")

  suite = test.Suite.new("framework")
  suite.setBeforeAll(beforeAll)
  suite.setAfterAll(afterAll)
  suite.setBeforeEach(beforeEach)
  suite.setAfterEach(afterEach)
  suite.add("passes", passingTest)
  suite.add("fails", failingTest)
  skipped = test.TestCase.new("skips", skippedTest)
  skipped.skipped = true
  skipped.skip_reason = "fixture"
  skipped.categories = ["unit"]
  skipped.covers = ["std.test.run"]
  suite.addCase(skipped)

  options = test.RunOptions.defaults()
  options.quiet = true
  summary = test.execute([suite], options)
  check(summary.passed == 1 and summary.failed == 1 and summary.skipped == 1, "suite result counts")
  check(_before_all == 1 and _after_all == 1 and _before_each == 2 and _after_each == 2, "fixture lifecycle")
  check(summary.exitCode() == 1 and summary.total() == 3, "summary helpers")

  json = test.toJson(summary)
  junit = test.toJUnit(summary)
  check(strings.contains(json, "\"passed\":1") and strings.contains(json, "intentional failure") and strings.contains(json, "\"categories\":[\"unit\"]") and strings.contains(json, "\"covers\":[\"std.test.run\"]"), "JSON report")
  check(strings.contains(junit, "<testsuite") and strings.contains(junit, "<failure") and strings.contains(junit, "<skipped") and strings.contains(junit, "<property name=\"category\" value=\"unit\"/>") and strings.contains(junit, "<property name=\"covers\" value=\"std.test.run\"/>"), "JUnit report")

  filtered = test.RunOptions.defaults()
  filtered.quiet = true
  filtered.filter = "PASSES"
  filtered_summary = test.execute([suite], filtered)
  check(filtered_summary.passed == 1 and filtered_summary.total() == 1, "case-insensitive name filter")

  fixture_counts = [_before_all, _after_all, _before_each, _after_each]
  listed = test.RunOptions.defaults()
  listed.quiet = true
  listed.list_only = true
  listed.repeat = 3
  listed_summary = test.execute([suite], listed)
  check(listed_summary.skipped == 3 and listed_summary.total() == 3, "list-only ignores repeat")
  check([_before_all, _after_all, _before_each, _after_each] == fixture_counts, "list-only skips fixtures")

  unmatched = test.RunOptions.defaults()
  unmatched.quiet = true
  unmatched.filter = "not present"
  unmatched_summary = test.execute([suite], unmatched)
  check(unmatched_summary.total() == 0 and [_before_all, _after_all, _before_each, _after_each] == fixture_counts, "empty selection skips fixtures")

  if _failures > 0 then return 1 end if
  print "[OK] std.test framework"
  return 0
end function
