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

//! Supplies tagged declarations used by the mltest end-to-end tests.

package mltest_fixture.sample_tests

import std.test as test

_fixture_active = false

/// Activates the shared fixture.
/// @beforeall
function startFixture()
  global _fixture_active
  _fixture_active = true
end function

/// Keeps per-test setup deliberately lightweight.
/// @beforeeach
function prepareTest()
  test.assertTrue(_fixture_active, "fixture must be active")
end function

/**
 * Verifies an ordinary top-level test callback.
 * @testmethod top-level addition
 * @category unit
 * @covers std.test.assertEqual
 * @timeout 1000
 */
function additionWorks()
  test.assertEqual(2 + 3, 5)
end function

/// Groups static test methods without requiring implicit construction.
struct StaticCases
  /// Verifies discovery of a static struct method.
  /// @testmethod static containment
  /// @category unit
  /// @covers std.test.assertContains
  static function containmentWorks()
    test.assertContains("MiniLang", "Lang")
  end function
end struct

/// This callback must remain unexecuted.
/// @testmethod disabled example
/// @skip demonstrates explicit skips
/// @category slow
function deliberatelySkipped()
  test.fail("a skipped callback was executed")
end function

/// Deactivates the shared fixture.
/// @afterall
function stopFixture()
  global _fixture_active
  _fixture_active = false
end function
