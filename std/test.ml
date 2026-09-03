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

//! Provides assertions, suites, fixtures, filtering, timing, and portable
//! console, JSON, and JUnit reporting for MiniLang tests.

package std.test

import std.fs as fs
import std.string as strings
import std.string_builder as builders
import std.time as time

/// Error code returned by an assertion that does not hold.
const ASSERTION_ERROR = 1800
/// Error code returned when a timed test does not finish before its deadline.
const TIMEOUT_ERROR = 1801
/// Error code returned for an invalid test-framework argument or declaration.
const CONFIGURATION_ERROR = 1802

/// Status assigned to a successful test result.
const STATUS_PASSED = "passed"
/// Status assigned to a failed test result.
const STATUS_FAILED = "failed"
/// Status assigned to a deliberately skipped test result.
const STATUS_SKIPPED = "skipped"

/// Construct a structured assertion error.
/// @param message Human-readable failure detail.
/// @internal
function _failure(message)
  return error(ASSERTION_ERROR, message)
end function

/// Convert a value to a stable diagnostic representation.
/// @param value Value shown in an assertion failure.
/// @internal
function _display(value)
  if value is void then return "void" end if
  if typeof(value) == "string" then return "\"" + value + "\"" end if
  return str(value)
end function

/// Assert that a value is truthy.
/// @param condition Condition expected to be true.
/// @param message Optional diagnostic label.
function assertTrue(condition, message = "")
  if condition then return true end if
  if message == "" then message = "expected condition to be true" end if
  return _failure(message)
end function

/// Assert that a value is false.
/// @param condition Condition expected to be false.
/// @param message Optional diagnostic label.
function assertFalse(condition, message = "")
  if not condition then return true end if
  if message == "" then message = "expected condition to be false" end if
  return _failure(message)
end function

/// Assert value equality using MiniLang's ordinary equality semantics.
/// @param actual Observed value.
/// @param expected Required value.
/// @param message Optional diagnostic label.
function assertEqual(actual, expected, message = "")
  if actual == expected then return true end if
  detail = "expected " + _display(expected) + ", got " + _display(actual)
  if message != "" then detail = message + ": " + detail end if
  return _failure(detail)
end function

/// Assert that two values are different.
/// @param actual Observed value.
/// @param unexpected Value which must not be observed.
/// @param message Optional diagnostic label.
function assertNotEqual(actual, unexpected, message = "")
  if actual != unexpected then return true end if
  detail = "did not expect " + _display(unexpected)
  if message != "" then detail = message + ": " + detail end if
  return _failure(detail)
end function

/// Assert managed-object or callable identity rather than structural equality.
/// @param actual Observed value.
/// @param expected Required identical value.
/// @param message Optional diagnostic label.
function assertSame(actual, expected, message = "")
  if nativeRawValue(actual) == nativeRawValue(expected) then return true end if
  detail = "expected both values to have identical runtime identity"
  if message != "" then detail = message + ": " + detail end if
  return _failure(detail)
end function

/// Assert that a value is void.
/// @param value Observed value.
/// @param message Optional diagnostic label.
function assertNull(value, message = "")
  if value is void then return true end if
  detail = "expected void, got " + _display(value)
  if message != "" then detail = message + ": " + detail end if
  return _failure(detail)
end function

/// Assert that a value is not void.
/// @param value Observed value.
/// @param message Optional diagnostic label.
function assertNotNull(value, message = "")
  if value is not void then return true end if
  if message == "" then message = "expected a non-void value" end if
  return _failure(message)
end function

/// Assert the public runtime category returned by `typeof`.
/// @param value Observed value.
/// @param expected_type Expected runtime category.
/// @param message Optional diagnostic label.
function assertType(value, expected_type, message = "")
  actual_type = typeof(value)
  if actual_type == expected_type then return true end if
  detail = "expected type " + expected_type + ", got " + actual_type
  if message != "" then detail = message + ": " + detail end if
  return _failure(detail)
end function

/// Assert that a string or array contains a requested value.
/// @param container String or array to search.
/// @param expected Requested substring or element.
/// @param message Optional diagnostic label.
function assertContains(container, expected, message = "")
  found = false
  if typeof(container) == "string" and typeof(expected) == "string" then
    found = strings.contains(container, expected)
  else if typeof(container) == "array" then
    if len(container) > 0 then
      for i = 0 to len(container) - 1
        if container[i] == expected then found = true break end if
      end for
    end if
  else
    return _failure("assertContains expects a string or array container")
  end if
  if found then return true end if
  detail = "expected container to contain " + _display(expected)
  if message != "" then detail = message + ": " + detail end if
  return _failure(detail)
end function

/// Assert approximate numeric equality.
/// @param actual Observed numeric value.
/// @param expected Required numeric value.
/// @param epsilon Maximum absolute difference.
/// @param message Optional diagnostic label.
function assertApproxEqual(actual, expected, epsilon, message = "")
  if typeof(epsilon) != "int" and typeof(epsilon) != "float" then
    return _failure("assertApproxEqual epsilon must be numeric")
  end if
  if epsilon < 0 then return _failure("assertApproxEqual epsilon must not be negative") end if
  difference = actual - expected
  if difference < 0 then difference = 0 - difference end if
  if difference <= epsilon then return true end if
  detail = "expected " + _display(expected) + " +/- " + _display(epsilon) + ", got " + _display(actual)
  if message != "" then detail = message + ": " + detail end if
  return _failure(detail)
end function

/// Assert that invoking a zero-argument callback produces an error value.
/// @param callback Operation expected to fail.
/// @param message Optional diagnostic label.
function assertError(callback, message = "")
  if typeof(callback) != "function" then return _failure("assertError expects a function") end if
  result = try(callback())
  if typeof(result) == "error" then return true end if
  detail = "expected an error, got " + _display(result)
  if message != "" then detail = message + ": " + detail end if
  return _failure(detail)
end function

/// Assert that invoking a callback produces an error with a requested code.
/// @param callback Operation expected to fail.
/// @param expected_code Required MiniLang error code.
/// @param message Optional diagnostic label.
function assertErrorCode(callback, expected_code, message = "")
  if typeof(callback) != "function" then return _failure("assertErrorCode expects a function") end if
  result = try(callback())
  if typeof(result) != "error" then
    detail = "expected error code " + expected_code + ", got " + _display(result)
    if message != "" then detail = message + ": " + detail end if
    return _failure(detail)
  end if
  if result.code == expected_code then return true end if
  detail2 = "expected error code " + expected_code + ", got " + result.code
  if message != "" then detail2 = message + ": " + detail2 end if
  return _failure(detail2)
end function

/// Fail the current test immediately.
/// @param message Failure detail.
function fail(message = "test failed")
  return _failure(message)
end function

/// One executable test plus source and discovery metadata.
struct TestCase
  /// Display name shown by reporters.
  name
  /// Zero-argument function executed by the runner.
  callback
  /// Project-relative source path when discovered by `mltest`.
  source
  /// One-based declaration line.
  line
  /// Whether the test is deliberately disabled.
  skipped
  /// Explanation attached to a skipped test.
  skip_reason
  /// Per-test timeout in milliseconds, or zero when unlimited.
  timeout_ms
  /// Categories used by runner filters.
  categories
  /// Qualified API symbols covered by this test.
  covers

  /// Create a test with portable default metadata.
  /// @param name Display name.
  /// @param callback Zero-argument test function.
  static function new(name, callback)
    if typeof(name) != "string" or name == "" then return error(CONFIGURATION_ERROR, "test name must be non-empty") end if
    if typeof(callback) != "function" then return error(CONFIGURATION_ERROR, "test callback must be a function") end if
    return TestCase(name, callback, "", 0, false, "", 0, [], [])
  end function
end struct

/// A named set of tests and optional lifecycle callbacks.
struct Suite
  /// Suite display name.
  name
  /// Registered TestCase values.
  cases
  /// Optional suite-level setup callback.
  before_all
  /// Optional suite-level cleanup callback.
  after_all
  /// Optional per-test setup callback.
  before_each
  /// Optional per-test cleanup callback.
  after_each

  /// Create an empty suite.
  /// @param name Suite display name.
  static function new(name)
    if typeof(name) != "string" or name == "" then return error(CONFIGURATION_ERROR, "suite name must be non-empty") end if
    return Suite(name, [], void, void, void, void)
  end function

  /// Register a fully configured test case.
  /// @param test_case TestCase to append.
  function addCase(test_case)
    if typeof(test_case) != "struct" then return error(CONFIGURATION_ERROR, "addCase expects a TestCase") end if
    this.cases = this.cases + [test_case]
    return this
  end function

  /// Register a test callback using default metadata.
  /// @param name Display name.
  /// @param callback Zero-argument test function.
  function add(name, callback)
    test_case = TestCase.new(name, callback)
    this.cases = this.cases + [test_case]
    return this
  end function

  /// Set the callback executed once before this suite.
  /// @param callback Zero-argument setup function.
  function setBeforeAll(callback)
    this.before_all = callback
    return this
  end function

  /// Set the callback executed once after this suite.
  /// @param callback Zero-argument cleanup function.
  function setAfterAll(callback)
    this.after_all = callback
    return this
  end function

  /// Set the callback executed before every selected test.
  /// @param callback Zero-argument setup function.
  function setBeforeEach(callback)
    this.before_each = callback
    return this
  end function

  /// Set the callback executed after every selected test.
  /// @param callback Zero-argument cleanup function.
  function setAfterEach(callback)
    this.after_each = callback
    return this
  end function
end struct

/// Effective settings for one test run.
struct RunOptions
  /// Case-insensitive substring matched against suite and test names.
  filter
  /// Required category, or an empty string.
  category
  /// Excluded category, or an empty string.
  excluded_category
  /// Number of times to execute each selected test.
  repeat
  /// Deterministic shuffle seed; zero preserves declaration order.
  seed
  /// Whether the run stops after its first failure.
  fail_fast
  /// Whether selected tests are listed without being executed.
  list_only
  /// Whether console reporting is suppressed.
  quiet
  /// Report format: console, json, or junit.
  format
  /// Report destination used by JSON and JUnit formats.
  output

  /// Return deterministic default settings.
  static function defaults()
    return RunOptions("", "", "", 1, 0, false, false, false, "console", "")
  end function
end struct

/// Result of one test or lifecycle callback.
struct TestResult
  /// Suite display name.
  suite
  /// Test or lifecycle callback display name.
  name
  /// One of the STATUS_* constants.
  status
  /// Elapsed execution time in milliseconds.
  duration_ms
  /// Failure or skip description.
  message
  /// Source file recorded during discovery.
  source
  /// One-based source line recorded during discovery.
  line
  /// Categories assigned to the test.
  categories
  /// Coverage declarations assigned to the test.
  covers
end struct

/// Aggregate counts and detailed results from a completed run.
struct RunSummary
  /// Number of passed results.
  passed
  /// Number of failed results.
  failed
  /// Number of skipped results.
  skipped
  /// Elapsed duration of the complete run in milliseconds.
  duration_ms
  /// Detailed TestResult values in execution order.
  results

  /// Return the total number of recorded results.
  function total()
    return this.passed + this.failed + this.skipped
  end function

  /// Return the process exit code expected by test automation.
  function exitCode()
    if this.failed > 0 then return 1 end if
    return 0
  end function
end struct

/// Mutable cross-thread result holder used for bounded tests.
/// @internal
struct _Invocation
  /// Callback executed by the worker thread.
  callback
  /// Captured return value or error.
  result
end struct

/// Execute a callback on a test thread and retain its result.
/// @param invocation Shared invocation holder.
/// @internal
function _threadEntry(invocation)
  invocation.result = try(invocation.callback())
end function

/// Execute a callback directly or with an enforced timeout.
/// @param callback Zero-argument operation.
/// @param timeout_ms Maximum duration in milliseconds, or zero.
/// @internal
function _executeCallback(callback, timeout_ms)
  if typeof(callback) != "function" then return error(CONFIGURATION_ERROR, "test callback is not callable") end if
  if timeout_ms <= 0 then return try(callback()) end if

  invocation = _Invocation(callback, void)
  worker = Thread(_threadEntry, "std.test.timeout")
  if not worker.Start(invocation) then return error(TIMEOUT_ERROR, "could not start timed test") end if
  completed = worker.Join(timeout_ms)
  if completed then
    worker.Close()
    return invocation.result
  end if
  worker.Stop()
  worker.Join(1000)
  worker.Close()
  return error(TIMEOUT_ERROR, "test exceeded timeout of " + timeout_ms + " ms")
end function

/// Report whether a string array contains a value.
/// @internal
function _containsValue(values, expected)
  if typeof(values) != "array" or len(values) == 0 then return false end if
  for i = 0 to len(values) - 1
    if values[i] == expected then return true end if
  end for
  return false
end function

/// Decide whether a test passes active name and category filters.
/// @internal
function _selected(test_case, options, suite_name = "")
  if options.filter != "" then
    needle = strings.toLowerAscii(options.filter)
    if not strings.contains(strings.toLowerAscii(test_case.name), needle) and not strings.contains(strings.toLowerAscii(suite_name), needle) then return false end if
  end if
  if options.category != "" and not _containsValue(test_case.categories, options.category) then return false end if
  if options.excluded_category != "" and _containsValue(test_case.categories, options.excluded_category) then return false end if
  return true
end function

/// Return whether a suite contains at least one selected test.
/// @internal
function _suiteHasSelected(suite, options)
  if len(suite.cases) == 0 then return false end if
  for i = 0 to len(suite.cases) - 1
    if _selected(suite.cases[i], options, suite.name) then return true end if
  end for
  return false
end function

/// Copy and optionally deterministically shuffle one suite's tests.
/// @internal
function _orderedCases(cases, seed, repetition)
  result = cases + []
  if seed == 0 or len(result) < 2 then return result end if
  state = (seed + repetition) & 0x7FFFFFFF
  i = len(result) - 1
  while i > 0
    state = (state * 1103515245 + 12345) & 0x7FFFFFFF
    target = state % (i + 1)
    temporary = result[i]
    result[i] = result[target]
    result[target] = temporary
    i = i - 1
  end while
  return result
end function

/// Append a result and update aggregate counters.
/// @internal
function _record(summary, result)
  summary.results = summary.results + [result]
  if result.status == STATUS_PASSED then summary.passed = summary.passed + 1
  else if result.status == STATUS_SKIPPED then summary.skipped = summary.skipped + 1
  else summary.failed = summary.failed + 1
  end if
end function

/// Convert a captured value into a failure message.
/// @internal
function _resultMessage(value)
  if typeof(value) == "error" then return value.message end if
  return ""
end function

/// Execute one lifecycle callback and return a result when it fails.
/// @internal
function _runHook(suite_name, hook_name, callback)
  if callback is void then return end if
  started = time.ticks()
  value = try(_executeCallback(callback, 0))
  duration = time.elapsed(started, time.ticks())
  if typeof(duration) != "int" then duration = 0 end if
  if typeof(value) == "error" then
    return TestResult(suite_name, hook_name, STATUS_FAILED, duration, _resultMessage(value), "", 0, [], [])
  end if
end function

/// Execute selected suites without rendering a report.
/// @param suites Array of Suite values.
/// @param options Effective RunOptions.
function execute(suites, options)
  summary = RunSummary(0, 0, 0, 0, [])
  run_started = time.ticks()
  stop = false

  if typeof(suites) != "array" then
    _record(summary, TestResult("std.test", "configuration", STATUS_FAILED, 0, "execute expects an array of suites", "", 0, [], []))
    return summary
  end if

  if len(suites) > 0 then
    for si = 0 to len(suites) - 1
      suite = suites[si]
      if not _suiteHasSelected(suite, options) then continue end if
      before_all_failure = void
      if not options.list_only then before_all_failure = _runHook(suite.name, "beforeAll", suite.before_all) end if
      if typeof(before_all_failure) == "struct" then
        _record(summary, before_all_failure)
        if options.fail_fast then stop = true end if
      end if

      if not stop and typeof(before_all_failure) != "struct" and len(suite.cases) > 0 then
        repetition = 0
        repetitions = options.repeat
        if options.list_only then repetitions = 1 end if
        while repetition < repetitions and not stop
          cases = _orderedCases(suite.cases, options.seed, repetition)
          for ci = 0 to len(cases) - 1
            test_case = cases[ci]
            if not _selected(test_case, options, suite.name) then continue end if
            display_name = test_case.name
            if options.repeat > 1 then display_name = display_name + " [" + (repetition + 1) + "/" + options.repeat + "]" end if

            if options.list_only then
              _record(summary, TestResult(suite.name, display_name, STATUS_SKIPPED, 0, "listed only", test_case.source, test_case.line, test_case.categories, test_case.covers))
              continue
            end if
            if test_case.skipped then
              reason = test_case.skip_reason
              if reason == "" then reason = "marked with @skip" end if
              _record(summary, TestResult(suite.name, display_name, STATUS_SKIPPED, 0, reason, test_case.source, test_case.line, test_case.categories, test_case.covers))
              continue
            end if

            started = time.ticks()
            value = _runHook(suite.name, "beforeEach", suite.before_each)
            if typeof(value) != "struct" then value = try(_executeCallback(test_case.callback, test_case.timeout_ms)) end if
            after_value = _runHook(suite.name, "afterEach", suite.after_each)
            if typeof(value) != "struct" and typeof(after_value) == "struct" then value = after_value end if
            duration = time.elapsed(started, time.ticks())
            if typeof(duration) != "int" then duration = 0 end if

            result = void
            if typeof(value) == "struct" then
              result = TestResult(suite.name, display_name, STATUS_FAILED, duration, value.message, test_case.source, test_case.line, test_case.categories, test_case.covers)
            else if typeof(value) == "error" then
              result = TestResult(suite.name, display_name, STATUS_FAILED, duration, value.message, test_case.source, test_case.line, test_case.categories, test_case.covers)
            else
              result = TestResult(suite.name, display_name, STATUS_PASSED, duration, "", test_case.source, test_case.line, test_case.categories, test_case.covers)
            end if
            _record(summary, result)
            if result.status == STATUS_FAILED and options.fail_fast then stop = true end if
          end for
          repetition = repetition + 1
        end while
      end if

      if not options.list_only then
        after_all_failure = _runHook(suite.name, "afterAll", suite.after_all)
        if typeof(after_all_failure) == "struct" then _record(summary, after_all_failure) end if
      end if
      if stop then break end if
    end for
  end if

  summary.duration_ms = time.elapsed(run_started, time.ticks())
  if typeof(summary.duration_ms) != "int" then summary.duration_ms = 0 end if
  return summary
end function

/// Escape a string for JSON output.
/// @internal
function _jsonEscape(value)
  result = builders.StringBuilder.withCapacity(len(value) + 16)
  if len(value) > 0 then
    for i = 0 to len(value) - 1
      ch = value[i]
      if ch == "\\" then result.appendString("\\\\")
      else if ch == "\"" then result.appendString("\\\"")
      else if ch == "\n" then result.appendString("\\n")
      else if ch == "\r" then result.appendString("\\r")
      else if ch == "\t" then result.appendString("\\t")
      else result.appendString(ch)
      end if
    end for
  end if
  return result.toString()
end function

/// Render a string array as a JSON value.
/// @internal
function _jsonStringArray(values)
  writer = builders.StringBuilder.withCapacity(16 + len(values) * 16)
  writer.appendString("[")
  if len(values) > 0 then
    for i = 0 to len(values) - 1
      if i > 0 then writer.appendString(",") end if
      writer.appendString("\"" + _jsonEscape(values[i]) + "\"")
    end for
  end if
  writer.appendString("]")
  return writer.toString()
end function

/// Escape a string for XML element and attribute content.
/// @internal
function _xmlEscape(value)
  result = builders.StringBuilder.withCapacity(len(value) + 16)
  if len(value) > 0 then
    for i = 0 to len(value) - 1
      ch = value[i]
      if ch == "&" then result.appendString("&amp;")
      else if ch == "<" then result.appendString("&lt;")
      else if ch == ">" then result.appendString("&gt;")
      else if ch == "\"" then result.appendString("&quot;")
      else result.appendString(ch)
      end if
    end for
  end if
  return result.toString()
end function

/// Render detailed JSON suitable for archival and custom automation.
/// @param summary Completed RunSummary.
function toJson(summary)
  writer = builders.StringBuilder.withCapacity(1024 + len(summary.results) * 160)
  writer.appendString("{\"total\":" + summary.total() + ",\"passed\":" + summary.passed + ",\"failed\":" + summary.failed + ",\"skipped\":" + summary.skipped + ",\"durationMs\":" + summary.duration_ms + ",\"results\":[")
  if len(summary.results) > 0 then
    for i = 0 to len(summary.results) - 1
      if i > 0 then writer.appendString(",") end if
      item = summary.results[i]
      writer.appendString("{\"suite\":\"" + _jsonEscape(item.suite) + "\",\"name\":\"" + _jsonEscape(item.name) + "\",\"status\":\"" + item.status + "\",\"durationMs\":" + item.duration_ms + ",\"message\":\"" + _jsonEscape(item.message) + "\",\"source\":\"" + _jsonEscape(item.source) + "\",\"line\":" + item.line + ",\"categories\":" + _jsonStringArray(item.categories) + ",\"covers\":" + _jsonStringArray(item.covers) + "}")
    end for
  end if
  writer.appendString("]}\n")
  return writer.toString()
end function

/// Render a JUnit-compatible XML test suite.
/// @param summary Completed RunSummary.
function toJUnit(summary)
  writer = builders.StringBuilder.withCapacity(1024 + len(summary.results) * 192)
  writer.appendString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
  writer.appendString("<testsuite name=\"MiniLang\" tests=\"" + summary.total() + "\" failures=\"" + summary.failed + "\" skipped=\"" + summary.skipped + "\" time=\"" + (summary.duration_ms / 1000.0) + "\">\n")
  if len(summary.results) > 0 then
    for i = 0 to len(summary.results) - 1
      item = summary.results[i]
      writer.appendString("  <testcase classname=\"" + _xmlEscape(item.suite) + "\" name=\"" + _xmlEscape(item.name) + "\" time=\"" + (item.duration_ms / 1000.0) + "\">")
      if len(item.categories) > 0 or len(item.covers) > 0 then
        writer.appendString("<properties>")
        if len(item.categories) > 0 then
          for ci = 0 to len(item.categories) - 1
            writer.appendString("<property name=\"category\" value=\"" + _xmlEscape(item.categories[ci]) + "\"/>")
          end for
        end if
        if len(item.covers) > 0 then
          for vi = 0 to len(item.covers) - 1
            writer.appendString("<property name=\"covers\" value=\"" + _xmlEscape(item.covers[vi]) + "\"/>")
          end for
        end if
        writer.appendString("</properties>")
      end if
      if item.status == STATUS_FAILED then writer.appendString("<failure message=\"" + _xmlEscape(item.message) + "\"/>")
      else if item.status == STATUS_SKIPPED then writer.appendString("<skipped message=\"" + _xmlEscape(item.message) + "\"/>")
      end if
      writer.appendString("</testcase>\n")
    end for
  end if
  writer.appendString("</testsuite>\n")
  return writer.toString()
end function

/// Render a human-readable console report.
/// @param summary Completed RunSummary.
function printConsole(summary)
  if len(summary.results) > 0 then
    for i = 0 to len(summary.results) - 1
      item = summary.results[i]
      prefix = "[PASS]"
      if item.status == STATUS_FAILED then prefix = "[FAIL]"
      else if item.status == STATUS_SKIPPED then prefix = "[SKIP]"
      end if
      line = prefix + " " + item.suite + " :: " + item.name + " (" + item.duration_ms + " ms)"
      if item.message != "" then line = line + " - " + item.message end if
      if item.source != "" then line = line + " [" + item.source + ":" + item.line + "]" end if
      print line
    end for
  end if
  print "Tests: " + summary.total() + ", passed: " + summary.passed + ", failed: " + summary.failed + ", skipped: " + summary.skipped + ", time: " + summary.duration_ms + " ms"
end function

/// Parse a non-negative decimal integer, returning void on invalid input.
/// @internal
function _parseInteger(value)
  if typeof(value) != "string" or value == "" then return end if
  raw = bytes(value)
  result = 0
  for i = 0 to len(raw) - 1
    code = raw[i]
    if code < 48 or code > 57 then return end if
    result = result * 10 + code - 48
  end for
  return result
end function

/// Parse portable runner switches.
/// @param args Command-line arguments passed to the test executable.
function parseOptions(args)
  options = RunOptions.defaults()
  i = 0
  while i < len(args)
    argument = args[i]
    if argument == "--fail-fast" then options.fail_fast = true
    else if argument == "--list" then options.list_only = true
    else if argument == "--quiet" then options.quiet = true
    else if argument == "--filter" or argument == "--category" or argument == "--exclude-category" or argument == "--repeat" or argument == "--seed" or argument == "--format" or argument == "--output" then
      if i + 1 >= len(args) then return error(CONFIGURATION_ERROR, "missing value after " + argument) end if
      value = args[i + 1]
      if argument == "--filter" then options.filter = value
      else if argument == "--category" then options.category = value
      else if argument == "--exclude-category" then options.excluded_category = value
      else if argument == "--format" then options.format = value
      else if argument == "--output" then options.output = value
      else
        number = _parseInteger(value)
        if number is void then return error(CONFIGURATION_ERROR, "invalid integer after " + argument) end if
        if argument == "--repeat" then options.repeat = number else options.seed = number end if
      end if
      i = i + 1
    else
      return error(CONFIGURATION_ERROR, "unknown test option: " + argument)
    end if
    i = i + 1
  end while
  if options.repeat < 1 then return error(CONFIGURATION_ERROR, "--repeat must be at least one") end if
  if options.format != "console" and options.format != "json" and options.format != "junit" then return error(CONFIGURATION_ERROR, "--format must be console, json, or junit") end if
  if options.format != "console" and options.output == "" then return error(CONFIGURATION_ERROR, "--output is required for JSON and JUnit reports") end if
  return options
end function

/// Execute suites, render the selected report, and return a process exit code.
/// @param suites Array of Suite values.
/// @param args Runner command-line switches.
function run(suites, args = [])
  options = parseOptions(args)
  if typeof(options) == "error" then
    print "std.test: " + options.message
    return 2
  end if
  summary = execute(suites, options)
  if not options.quiet then printConsole(summary) end if
  if options.format == "json" then
    written = fs.writeAllText(options.output, toJson(summary))
    if typeof(written) == "error" then print "std.test: " + written.message; return 2 end if
  else if options.format == "junit" then
    written2 = fs.writeAllText(options.output, toJUnit(summary))
    if typeof(written2) == "error" then print "std.test: " + written2.message; return 2 end if
  end if
  return summary.exitCode()
end function
