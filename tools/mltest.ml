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

//! Discovers MiniLang test declaration tags and generates an ordinary,
//! explicitly registered std.test entrypoint without compiler extensions.

import std.fs as fs
import std.path as path
import std.process as process
import std.sort as sorting
import std.string as strings
import std.string_builder as builders

struct Tag
  name
  value
  line
end struct

struct DiscoveredTest
  name
  target
  source
  line
  skipped
  skip_reason
  timeout_ms
  categories
  covers
end struct

struct DiscoveredSuite
  name
  source
  import_path
  tests
  before_all
  after_all
  before_each
  after_each
end struct

#if TARGET_OS == "windows"
extern function _testGetFileAttributesW(value as wstr) from "kernel32.dll" symbol "GetFileAttributesW" returns u32
#else
extern function _testLstat(value as cstr, info as bytes) from "libc.so.6" symbol "lstat" returns i32
#endif

function _u32le(value, offset)
  return value[offset] + value[offset + 1] * 256 + value[offset + 2] * 65536 + value[offset + 3] * 16777216
end function

// Recursive discovery deliberately avoids directory links so a project cannot
// make the test scan loop through a junction or symbolic-link cycle.
function _isDirectoryLink(value)
#if TARGET_OS == "windows"
  attributes = _testGetFileAttributesW(value)
  if attributes == 0xFFFFFFFF then return false end if
  return (attributes & 0x10) != 0 and (attributes & 0x400) != 0
#else
  info = bytes(144, 0)
  if _testLstat(value, info) != 0 then return false end if
  mode = _u32le(info, 24)
  return (mode & 61440) == 40960 and fs.isDir(value)
#endif
end function

function _grow(items, required)
  new_length = len(items)
  if new_length < 16 then new_length = 16 end if
  while new_length < required new_length = new_length * 2 end while
  result = array(new_length)
  if len(items) > 0 then copyArray(result, 0, items, 0, len(items)) end if
  return result
end function

function _take(items, count)
  if count <= 0 then return [] end if
  result = array(count)
  copyArray(result, 0, items, 0, count)
  return result
end function

function _collectSources(root)
  files = array(16)
  file_count = 0
  directories = array(16)
  directories[0] = root
  directory_count = 1

  while directory_count > 0
    directory_count = directory_count - 1
    directory = directories[directory_count]
    entries = fs.listDir(directory)
    if typeof(entries) == "error" then return error(entries.code, "cannot scan " + directory + ": " + entries.message) end if
    if len(entries) > 0 then
      for i = 0 to len(entries) - 1
        full = path.join(directory, entries[i])
        if fs.isDir(full) then
          if not _isDirectoryLink(full) then
            if directory_count == len(directories) then directories = _grow(directories, directory_count + 1) end if
            directories[directory_count] = full
            directory_count = directory_count + 1
          end if
        else if strings.toLowerAscii(path.extension(entries[i])) == ".ml" then
          if file_count == len(files) then files = _grow(files, file_count + 1) end if
          files[file_count] = full
          file_count = file_count + 1
        end if
      end for
    end if
  end while
  result = _take(files, file_count)
  sorting.sort(result)
  return result
end function

function _replaceSlashes(value)
  result = builders.StringBuilder.withCapacity(len(value))
  if len(value) > 0 then
    for i = 0 to len(value) - 1
      if value[i] == "\\" then result.appendString("/") else result.appendString(value[i]) end if
    end for
  end if
  return result.toString()
end function

function _absolute(value)
  if path.isAbsolute(value) then return _replaceSlashes(value) end if
  return _replaceSlashes(path.join(process.currentDirectory(), value))
end function

function _relative(root, value)
  normalized_root = _replaceSlashes(root)
  normalized_value = _replaceSlashes(value)
  prefix = normalized_root
  if not strings.endsWith(prefix, "/") then prefix = prefix + "/" end if
  if strings.startsWith(strings.toLowerAscii(normalized_value), strings.toLowerAscii(prefix)) then
    return strings.substr(normalized_value, len(prefix), len(normalized_value) - len(prefix))
  end if
  return normalized_value
end function

function _firstWord(value)
  text = strings.trim(value)
  if text == "" then return ["", ""] end if
  raw = bytes(text)
  i = 0
  while i < len(raw) and raw[i] != 32 and raw[i] != 9 i = i + 1 end while
  if i == len(raw) then return [text, ""] end if
  return [strings.substr(text, 0, i), strings.trim(strings.substr(text, i, len(text) - i))]
end function

function _appendDocLine(tags, value, line_number)
  text = strings.trim(value)
  if text == "" or not strings.startsWith(text, "@") then return tags end if
  parts = _firstWord(strings.substr(text, 1, len(text) - 1))
  if parts[0] == "" then return tags end if
  return tags + [Tag(strings.toLowerAscii(parts[0]), parts[1], line_number)]
end function

function _tagValue(tags, name)
  if len(tags) == 0 then return "" end if
  for i = 0 to len(tags) - 1
    if tags[i].name == name then return tags[i].value end if
  end for
  return ""
end function

function _hasTag(tags, name)
  if len(tags) == 0 then return false end if
  for i = 0 to len(tags) - 1
    if tags[i].name == name then return true end if
  end for
  return false
end function

function _tagValues(tags, name)
  result = []
  if len(tags) == 0 then return result end if
  for i = 0 to len(tags) - 1
    if tags[i].name == name and tags[i].value != "" then result = result + [tags[i].value] end if
  end for
  return result
end function

function _parseInteger(value)
  text = strings.trim(value)
  if text == "" then return end if
  raw = bytes(text)
  result = 0
  for i = 0 to len(raw) - 1
    if raw[i] < 48 or raw[i] > 57 then return end if
    result = result * 10 + raw[i] - 48
  end for
  return result
end function

function _functionParts(line)
  trimmed = strings.trim(line)
  function_pos = strings.indexOf(trimmed, "function ", 0)
  if function_pos < 0 then return end if
  before = strings.trim(strings.substr(trimmed, 0, function_pos))
  allowed = before == "" or before == "static" or before == "inline" or before == "synchronized" or before == "async" or before == "iterator" or before == "lazy iterator" or before == "static inline" or before == "static synchronized"
  if not allowed then return end if
  rest_start = function_pos + len("function ")
  open_pos = strings.indexOf(trimmed, "(", rest_start)
  close_pos = strings.indexOf(trimmed, ")", open_pos + 1)
  if open_pos < 0 or close_pos < 0 then return error(1, "tagged declarations must keep their function name and parameters on one line") end if
  name = strings.trim(strings.substr(trimmed, rest_start, open_pos - rest_start))
  parameters = strings.trim(strings.substr(trimmed, open_pos + 1, close_pos - open_pos - 1))
  if name == "" then return end if
  return [name, parameters, strings.contains(" " + before + " ", " static "), strings.contains(" " + before + " ", " async ") or strings.contains(" " + before + " ", " iterator ")]
end function

function _qualifiedTarget(namespace_parts, struct_name, function_name)
  pieces = []
  if len(namespace_parts) > 0 then pieces = namespace_parts + [] end if
  if struct_name != "" then pieces = pieces + [struct_name] end if
  pieces = pieces + [function_name]
  return strings.join(pieces, ".")
end function

function _role(tags)
  roles = []
  names = ["testmethod", "beforeall", "afterall", "beforeeach", "aftereach"]
  if len(tags) > 0 then
    for ti = 0 to len(tags) - 1
      for i = 0 to len(names) - 1
        if tags[ti].name == names[i] then roles = roles + [names[i]] end if
      end for
    end for
  end if
  if len(roles) == 0 then return "" end if
  if len(roles) > 1 then return error(1, "a declaration may have only one test lifecycle tag") end if
  return roles[0]
end function

function _assignHook(suite, role, target)
  if role == "beforeall" then
    if suite.before_all != "" then return error(1, "duplicate @beforeall in " + suite.source) end if
    suite.before_all = target
  else if role == "afterall" then
    if suite.after_all != "" then return error(1, "duplicate @afterall in " + suite.source) end if
    suite.after_all = target
  else if role == "beforeeach" then
    if suite.before_each != "" then return error(1, "duplicate @beforeeach in " + suite.source) end if
    suite.before_each = target
  else if role == "aftereach" then
    if suite.after_each != "" then return error(1, "duplicate @aftereach in " + suite.source) end if
    suite.after_each = target
  end if
  return true
end function

function _scanFile(root, file_name)
  lines = fs.readAllLines(file_name)
  if typeof(lines) == "error" then return lines end if
  source = _relative(root, file_name)
  suite = DiscoveredSuite("", source, _absolute(file_name), [], "", "", "", "")
  package_name = ""
  namespace_parts = []
  struct_name = ""
  function_depth = 0
  pending_tags = []
  in_block_doc = false

  if len(lines) > 0 then
    for index = 0 to len(lines) - 1
      trimmed = strings.trim(lines[index])
      line_number = index + 1

      if function_depth > 0 then
        if strings.startsWith(trimmed, "end function") then function_depth = function_depth - 1
        else if strings.startsWith(trimmed, "function ") or strings.startsWith(trimmed, "function(") or strings.contains(trimmed, " function(") then function_depth = function_depth + 1
        end if
        continue
      end if

      if in_block_doc then
        closing = strings.indexOf(trimmed, "*/", 0)
        content = trimmed
        if closing >= 0 then
          content = strings.trim(strings.substr(content, 0, closing))
          in_block_doc = false
        end if
        if strings.startsWith(content, "*") then content = strings.trim(strings.substr(content, 1, len(content) - 1)) end if
        pending_tags = _appendDocLine(pending_tags, content, line_number)
        continue
      end if

      if strings.startsWith(trimmed, "///") then
        pending_tags = _appendDocLine(pending_tags, strings.substr(trimmed, 3, len(trimmed) - 3), line_number)
        continue
      end if
      if strings.startsWith(trimmed, "/**") then
        content2 = strings.substr(trimmed, 3, len(trimmed) - 3)
        closing2 = strings.indexOf(content2, "*/", 0)
        if closing2 >= 0 then content2 = strings.substr(content2, 0, closing2)
        else in_block_doc = true
        end if
        pending_tags = _appendDocLine(pending_tags, content2, line_number)
        continue
      end if
      if trimmed == "" then continue end if

      if strings.startsWith(trimmed, "package ") then
        package_name = strings.trim(strings.substr(trimmed, len("package "), len(trimmed) - len("package ")))
        if suite.name == "" then suite.name = package_name end if
        pending_tags = []
        continue
      end if
      if strings.startsWith(trimmed, "namespace ") then
        namespace_name = strings.trim(strings.substr(trimmed, len("namespace "), len(trimmed) - len("namespace ")))
        namespace_parts = namespace_parts + [namespace_name]
        pending_tags = []
        continue
      end if
      if strings.startsWith(trimmed, "end namespace") then
        if len(namespace_parts) > 0 then namespace_parts = slice(namespace_parts, 0, len(namespace_parts) - 1) end if
        pending_tags = []
        continue
      end if
      if strings.startsWith(trimmed, "struct ") then
        declaration = _firstWord(strings.substr(trimmed, len("struct "), len(trimmed) - len("struct ")))
        struct_name = declaration[0]
        pending_tags = []
        continue
      end if
      if strings.startsWith(trimmed, "end struct") then
        struct_name = ""
        pending_tags = []
        continue
      end if

      parts = _functionParts(trimmed)
      if typeof(parts) == "error" then return error(1, source + ":" + line_number + ": " + parts.message) end if
      if typeof(parts) == "array" then
        role = _role(pending_tags)
        if typeof(role) == "error" then return error(1, source + ":" + line_number + ": " + role.message) end if
        has_test_metadata = _hasTag(pending_tags, "skip") or _hasTag(pending_tags, "timeout") or _hasTag(pending_tags, "category") or _hasTag(pending_tags, "covers")
        if has_test_metadata and role != "testmethod" then return error(1, source + ":" + line_number + ": @skip, @timeout, @category, and @covers require @testmethod") end if
        if role != "" then
          if package_name == "" then return error(1, source + ":" + line_number + ": discovered test files must declare a package") end if
          if parts[1] != "" then return error(1, source + ":" + line_number + ": test and fixture functions must have zero parameters") end if
          if parts[3] then return error(1, source + ":" + line_number + ": async and iterator functions cannot be test callbacks") end if
          if struct_name != "" and not parts[2] then return error(1, source + ":" + line_number + ": test methods inside structs must be static") end if
          target = _qualifiedTarget(namespace_parts, struct_name, parts[0])
          if role == "testmethod" then
            if _hasTag(pending_tags, "category") and len(_tagValues(pending_tags, "category")) == 0 then return error(1, source + ":" + line_number + ": @category requires a value") end if
            if _hasTag(pending_tags, "covers") and len(_tagValues(pending_tags, "covers")) == 0 then return error(1, source + ":" + line_number + ": @covers requires a value") end if
            display_name = _tagValue(pending_tags, "testmethod")
            if display_name == "" then display_name = target end if
            timeout = 0
            timeout_text = _tagValue(pending_tags, "timeout")
            if _hasTag(pending_tags, "timeout") then
              timeout = _parseInteger(timeout_text)
              if timeout is void or timeout <= 0 then return error(1, source + ":" + line_number + ": @timeout expects positive milliseconds") end if
            end if
            suite.tests = suite.tests + [DiscoveredTest(display_name, target, source, line_number, _hasTag(pending_tags, "skip"), _tagValue(pending_tags, "skip"), timeout, _tagValues(pending_tags, "category"), _tagValues(pending_tags, "covers"))]
          else
            assigned = _assignHook(suite, role, target)
            if typeof(assigned) == "error" then return assigned end if
          end if
        end if
        pending_tags = []
        function_depth = 1
        continue
      end if

      pending_tags = []
    end for
  end if

  if len(suite.tests) == 0 and suite.before_all == "" and suite.after_all == "" and suite.before_each == "" and suite.after_each == "" then return end if
  if suite.name == "" then suite.name = source end if
  return suite
end function

function discover(root)
  absolute_root = _absolute(root)
  if not fs.isDir(absolute_root) then return error(1, "test root is not a directory: " + root) end if
  files = _collectSources(absolute_root)
  if typeof(files) == "error" then return files end if
  suites = []
  if len(files) > 0 then
    for i = 0 to len(files) - 1
      suite = _scanFile(absolute_root, files[i])
      if typeof(suite) == "error" then return suite end if
      if typeof(suite) == "struct" then suites = suites + [suite] end if
    end for
  end if
  return suites
end function

function _literal(value)
  writer = builders.StringBuilder.withCapacity(len(value) + 8)
  writer.appendString("\"")
  if len(value) > 0 then
    for i = 0 to len(value) - 1
      ch = value[i]
      if ch == "\\" then writer.appendString("\\\\")
      else if ch == "\"" then writer.appendString("\\\"")
      else if ch == "\n" then writer.appendString("\\n")
      else if ch == "\r" then writer.appendString("\\r")
      else if ch == "\t" then writer.appendString("\\t")
      else writer.appendString(ch)
      end if
    end for
  end if
  writer.appendString("\"")
  return writer.toString()
end function

function _stringArray(values)
  result = builders.StringBuilder.withCapacity(32)
  result.appendString("[")
  if len(values) > 0 then
    for i = 0 to len(values) - 1
      if i > 0 then result.appendString(", ") end if
      result.appendString(_literal(values[i]))
    end for
  end if
  result.appendString("]")
  return result.toString()
end function

function generate(suites)
  writer = builders.StringBuilder.withCapacity(4096)
  writer.appendString("/* Generated by mltest. Do not edit. */\n\n")
  writer.appendString("import std.test as test\n")
  if len(suites) > 0 then
    for i = 0 to len(suites) - 1
      writer.appendString("import " + _literal(suites[i].import_path) + " as mltest_module_" + i + "\n")
    end for
  end if
  writer.appendString("\nfunction main(args)\n")
  writer.appendString("  suites = []\n")
  if len(suites) > 0 then
    for si = 0 to len(suites) - 1
      suite = suites[si]
      alias = "mltest_module_" + si
      variable = "mltest_suite_" + si
      writer.appendString("  " + variable + " = test.Suite.new(" + _literal(suite.name) + ")\n")
      if suite.before_all != "" then writer.appendString("  " + variable + ".setBeforeAll(" + alias + "." + suite.before_all + ")\n") end if
      if suite.after_all != "" then writer.appendString("  " + variable + ".setAfterAll(" + alias + "." + suite.after_all + ")\n") end if
      if suite.before_each != "" then writer.appendString("  " + variable + ".setBeforeEach(" + alias + "." + suite.before_each + ")\n") end if
      if suite.after_each != "" then writer.appendString("  " + variable + ".setAfterEach(" + alias + "." + suite.after_each + ")\n") end if
      if len(suite.tests) > 0 then
        for ti = 0 to len(suite.tests) - 1
          item = suite.tests[ti]
          case_variable = "mltest_case_" + si + "_" + ti
          writer.appendString("  " + case_variable + " = test.TestCase.new(" + _literal(item.name) + ", " + alias + "." + item.target + ")\n")
          writer.appendString("  " + case_variable + ".source = " + _literal(item.source) + "\n")
          writer.appendString("  " + case_variable + ".line = " + item.line + "\n")
          if item.skipped then writer.appendString("  " + case_variable + ".skipped = true\n") end if
          if item.skip_reason != "" then writer.appendString("  " + case_variable + ".skip_reason = " + _literal(item.skip_reason) + "\n") end if
          if item.timeout_ms > 0 then writer.appendString("  " + case_variable + ".timeout_ms = " + item.timeout_ms + "\n") end if
          if len(item.categories) > 0 then writer.appendString("  " + case_variable + ".categories = " + _stringArray(item.categories) + "\n") end if
          if len(item.covers) > 0 then writer.appendString("  " + case_variable + ".covers = " + _stringArray(item.covers) + "\n") end if
          writer.appendString("  " + variable + ".addCase(" + case_variable + ")\n")
        end for
      end if
      writer.appendString("  suites = suites + [" + variable + "]\n")
    end for
  end if
  writer.appendString("  return test.run(suites, args)\n")
  writer.appendString("end function\n")
  return writer.toString()
end function

function _counts(suites)
  count = 0
  if len(suites) > 0 then
    for i = 0 to len(suites) - 1 count = count + len(suites[i].tests) end for
  end if
  return count
end function

function _usage()
  print "mltest - MiniLang std.test discovery generator"
  print "Usage:"
  print "  mltest generate <test-root> <runner.ml>"
  print "  mltest list <test-root>"
  print ""
  print "The generated runner is compiled normally and accepts std.test options:"
  print "  --filter TEXT --category NAME --exclude-category NAME"
  print "  --repeat N --seed N --fail-fast --list --quiet"
  print "  --format console|json|junit [--output PATH]"
end function

function main(args)
  if len(args) > 0 and (args[0] == "--help" or args[0] == "-h") then _usage(); return 0 end if
  if len(args) < 2 then _usage(); return 2 end if
  command = args[0]
  suites = discover(args[1])
  if typeof(suites) == "error" then print "mltest: " + suites.message; return 1 end if

  if command == "list" then
    if len(suites) > 0 then
      for si = 0 to len(suites) - 1
        if len(suites[si].tests) > 0 then
          for ti = 0 to len(suites[si].tests) - 1
            print suites[si].name + " :: " + suites[si].tests[ti].name
          end for
        end if
      end for
    end if
    print "Discovered " + _counts(suites) + " test(s) in " + len(suites) + " suite(s)."
    return 0
  end if

  if command == "generate" then
    if len(args) != 3 then _usage(); return 2 end if
    output = fs.writeAllText(args[2], generate(suites))
    if typeof(output) == "error" then print "mltest: " + output.message; return 1 end if
    print "Generated " + _counts(suites) + " test(s) in " + len(suites) + " suite(s): " + args[2]
    return 0
  end if

  _usage()
  return 2
end function
