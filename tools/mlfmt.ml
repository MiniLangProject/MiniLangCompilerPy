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

import std.fs as fs
import std.path as path
import std.time as time

// Standalone formatter for MiniLang source files. It tokenizes layout-sensitive
// constructs conservatively and writes normalized whitespace without changing
// statement order or expression spelling.

// ------------------------------------------------------------
// ByteBuilder
// ------------------------------------------------------------
// Capacity-backed byte sink used to avoid quadratic output concatenation.
struct ByteBuilder
  buf
  n
end struct

// Create an empty builder with a practical minimum capacity.
function bb_new(cap)
  if cap < 16 then cap = 16 end if
  return ByteBuilder(bytes(cap), 0)
end function

// Grow geometrically until more additional bytes fit.
function bb_ensure(bb, more)
  need = bb.n + more
  cap = len(bb.buf)
  if need <= cap then
    return bb
  end if

  newcap = cap
  while newcap < need
    newcap = newcap * 2
  end while

  nb = bytes(newcap)
  for i = 0 to bb.n - 1
    nb[i] = bb.buf[i]
  end for
  bb.buf = nb
  return bb
end function

function bb_pushByte(bb, v)
  bb = bb_ensure(bb, 1)
  bb.buf[bb.n] = v
  bb.n = bb.n + 1
  return bb
end function

function bb_pushBytes(bb, b)
  n = len(b)
  if n <= 0 then return bb end if
  bb = bb_ensure(bb, n)
  for i = 0 to n - 1
    bb.buf[bb.n + i] = b[i]
  end for
  bb.n = bb.n + n
  return bb
end function

function bb_trimRightSpaces(bb)
  while bb.n > 0 and bb.buf[bb.n - 1] == 32
    bb.n = bb.n - 1
  end while
  return bb
end function

function bb_toBytes(bb)
  return slice(bb.buf, 0, bb.n)
end function

// clamp consecutive blank lines by limiting consecutive \n
function _clampNewlines(b, maxBlankLines)
  if maxBlankLines < 0 then
    return b
  end if

  maxRun = maxBlankLines + 1
  if maxRun < 1 then
    maxRun = 1
  end if

  bb = bb_new(len(b) + 8)
  run = 0
  for i = 0 to len(b) - 1
    ch = b[i]
    if ch == 10 then
      run = run + 1
      if run <= maxRun then
        bb = bb_pushByte(bb, 10)
      end if
    else
      run = 0
      bb = bb_pushByte(bb, ch)
    end if
  end for

  return bb_toBytes(bb)
end function

// ------------------------------------------------------------
// small helper classes (Bytes/Char-classes)
// ------------------------------------------------------------
function _isWS(ch)
  return ch == 32 or ch == 9 or ch == 13
end function

function _isDigit(ch)
  return ch >= 48 and ch <= 57
end function

function _isAlpha(ch)
  return (ch >= 65 and ch <= 90) or(ch >= 97 and ch <= 122)
end function

function _isIdentStart(ch)
  return _isAlpha(ch) or ch == 95
end function

function _isIdentPart(ch)
  return _isIdentStart(ch) or _isDigit(ch)
end function

function _trimLeftBytes(b)
  i = 0
  while i < len(b) and _isWS(b[i])
    i = i + 1
  end while
  return slice(b, i, len(b) - i)
end function

function _trimRightBytes(b)
  n = len(b)
  i = n - 1
  while i >= 0 and _isWS(b[i])
    i = i - 1
  end while
  if i < 0 then
    return bytes(0)
  end if
  return slice(b, 0, i + 1)
end function

function _isBlankLine(b)
  if len(b) <= 0 then
    return true
  end if
  for i = 0 to len(b) - 1
    if not _isWS(b[i]) then
      return false
    end if
  end for
  return true
end function

function _startsWith(s, pref)
  bs = bytes(s)
  bp = bytes(pref)
  if len(bs) < len(bp) then return false end if
  for i = 0 to len(bp) - 1
    if bs[i] != bp[i] then return false end if
  end for
  return true
end function

function _parseIntOrDefault(s, defv)
  b = bytes(s)
  if len(b) <= 0 then return defv end if
  i = 0
  sign = 1
  if b[0] == 45 then
    sign = -1
    i = 1
  end if
  if i >= len(b) then return defv end if

  v = 0
  while i < len(b)
    c = b[i]
    if not _isDigit(c) then
      return defv
    end if
    v = v * 10 +(c - 48)
    i = i + 1
  end while
  return v * sign
end function

// ------------------------------------------------------------
// comment finder (//) outside of Strings
// ------------------------------------------------------------
function _findLineCommentIdx(b)
  i = 0
  inStr = false
  while i < len(b)
    ch = b[i]
    if inStr then
      if ch == 92 then
        i = i + 2
        continue
      end if
      if ch == 34 then
        inStr = false
      end if
      i = i + 1
      continue
    end if

    if ch == 34 then
      inStr = true
      i = i + 1
      continue
    end if

    if ch == 47 and(i + 1) < len(b) and b[i + 1] == 47 then
      return i
    end if

    i = i + 1
  end while
  return -1
end function

// normalize "//   foo" -> "// foo" (only if there is whitespace after //)
// keeps "///" etc unchanged
function _normalizeLineComment(c)
  if len(c) < 3 then
    return c
  end if
  // must start with //
  if c[0] != 47 or c[1] != 47 then
    return c
  end if
  // keep doc-style /// unchanged
  if c[2] == 47 then
    return c
  end if
  // only normalize if there is whitespace right after //
  if not _isWS(c[2]) then
    return c
  end if

  i = 2
  while i < len(c) and _isWS(c[i])
    i = i + 1
  end while

  // if only whitespace after //, keep just "//"
  if i >= len(c) then
    return slice(c, 0, 2)
  end if

  // build: "// " + rest
  return bytes("// " + decode(slice(c, i, len(c) - i)))
end function

// Find a two-byte marker at or after start. This is used only while already
// inside a block comment, where string and line-comment rules do not apply.
function _findSubseqFrom(b, start, a, c)
  if len(b) < 2 or start >= len(b) - 1 then
    return -1
  end if
  i = start
  if i < 0 then i = 0 end if
  while i < len(b) - 1
    if b[i] == a and b[i + 1] == c then
      return i
    end if
    i = i + 1
  end while
  return -1
end function

// Locate /* in executable text. Markers inside strings or after // are data,
// not comments; treating them as comments used to corrupt following indents.
function _findBlockCommentOpenIdx(b)
  if len(b) < 2 then
    return -1
  end if

  i = 0
  inStr = false
  while i < len(b) - 1
    ch = b[i]
    if inStr then
      if ch == 92 then
        i = i + 2
        continue
      end if
      if ch == 34 then inStr = false end if
      i = i + 1
      continue
    end if

    if ch == 34 then
      inStr = true
      i = i + 1
      continue
    end if
    if ch == 47 and b[i + 1] == 47 then return -1 end if
    if ch == 47 and b[i + 1] == 42 then return i end if
    i = i + 1
  end while
  return -1
end function

// ------------------------------------------------------------
// "end <kind>" in same Line-Header? (for inline blocks)
// ------------------------------------------------------------
function _containsEndOf(code, kind)
  i = 0
  inStr = false
  prevEnd = false
  while i < len(code)
    ch = code[i]
    if inStr then
      if ch == 92 then
        i = i + 2
        continue
      end if
      if ch == 34 then
        inStr = false
      end if
      i = i + 1
      continue
    end if

    if ch == 34 then
      inStr = true
      i = i + 1
      continue
    end if

    if _isIdentStart(ch) then
      st = i
      i = i + 1
      while i < len(code) and _isIdentPart(code[i])
        i = i + 1
      end while
      w = decode(slice(code, st, i - st))
      if prevEnd and w == kind then
        return true
      end if
      prevEnd =(w == "end")
      continue
    end if

    i = i + 1
  end while
  return false
end function

// ------------------------------------------------------------
// First two words at line beginning (for Indent-Logic)
// ------------------------------------------------------------
struct Words
  w0
  w1
end struct

function _firstTwoWords(code)
  t = _trimLeftBytes(code)
  i = 0

  if i >= len(t) or not _isIdentStart(t[i]) then
    return Words("", "")
  end if

  s0 = i
  i = i + 1
  while i < len(t) and _isIdentPart(t[i])
    i = i + 1
  end while
  w0 = decode(slice(t, s0, i - s0))

  while i < len(t) and _isWS(t[i])
    i = i + 1
  end while

  if i >= len(t) or not _isIdentStart(t[i]) then
    return Words(w0, "")
  end if

  s1 = i
  i = i + 1
  while i < len(t) and _isIdentPart(t[i])
    i = i + 1
  end while
  w1 = decode(slice(t, s1, i - s1))

  return Words(w0, w1)
end function

// Return true when the next non-empty, non-comment source line is `end loop`.
// The parser uses the same look-ahead to distinguish a do-while footer from a
// normal nested while statement.
function _nextLineIsEndLoop(source, start)
  pos = start
  inComment = false
  while pos < len(source)
    lineEnd = pos
    while lineEnd < len(source) and source[lineEnd] != 10
      lineEnd = lineEnd + 1
    end while
    line = _trimLeftBytes(_trimRightBytes(slice(source, pos, lineEnd - pos)))

    if inComment then
      closeAt = _findSubseqFrom(line, 0, 42, 47)
      if closeAt >= 0 then inComment = false end if
    else
      if len(line) > 0 then
        if len(line) >= 2 and line[0] == 47 and line[1] == 47 then
          // Skip a line comment.
        else
          if len(line) >= 2 and line[0] == 47 and line[1] == 42 then
            closeAt = _findSubseqFrom(line, 2, 42, 47)
            if closeAt < 0 then inComment = true end if
          else
            words = _firstTwoWords(line)
            return words.w0 == "end" and words.w1 == "loop"
          end if
        end if
      end if
    end if

    if lineEnd >= len(source) then return false end if
    pos = lineEnd + 1
  end while
  return false
end function

// ------------------------------------------------------------
// Switch-Base-Indent Stack (as "123\n456\n" in bytes)
// ------------------------------------------------------------
function sb_isEmpty(sb)
  return len(sb) == 0
end function

function sb_push(sb, v)
  return sb + bytes("" + v + "\n")
end function

function sb_top(sb)
  if len(sb) == 0 then return 0 end if
  endi = len(sb) - 1
  i = endi - 1
  while i >= 0 and sb[i] != 10
    i = i - 1
  end while
  start = i + 1
  num = 0
  j = start
  while j < endi
    c = sb[j]
    if c < 48 or c > 57 then
      return 0
    end if
    num = num * 10 +(c - 48)
    j = j + 1
  end while
  return num
end function

function sb_pop(sb)
  if len(sb) == 0 then return sb end if
  endi = len(sb) - 1
  i = endi - 1
  while i >= 0 and sb[i] != 10
    i = i - 1
  end while
  if i < 0 then
    return bytes(0)
  end if
  return slice(sb, 0, i + 1)
end function

// ------------------------------------------------------------
// Code-Formatter for ONE Code part (without // comment)
// ------------------------------------------------------------
function _isControlKw(w)
  return w == "if" or w == "while" or w == "for" or w == "switch" or w == "match" or w == "return"
end function

function emit_formatted_code(bb, code)
  i = 0
  prevCat = 0 // 0 none, 1 id/kw, 2 num, 3 str, 4 op, 5 dot, 6 open, 7 close
  prevWord = ""
  pendingSpace = false

  code2 = _trimRightBytes(_trimLeftBytes(code))

  while i < len(code2)
    ch = code2[i]

    if _isWS(ch) then
      i = i + 1
      continue
    end if

    // string literal
    if ch == 34 then
      if pendingSpace then
        bb = bb_pushByte(bb, 32)
        pendingSpace = false
      else
        if prevCat == 1 or prevCat == 2 or prevCat == 3 or prevCat == 7 then
          bb = bb_pushByte(bb, 32)
        end if
      end if

      st = i
      i = i + 1
      while i < len(code2)
        c = code2[i]
        if c == 92 then
          i = i + 2
          continue
        end if
        i = i + 1
        if c == 34 then
          break
        end if
      end while

      tok = slice(code2, st, i - st)
      bb = bb_pushBytes(bb, tok)

      prevCat = 3
      prevWord = ""
      continue
    end if

    // ident/keyword
    if _isIdentStart(ch) then
      st = i
      i = i + 1
      while i < len(code2) and _isIdentPart(code2[i])
        i = i + 1
      end while
      tok = slice(code2, st, i - st)
      w = decode(tok)

      // and/or/not als Operator-Wörter behandeln
      if w == "and" or w == "or" or w == "not" then
        if prevCat != 0 and prevCat != 6 and prevCat != 5 then
          bb = bb_pushByte(bb, 32)
        end if
        bb = bb_pushBytes(bb, tok)
        pendingSpace = true
        prevCat = 4
        prevWord = w
        continue
      end if

      if pendingSpace then
        bb = bb_pushByte(bb, 32)
        pendingSpace = false
      else
        if prevCat == 1 or prevCat == 2 or prevCat == 3 or prevCat == 7 then
          bb = bb_pushByte(bb, 32)
        end if
      end if

      bb = bb_pushBytes(bb, tok)
      prevCat = 1
      prevWord = w
      continue
    end if

    // number. A leading '-' is handled by the operator path so subtraction
    // (`left-1`) cannot accidentally become a glued negative literal.
    if _isDigit(ch) then
      st = i
      i = i + 1
      while i < len(code2)
        c = code2[i]
        if _isDigit(c) or _isAlpha(c) or c == 46 or c == 120 or c == 88 or c == 98 or c == 66 then
          i = i + 1
        else
          break
        end if
      end while
      tok = slice(code2, st, i - st)

      if pendingSpace then
        bb = bb_pushByte(bb, 32)
        pendingSpace = false
      else
        if prevCat == 1 or prevCat == 2 or prevCat == 3 or prevCat == 7 then
          bb = bb_pushByte(bb, 32)
        end if
      end if

      bb = bb_pushBytes(bb, tok)
      prevCat = 2
      prevWord = ""
      continue
    end if

    // two-char operators
    if (i + 1) < len(code2) then
      ch2 = code2[i + 1]

      // Safe member access is member punctuation and must stay joined.
      if ch == 63 and ch2 == 46 then
        pendingSpace = false
        bb = bb_trimRightSpaces(bb)
        bb = bb_pushByte(bb, ch)
        bb = bb_pushByte(bb, ch2)
        prevCat = 5
        prevWord = ""
        i = i + 2
        continue
      end if

      // comparisons, shifts, lambdas and null coalescing
      if (ch == 61 and ch2 == 61) or(ch == 33 and ch2 == 61) or(ch == 60 and ch2 == 61) or(ch == 62 and ch2 == 61) or(ch == 60 and ch2 == 60) or(ch == 62 and ch2 == 62) or(ch == 61 and ch2 == 62) or(ch == 63 and ch2 == 63) then
        if prevCat != 0 and prevCat != 6 and prevCat != 5 then
          bb = bb_pushByte(bb, 32)
        end if
        bb = bb_pushByte(bb, ch)
        bb = bb_pushByte(bb, ch2)
        pendingSpace = true
        prevCat = 4
        prevWord = ""
        i = i + 2
        continue
      end if

      // assignment operators: += -= *= /= %= &= |= ^=
      if ch2 == 61 then
        if ch == 43 or ch == 45 or ch == 42 or ch == 47 or ch == 37 or ch == 38 or ch == 124 or ch == 94 then
          if prevCat != 0 and prevCat != 6 and prevCat != 5 then
            bb = bb_pushByte(bb, 32)
          end if
          bb = bb_pushByte(bb, ch)
          bb = bb_pushByte(bb, ch2)
          pendingSpace = true
          prevCat = 4
          prevWord = ""
          i = i + 2
          continue
        end if
      end if
    end if

    // Variadic marker. It belongs to the preceding parameter name.
    if (i + 2) < len(code2) and ch == 46 and code2[i + 1] == 46 and code2[i + 2] == 46 then
      pendingSpace = false
      bb = bb_trimRightSpaces(bb)
      bb = bb_pushByte(bb, 46)
      bb = bb_pushByte(bb, 46)
      bb = bb_pushByte(bb, 46)
      prevCat = 7
      prevWord = ""
      i = i + 3
      continue
    end if

    // single-char tokens
    if ch == 40 or ch == 91 then
      // '(' or '['
      if pendingSpace then
        if prevCat == 1 and _isControlKw(prevWord) then
          bb = bb_pushByte(bb, 32)
        end if
        pendingSpace = false
      else
        if prevCat == 1 and _isControlKw(prevWord) then
          bb = bb_pushByte(bb, 32)
        end if
      end if

      bb = bb_pushByte(bb, ch)
      prevCat = 6
      prevWord = ""
      i = i + 1
      continue
    end if

    if ch == 41 or ch == 93 then
      // ')' or ']'
      pendingSpace = false
      bb = bb_trimRightSpaces(bb)
      bb = bb_pushByte(bb, ch)
      prevCat = 7
      prevWord = ""
      i = i + 1
      continue
    end if

    if ch == 46 then
      // '.'
      pendingSpace = false
      bb = bb_trimRightSpaces(bb)
      bb = bb_pushByte(bb, 46)
      prevCat = 5
      prevWord = ""
      i = i + 1
      continue
    end if

    if ch == 44 then
      // ','
      pendingSpace = false
      bb = bb_trimRightSpaces(bb)
      bb = bb_pushByte(bb, 44)
      pendingSpace = true
      prevCat = 7
      prevWord = ""
      i = i + 1
      continue
    end if

    if ch == 63 then
      // Optional type marker, e.g. `Person?`. Keep it attached while making
      // the next binary operator insert its normal leading space.
      pendingSpace = false
      bb = bb_trimRightSpaces(bb)
      bb = bb_pushByte(bb, ch)
      prevCat = 7
      prevWord = ""
      i = i + 1
      continue
    end if

    if ch == 58 then
      // Type separator used by compile-time #option declarations. Directives
      // are emitted verbatim, but handling ':' keeps this tokenizer complete.
      pendingSpace = false
      bb = bb_trimRightSpaces(bb)
      bb = bb_pushByte(bb, ch)
      pendingSpace = true
      prevCat = 0
      prevWord = ""
      i = i + 1
      continue
    end if

    if ch == 59 then
      // ';'
      pendingSpace = false
      bb = bb_trimRightSpaces(bb)
      bb = bb_pushByte(bb, 59)
      pendingSpace = true
      prevCat = 0
      prevWord = ""
      i = i + 1
      continue
    end if

    // operators
    isOp =(ch == 43 or ch == 45 or ch == 42 or ch == 47 or ch == 37 or ch == 61 or ch == 38 or ch == 124 or ch == 94 or ch == 126 or ch == 60 or ch == 62)
    if isOp then
      unary = false
      if ch == 45 or ch == 126 then
        if prevCat == 0 or prevCat == 4 or prevCat == 6 then
          unary = true
        end if
      end if

      if unary then
        if pendingSpace then
          bb = bb_pushByte(bb, 32)
          pendingSpace = false
        else
          if prevCat == 1 or prevCat == 2 or prevCat == 3 or prevCat == 7 then
            bb = bb_pushByte(bb, 32)
          end if
        end if
        bb = bb_pushByte(bb, ch)
        prevCat = 4
        prevWord = ""
        i = i + 1
        continue
      end if

      if prevCat != 0 and prevCat != 6 and prevCat != 5 then
        bb = bb_pushByte(bb, 32)
      end if
      bb = bb_pushByte(bb, ch)
      pendingSpace = true
      prevCat = 4
      prevWord = ""
      i = i + 1
      continue
    end if

    // fallback
    if pendingSpace then
      bb = bb_pushByte(bb, 32)
      pendingSpace = false
    end if
    bb = bb_pushByte(bb, ch)
    prevCat = 0
    prevWord = ""
    i = i + 1
  end while

  bb = bb_trimRightSpaces(bb)
  return bb
end function

// ------------------------------------------------------------
// complete Source-Format: Indentation + CodeSpacing
// ------------------------------------------------------------
function _emitIndent(bb, indentLevel, indentSize)
  nsp = indentLevel * indentSize
  if nsp <= 0 then
    return bb
  end if
  for i = 0 to nsp - 1
    bb = bb_pushByte(bb, 32)
  end for
  return bb
end function

function format_source(src, indentSize, maxBlankLines)
  b = bytes(src)
  bb = bb_new(len(b) + 128)

  indent = 0
  branchBases = bytes(0)
  interfaceDepth = 0
  pendingLoopFooterEnds = 0
  inBlockComment = false
  blankRun = 0

  lineStart = 0
  while true
    // A trailing newline terminates the preceding line; it must not synthesize
    // an additional empty line on the next iteration.
    if lineStart >= len(b) then break end if
    // find next '\n'
    j = lineStart
    while j < len(b) and b[j] != 10
      j = j + 1
    end while

    line = slice(b, lineStart, j - lineStart)
    // trim trailing '\r'
    if len(line) > 0 and line[len(line) - 1] == 13 then
      line = slice(line, 0, len(line) - 1)
    end if

    lineR = _trimRightBytes(line)

    // blank line -> keep (clamped)
    if _isBlankLine(lineR) then
      blankRun = blankRun + 1
      if maxBlankLines < 0 then
        // unlimited
        bb = bb_pushByte(bb, 10)
      else
        if blankRun <= maxBlankLines then
          bb = bb_pushByte(bb, 10)
        end if
      end if

      if j >= len(b) then
        break
      end if
      lineStart = j + 1
      continue
    end if

    blankRun = 0
    // block comment handling (simple)
    if inBlockComment then
      bb = _emitIndent(bb, indent, indentSize)
      commentLine = _trimLeftBytes(lineR)
      if len(commentLine) > 0 and commentLine[0] == 42 then bb = bb_pushByte(bb, 32) end if
      bb = bb_pushBytes(bb, commentLine)
      bb = bb_pushByte(bb, 10)
      if _findSubseqFrom(lineR, 0, 42, 47) >= 0 then
        inBlockComment = false
      end if
      if j >= len(b) then break end if
      lineStart = j + 1
      continue
    end if

    blockOpen = _findBlockCommentOpenIdx(lineR)
    if blockOpen >= 0 then
      bb = _emitIndent(bb, indent, indentSize)
      bb = bb_pushBytes(bb, _trimLeftBytes(lineR))
      bb = bb_pushByte(bb, 10)
      if _findSubseqFrom(lineR, blockOpen + 2, 42, 47) < 0 then
        inBlockComment = true
      end if
      if j >= len(b) then break end if
      lineStart = j + 1
      continue
    end if

    // split // comment (outside strings)
    cidx = _findLineCommentIdx(lineR)
    code = lineR
    comment = bytes(0)
    if cidx >= 0 then
      code = slice(lineR, 0, cidx)
      comment = slice(lineR, cidx, len(lineR) - cidx)
    end if

    code = _trimRightBytes(code)
    codeTL = _trimLeftBytes(code)
    w = _firstTwoWords(codeTL)
    w0 = w.w0
    w1 = w.w1

    // Conditional-compilation directives have their own expression grammar.
    // Preserve their spelling exactly instead of feeding them through the
    // runtime-token formatter (which historically removed spaces after ':').
    isDirective = len(codeTL) > 0 and codeTL[0] == 35
    inlineLoopFooter = w0 == "while" and _containsEndOf(codeTL, "loop")
    isLoopFooter = inlineLoopFooter or (w0 == "while" and _nextLineIsEndLoop(b, j + 1))

    // pre-indent adjustments
    if w0 == "end" then
      if w1 == "loop" and pendingLoopFooterEnds > 0 then
        pendingLoopFooterEnds = pendingLoopFooterEnds - 1
      else
        if (w1 == "switch" or w1 == "match") and not sb_isEmpty(branchBases) then
        base = sb_top(branchBases)
        branchBases = sb_pop(branchBases)
        indent = base - 1
        if indent < 0 then indent = 0 end if
        else
          indent = indent - 1
          if indent < 0 then indent = 0 end if
        end if
      end if
    else
      if isLoopFooter then
        indent = indent - 1
        if indent < 0 then indent = 0 end if
        if not inlineLoopFooter then pendingLoopFooterEnds = pendingLoopFooterEnds + 1 end if
      else
        if w0 == "else" then
        indent = indent - 1
        if indent < 0 then indent = 0 end if
        else
          if (w0 == "case" or w0 == "default") and not sb_isEmpty(branchBases) then
            base = sb_top(branchBases)
            indent = base
          end if
        end if
      end if
    end if

    // Keep preprocessor directives at column zero. Their selected runtime
    // statements still use the surrounding language-block indentation.
    if not isDirective then bb = _emitIndent(bb, indent, indentSize) end if

    // emit formatted code + comment
    if len(codeTL) > 0 and isDirective then
      bb = bb_pushBytes(bb, codeTL)
    else
      if len(codeTL) > 0 then
        bb = emit_formatted_code(bb, codeTL)
      end if
    end if

    if len(comment) > 0 then
      c2 = _normalizeLineComment(_trimLeftBytes(comment))
      if len(codeTL) > 0 then
        bb = bb_pushByte(bb, 32)
      end if
      bb = bb_pushBytes(bb, c2)
    end if

    bb = bb_pushByte(bb, 10)

    // post-indent adjustments
    if w0 == "else" then
      indent = indent + 1
    else
      if (w0 == "case" or w0 == "default") and not sb_isEmpty(branchBases) then
        base2 = sb_top(branchBases)
        indent = base2 + 1
      else
        // openers
        opener = ""
        if w0 == "function" or w0 == "struct" or w0 == "enum" or w0 == "namespace" or w0 == "interface" or w0 == "switch" or w0 == "match" or w0 == "if" or w0 == "while" or w0 == "for" or w0 == "loop" then
          opener = w0
        end if

        // Interface methods are signatures and therefore have no individual
        // `end function` block.
        if w0 == "function" and interfaceDepth > 0 then opener = "" end if

        // Modern declaration prefixes all close with `end function`.
        if (w0 == "async" or w0 == "iterator") and w1 == "function" then
          opener = "function"
        end if
        if w0 == "lazy" and w1 == "iterator" then opener = "function" end if
        if w0 == "static" and w1 == "function" then opener = "function" end if
        if isLoopFooter then opener = "" end if

        // Fine-grained synchronization is a block only in call form;
        // `synchronized name = value` remains a declaration.
        if w0 == "synchronized" and w1 == "" then opener = "synchronized" end if

        // extern struct ...
        if w0 == "extern" and w1 == "struct" then
          opener = "struct"
        end if

        if opener != "" then
          // avoid indenting inline blocks like: if .. then .. end if
          if not _containsEndOf(codeTL, opener) then
            indent = indent + 1
            if w0 == "switch" or w0 == "match" then
              // indent is now the case-header base
              branchBases = sb_push(branchBases, indent)
            end if
            if w0 == "interface" then interfaceDepth = interfaceDepth + 1 end if
          end if
        end if
      end if
    end if

    if w0 == "end" and w1 == "interface" and interfaceDepth > 0 then
      interfaceDepth = interfaceDepth - 1
    end if

    if j >= len(b) then
      break
    end if
    lineStart = j + 1
  end while

  output = bb_toBytes(bb)
  output = _clampNewlines(output, maxBlankLines)
  return decode(output)
end function

// ------------------------------------------------------------
// Batch formatting helpers (portable recursive directory walk)
// ------------------------------------------------------------

#if TARGET_OS == "windows"
extern function _formatterGetFileAttributesW(path as wstr) from "kernel32.dll" symbol "GetFileAttributesW" returns u32
#else
extern function _formatterLstat(path as cstr, info as bytes) from "libc.so.6" symbol "lstat" returns i32
#endif

function _u32le(b, off)
  return b[off] + b[off + 1] * 256 + b[off + 2] * 65536 + b[off + 3] * 16777216
end function

// Recursive tree formatting must not follow junctions or symbolic-link
// directories. Besides preventing cycles, this matches compiler project scans.
function _isDirectoryLink(pathValue)
#if TARGET_OS == "windows"
  attributes = _formatterGetFileAttributesW(pathValue)
  if attributes == 0xFFFFFFFF then return false end if
  return (attributes & 0x10) != 0 and (attributes & 0x400) != 0
#else
  info = bytes(144, 0)
  if _formatterLstat(pathValue, info) != 0 then return false end if
  mode = _u32le(info, 24)
  return (mode & 61440) == 40960 and fs.isDir(pathValue)
#endif
end function

function _isMlFile(name)
  b = bytes(name)
  if len(b) < 3 then return false end if
  i = len(b) - 3
  if b[i] != 46 then return false end if
  c1 = b[i + 1]
  c2 = b[i + 2]
  if (c1 == 109 or c1 == 77) and(c2 == 108 or c2 == 76) then
    return true
  end if
  return false
end function

function _containsAsciiPrefix(s, needle, maxBytes)
  if typeof(s) != "string" or typeof(needle) != "string" then
    return false
  end if

  hb = bytes(s)
  if maxBytes >= 0 and len(hb) > maxBytes then
    hb = slice(hb, 0, maxBytes)
  end if

  nb = bytes(needle)
  if len(nb) <= 0 then
    return true
  end if
  if len(hb) < len(nb) then
    return false
  end if

  i = 0
  while i <= len(hb) - len(nb)
    j = 0
    match = true
    while j < len(nb)
      if hb[i + j] != nb[j] then
        match = false
        break
      end if
      j = j + 1
    end while
    if match then
      return true
    end if
    i = i + 1
  end while

  return false
end function

function _hasApacheHeader(src)
  // only look at the beginning of the file
  if _containsAsciiPrefix(src, "Licensed under the Apache License, Version 2.0", 4096) then
    return true
  end if
  if _containsAsciiPrefix(src, "http://www.apache.org/licenses/LICENSE-2.0", 4096) then
    return true
  end if
  return false
end function

// Grow a managed-value vector without repeatedly concatenating immutable
// arrays. Directory mode can encounter thousands of source files.
function _growValues(items, need)
  newLength = len(items)
  if newLength < 16 then newLength = 16 end if
  while newLength < need newLength = newLength * 2 end while
  grown = array(newLength)
  if len(items) > 0 then copyArray(grown, 0, items, 0, len(items)) end if
  return grown
end function

function _takeValues(items, count)
  if count <= 0 then return [] end if
  result = array(count)
  copyArray(result, 0, items, 0, count)
  return result
end function

function _apacheHeader(author, year)
  return "/*
  Copyright " + year + " " + author + "

  Licensed under the Apache License, Version 2.0 (the \"License\");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an \"AS IS\" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
  */"
end function

function _nl2()
  return "

  "
end function

function _formatOneFile(path, outPath, indentSize, maxBlankLines, addApache, author, year)
  src = fs.readAllText(path)
  if typeof(src) == "error" then
    print "readAllText failed: " + path + " error: " + src.message
    return false
  end if
  formatted = format_source(src, indentSize, maxBlankLines)

  if addApache and _hasApacheHeader(src) == false then
    formatted = _apacheHeader(author, year) + _nl2() + formatted
  end if

  // safety: never overwrite with empty output
  if len(formatted) == 0 and len(src) > 0 then
    print "Refusing to write empty output: " + outPath
    return false
  end if

  w = fs.writeAllText(outPath, formatted)
  if typeof(w) == "error" then
    print "writeAllText failed: " + outPath + " error: " + w.message
    return false
  end if
  if w == false then
    print "writeAllText failed: " + outPath
    return false
  end if

  return true
end function

function _collectMlFiles(rootDir)
  files = array(16)
  fileCount = 0
  stack = array(16)
  stack[0] = rootDir
  stackCount = 1

  while stackCount > 0
    stackCount = stackCount - 1
    dir = stack[stackCount]

    entries = fs.listDir(dir)
    if typeof(entries) == "error" then
      return error(entries.code, "listDir failed for " + dir + ": " + entries.message)
    end if
    i = 0
    while i < len(entries)
      name = entries[i]
      full = path.join(dir, name)

      if fs.isDir(full) then
        if not _isDirectoryLink(full) then
          if stackCount == len(stack) then stack = _growValues(stack, stackCount + 1) end if
          stack[stackCount] = full
          stackCount = stackCount + 1
        end if
      else
        if _isMlFile(name) then
          if fileCount == len(files) then files = _growValues(files, fileCount + 1) end if
          files[fileCount] = full
          fileCount = fileCount + 1
        end if
      end if

      i = i + 1
    end while
  end while

  return _takeValues(files, fileCount)
end function

function _formatTree(rootDir, indentSize, maxBlankLines, addApache, author, year)
  files = _collectMlFiles(rootDir)
  if typeof(files) == "error" then
    print files.message
    return false
  end if
  okAll = true
  i = 0
  while i < len(files)
    p = files[i]
    ok = _formatOneFile(p, p, indentSize, maxBlankLines, addApache, author, year)
    if ok == false then
      okAll = false
    end if
    i = i + 1
  end while
  print "Formatted " + len(files) + " file(s)."
  return okAll
end function

function _currentYear()
  year = 1970
  current = time.datetime.nowLocal()
  if typeof(current) != "void" then
    year = current.date.year
  end if
  return year
end function

function _usage()
  print "mlfmt - MiniLang AutoFormatter"
  print "Usage:"
  print "  mlfmt <path> [output.ml] [--inplace] [--indent N] [--max-blank N] [--apache AUTHOR] [--author AUTHOR] [--help]"
  print ""
  print "Notes:"
  print "  - If <path> is a directory, mlfmt formats all *.ml files recursively IN-PLACE."
  print "  - [output.ml] is only valid when <path> is a single file."
  print ""
  print "Defaults:"
  print "  --indent 2"
  print "  --max-blank 2 (use -1 for unlimited)"
  print ""
  print "Examples:"
  print "  mlfmt src.ml --inplace"
  print "  mlfmt src.ml out.ml --indent 2"
  print "  mlfmt ."
  print "  mlfmt . --apache \"Authorname\""
end function

function main(args)
  indentSize = 2
  maxBlankLines = 2
  inplace = false
  addApache = false
  author = ""
  inPath = ""
  outPath = ""

  i = 0
  while i < len(args)
    a = args[i]

    if _startsWith(a, "--") then
      if a == "--help" then
        _usage()
        return 0
      end if

      if a == "--inplace" then
        inplace = true
        i = i + 1
        continue
      end if

      if a == "--indent" then
        if i + 1 >= len(args) then
          _usage()
          return 1
        end if
        indentSize = _parseIntOrDefault(args[i + 1], 2)
        if indentSize < 0 then indentSize = 2 end if
        i = i + 2
        continue
      end if

      if a == "--max-blank" then
        if i + 1 >= len(args) then
          _usage()
          return 1
        end if
        maxBlankLines = _parseIntOrDefault(args[i + 1], 2)
        i = i + 2
        continue
      end if

      if a == "--apache" then
        addApache = true
        // optional inline author
        if i + 1 < len(args) and not _startsWith(args[i + 1], "--") then
          author = args[i + 1]
          i = i + 2
        else
          i = i + 1
        end if
        continue
      end if

      if a == "--author" then
        if i + 1 >= len(args) then
          _usage()
          return 1
        end if
        addApache = true
        author = args[i + 1]
        i = i + 2
        continue
      end if

      print "Unknown flag: " + a
      _usage()
      return 1
    end if

    if inPath == "" then
      inPath = a
    else
      if outPath == "" then
        outPath = a
      else
        print "Too many positional arguments."
        _usage()
        return 1
      end if
    end if

    i = i + 1
  end while

  if inPath == "" then
    _usage()
    return 1
  end if

  if addApache and author == "" then
    print "Missing author. Use --apache AUTHOR or --author AUTHOR."
    return 1
  end if

  year = _currentYear()

  if fs.isDir(inPath) then
    if outPath != "" then
      print "output.ml is only valid for single-file formatting."
      return 1
    end if
    ok = _formatTree(inPath, indentSize, maxBlankLines, addApache, author, year)
    if ok then return 0 end if
    return 1
  end if

  if inplace or outPath == "" then
    outPath = inPath
  end if

  ok = _formatOneFile(inPath, outPath, indentSize, maxBlankLines, addApache, author, year)
  if ok then return 0 end if
  return 1
end function

