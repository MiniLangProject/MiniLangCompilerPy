package regression.struct_identity.alpha

struct Record
  left
  right

  /// An instance method's unqualified constructor stays in its owning package.
  function reverse()
    return Record(this.right, this.left)
  end function

  /// A static method's unqualified constructor stays in its owning package.
  static function make(left, right)
    return Record(left, right)
  end function
end struct

struct Holder
  value = Record(31, 41)
end struct

function make()
  return Record(11, 22)
end function

function makeNamed()
  return Record(right = 24, left = 13)
end function

function makeStatic()
  return Record.make(71, 81)
end function

function makeHolder()
  return Holder()
end function

function constructor()
  return Record
end function

/// A lexical parameter still takes precedence over the package's struct name.
function parameterFactory(Record)
  return Record(101, 102)
end function

/// A lexical local still takes precedence over the package's struct name.
function localFactory(factory)
  Record = factory
  return Record(103, 104)
end function

/// A shadowing callable's result cannot inherit the hidden struct's field layout.
function leftFromLocalFactory(factory)
  Record = factory
  value = Record(107, 108)
  return value.left
end function

function rightFromParameterFactory(Record)
  value = Record(109, 110)
  return value.right
end function

/// A captured callable retains lexical shadowing when invoked after return.
function capturedFactory(factory)
  Record = factory
  return function(left, right) => Record(left, right)
end function

/// Explicitly qualified names must not gain an unrelated package prefix.
function qualifiedGlobal()
  return entry_scope.Record(51, 61)
end function

namespace child
  function parentRecord()
    return Record(95, 96)
  end function
end namespace

namespace inner
  struct Record
    right
    left

    static function make(right, left)
      return Record(right, left)
    end function

    function clone()
      return Record(this.right, this.left)
    end function
  end struct

  function make()
    return Record(91, 92)
  end function

  function parentRecord()
    return regression.struct_identity.alpha.Record(93, 94)
  end function

  function makeStatic()
    return Record.make(97, 98)
  end function
end namespace
