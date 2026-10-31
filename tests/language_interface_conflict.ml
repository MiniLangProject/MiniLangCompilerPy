interface IntegerValue
  function value() returns int
end interface

interface TextValue
  function value() returns string
end interface

interface Both extends IntegerValue, TextValue
end interface
