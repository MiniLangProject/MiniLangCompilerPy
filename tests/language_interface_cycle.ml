interface First extends Second
  function value() returns int
end interface

interface Second extends First
  function other() returns int
end interface
