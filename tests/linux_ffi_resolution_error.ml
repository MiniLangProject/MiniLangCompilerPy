#if TARGET_OS == "linux"
extern function missingLibrary() from "/definitely/missing/minilang/libmissing.so" symbol "missingLibrary" returns int
extern function missingSymbol() from "libc.so.6" symbol "minilang_symbol_that_does_not_exist" returns int

function main(args)
  directLibrary = try(missingLibrary())
  directSymbol = try(missingSymbol())
  indirect = missingSymbol
  indirectSymbol = try(indirect())

  if typeof(directLibrary) != "error" then return 1 end if
  if typeof(directSymbol) != "error" then return 2 end if
  if typeof(indirectSymbol) != "error" then return 3 end if
  if directLibrary.code != 1001 then return 4 end if
  if directSymbol.code != 1001 then return 5 end if
  if indirectSymbol.code != 1001 then return 6 end if
  print "[OK] Linux extern resolution errors are managed"
  return 0
end function
#endif
