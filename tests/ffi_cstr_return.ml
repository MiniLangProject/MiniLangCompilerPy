/// Native cstr conversion must share one emitter across both targets/pipelines.
#if TARGET_OS == "windows"
extern function locate(value as cstr, ch as i32) from "msvcrt.dll" symbol "strchr" returns cstr
#else
extern function locate(value as cstr, ch as i32) from "libc.so.6" symbol "strchr" returns cstr
#endif

function checkConversions(repeats)
  lengths = [0, 1, 7, 8, 15, 16, 31, 63, 64, 255, 4096, 16384]
  for cycle = 1 to repeats
    for each n in lengths
      suffix = stringRepeat("x", n)
      input = "prefix!" + suffix
      value = locate(input, 33)
      if value != "!" + suffix then return false end if
      if locate(input, 0) != "" then return false end if
      if locate(input, 63) != void then return false end if
      gc_collect()
      if len(value) != n + 1 or value[0] != "!" then return false end if
    end for
  end for
  return true
end function

function main(args)
  if not checkConversions(3) then return 1 end if
  workers = array(4, void)
  for i = 0 to 3
    worker = Thread(checkConversions)
    if not worker.Start(3) then return 2 end if
    workers[i] = worker
  end for
  for each worker in workers
    if not worker.Join(30000) or worker.Result() != true then return 3 end if
    if not worker.Close() then return 4 end if
  end for
  gc_collect()
  print "FFI CSTR RETURN [OK]"
  return 0
end function
