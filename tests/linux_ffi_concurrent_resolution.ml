#if TARGET_OS != "linux" or TARGET_ABI != "sysv"
#error "linux_ffi_concurrent_resolution.ml requires the linux-x64 target"
#endif

extern function strlen(value as cstr) from "libc.so.6" returns u64
extern function missingSymbol() from "libc.so.6" symbol "minilang_concurrent_symbol_that_does_not_exist" returns int

synchronized ready = 0
synchronized go = false
synchronized failures = 0

function resolverWorker()
  global ready, go, failures
  ready = ready + 1
  while not go
    threadSleep(0)
  end while
  if strlen("concurrent") != 10 then failures = failures + 1 end if
  missing = try(missingSymbol())
  if typeof(missing) != "error" or missing.code != 1001 then failures = failures + 1 end if
end function

function main(args)
  global ready, go, failures
  workerCount = 32
  workers = []
  for i = 1 to workerCount
    worker = Thread(resolverWorker)
    if not worker.Start() then return 1 end if
    workers = workers + [worker]
  end for
  while ready < workerCount
    threadSleep(0)
  end while
  go = true
  for each worker in workers
    if not worker.Join(10000) then return 2 end if
    worker.Close()
  end for
  if failures != 0 then return 3 end if
  print "[OK] concurrent Linux extern resolution"
  return 0
end function
