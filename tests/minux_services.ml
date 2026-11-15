import std.fs as fs
import std.time as time
import std.process as process
import std.platform as platform
import std.path as path
import std.threading as sync

extern function nativeLength(text as cstr) from "libc.so.1" symbol "strlen" returns u64
extern function nativeTail(text as cstr, ch as int) from "libc.so.1" symbol "strchr" returns cstr

function worker(value)
  retained = [value, "worker", bytes(4096, value)]
  for i = 0 to 31
    garbage = bytes(2048, value)
    gc_collect()
  end for
  if retained[0] != value or retained[2][0] != value then return -1 end if
  return value + 1
end function

function sleeper(value)
  time.sleep(100)
  return value
end function

function main(args)
  if platform.operatingSystem() != "minux" or not platform.isMinux() or platform.isLinux() then return 1 end if
  if path.join("/home/user", "probe") != "/home/user/probe" then return 2 end if
  if nativeLength("Grüße") != 7 or nativeTail("abc:def", 58) != ":def" then return 3 end if
  print "ffi=ok"
  filename = "/home/user/minilang-test.bin"
  content = bytes("MiniLang auf MinUX: Grüße 🚀")
  if fs.writeAllBytes(filename, content) != true then return 4 end if
  if fs.readAllBytes(filename) != content or fs.fileSize(filename) != len(content) then return 5 end if
  if not fs.isFile(filename) or not fs.isDir("/home/user") then return 6 end if
  if typeof(fs.listDir("/home/user")) != "array" then return 7 end if
  copy = filename + ".copy"
  if fs.copyFile(filename, copy, true) != true or fs.readAllBytes(copy) != content then return 8 end if
  sameFile = try(fs.copyFile(filename, filename, true))
  if typeof(sameFile) != "error" then return 9 end if
  if not fs.delete(copy) or not fs.delete(filename) then return 10 end if
  print "files=ok"
  stamp = time.ticks()
  time.sleep(20)
  if time.ticks() < stamp + 10 then return 11 end if
  if process.id() <= 0 or process.currentDirectory() != "/home/user" then return 12 end if
  executable = process.executablePath()
  if typeof(executable) != "string" or len(executable) == 0 then return 21 end if
  print "services=ok"
  lock = sync.Lock.new()
  if lock is error or not lock.acquire() or not lock.release() or not lock.close() then return 13 end if
  sem = sync.Semaphore.new(1, 2)
  if sem is error or not sem.tryAcquire() or sem.tryAcquire() or not sem.release() or not sem.acquire() or not sem.close() then return 14 end if
  event = sync.Event.new(false, true)
  if event is error or not event.waitFor(0) or event.waitFor(0) or not event.set() or not event.waitFor(100) or not event.close() then return 15 end if
  print "synchronization=ok"
  first = Thread(worker)
  second = Thread(worker)
  if not first.Start(41) or not second.Start(42) then return 16 end if
  gc_collect()
  if not first.Join(10000) or not second.Join(10000) then return 17 end if
  if first.Result() != 42 or second.Result() != 43 then return 18 end if
  delayed = Thread(sleeper)
  if not delayed.Start(12) then return 19 end if
  if delayed.Join(10) then return 20 end if
  if not delayed.Join(10000) or delayed.Result() != 12 then return 21 end if
  print "threads-gc=ok"
  print "minux-services=ok"
  return 37
end function
