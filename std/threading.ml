/*
   Copyright 2026 Nils Kopal

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0
*/

package std.threading

// Native Win32 synchronization primitives. All MiniLang objects live in the
// process-wide managed heap; these handles serialize access between the OS
// threads and their private stacks. Close only after users/waiters have stopped.

const WAIT_OBJECT_0 = 0
const WAIT_ABANDONED = 0x80
const WAIT_TIMEOUT = 0x102
const INFINITE = 0xFFFFFFFF

extern function CreateMutexW(security as ptr, initialOwner as bool, name as ptr) from "kernel32.dll" returns ptr
extern function ReleaseMutex(handle as ptr) from "kernel32.dll" returns bool
extern function CreateSemaphoreW(security as ptr, initialCount as int, maximumCount as int, name as ptr) from "kernel32.dll" returns ptr
extern function ReleaseSemaphore(handle as ptr, releaseCount as int, previousCount as ptr) from "kernel32.dll" returns bool
extern function CreateEventW(security as ptr, manualReset as bool, initialState as bool, name as ptr) from "kernel32.dll" returns ptr
extern function SetEvent(handle as ptr) from "kernel32.dll" returns bool
extern function ResetEvent(handle as ptr) from "kernel32.dll" returns bool
extern function WaitForSingleObject(handle as ptr, milliseconds as u32) from "kernel32.dll" returns u32
extern function CloseHandle(handle as ptr) from "kernel32.dll" returns bool

function _waitSucceeded(result)
  return result == WAIT_OBJECT_0 or result == WAIT_ABANDONED
end function

struct Lock
  handle
  closed

  static function new()
    h = CreateMutexW(void, false, void)
    if h == 0 then
      return error(1600, "could not create native lock")
    end if
    return Lock(h, false)
  end function

  function acquire()
    if this.closed then return false end if
    return _waitSucceeded(WaitForSingleObject(this.handle, INFINITE))
  end function

  function acquireFor(milliseconds)
    if this.closed or typeof(milliseconds) != "int" or milliseconds < 0 then
      return false
    end if
    return _waitSucceeded(WaitForSingleObject(this.handle, milliseconds))
  end function

  function tryAcquire()
    return this.acquireFor(0)
  end function

  function release()
    if this.closed then return false end if
    return ReleaseMutex(this.handle)
  end function

  function isClosed()
    return this.closed
  end function

  function close()
    if this.closed then return false end if
    ok = CloseHandle(this.handle)
    if ok then
      this.closed = true
      this.handle = 0
    end if
    return ok
  end function

  // PascalCase aliases match the native Thread API.
  function Acquire() return this.acquire() end function
  function AcquireFor(milliseconds) return this.acquireFor(milliseconds) end function
  function TryAcquire() return this.tryAcquire() end function
  function Release() return this.release() end function
  function IsClosed() return this.isClosed() end function
end struct

struct Semaphore
  handle
  maximumCount
  closed

  static function new(initialCount, maximumCount)
    if typeof(initialCount) != "int" or typeof(maximumCount) != "int" then
      return error(1601, "semaphore counts must be integers")
    end if
    if initialCount < 0 or maximumCount <= 0 or initialCount > maximumCount then
      return error(1601, "invalid semaphore counts")
    end if
    h = CreateSemaphoreW(void, initialCount, maximumCount, void)
    if h == 0 then
      return error(1601, "could not create native semaphore")
    end if
    return Semaphore(h, maximumCount, false)
  end function

  function acquire()
    if this.closed then return false end if
    return _waitSucceeded(WaitForSingleObject(this.handle, INFINITE))
  end function

  function acquireFor(milliseconds)
    if this.closed or typeof(milliseconds) != "int" or milliseconds < 0 then
      return false
    end if
    return _waitSucceeded(WaitForSingleObject(this.handle, milliseconds))
  end function

  function tryAcquire()
    return this.acquireFor(0)
  end function

  function release()
    return this.releaseMany(1)
  end function

  function releaseMany(count)
    if this.closed or typeof(count) != "int" or count <= 0 then
      return false
    end if
    return ReleaseSemaphore(this.handle, count, void)
  end function

  function isClosed()
    return this.closed
  end function

  function close()
    if this.closed then return false end if
    ok = CloseHandle(this.handle)
    if ok then
      this.closed = true
      this.handle = 0
    end if
    return ok
  end function

  function Acquire() return this.acquire() end function
  function AcquireFor(milliseconds) return this.acquireFor(milliseconds) end function
  function TryAcquire() return this.tryAcquire() end function
  function Release() return this.release() end function
  function ReleaseMany(count) return this.releaseMany(count) end function
  function IsClosed() return this.isClosed() end function
end struct

struct Event
  handle
  manualReset
  closed

  static function new(manualReset, initialState)
    if typeof(manualReset) != "bool" or typeof(initialState) != "bool" then
      return error(1602, "event flags must be booleans")
    end if
    h = CreateEventW(void, manualReset, initialState, void)
    if h == 0 then
      return error(1602, "could not create native event")
    end if
    return Event(h, manualReset, false)
  end function

  function wait()
    if this.closed then return false end if
    return _waitSucceeded(WaitForSingleObject(this.handle, INFINITE))
  end function

  function waitFor(milliseconds)
    if this.closed or typeof(milliseconds) != "int" or milliseconds < 0 then
      return false
    end if
    return _waitSucceeded(WaitForSingleObject(this.handle, milliseconds))
  end function

  function tryWait()
    return this.waitFor(0)
  end function

  function set()
    if this.closed then return false end if
    return SetEvent(this.handle)
  end function

  function reset()
    if this.closed then return false end if
    return ResetEvent(this.handle)
  end function

  function isClosed()
    return this.closed
  end function

  function close()
    if this.closed then return false end if
    ok = CloseHandle(this.handle)
    if ok then
      this.closed = true
      this.handle = 0
    end if
    return ok
  end function

  function Wait() return this.wait() end function
  function WaitFor(milliseconds) return this.waitFor(milliseconds) end function
  function TryWait() return this.tryWait() end function
  function Set() return this.set() end function
  function Reset() return this.reset() end function
  function IsClosed() return this.isClosed() end function
end struct
