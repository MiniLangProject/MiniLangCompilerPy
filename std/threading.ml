/*
   Copyright 2026 Nils Kopal

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0
*/

//! Provides the std threading package.

package std.threading

/// Native timeout/count parameters are signed 32-bit values on at least one supported target. Keeping the shared API inside this range avoids truncation and platform-dependent interpretations of the high bit.
const MAX_PORTABLE_TIMEOUT_MS = 2147483647
/// Stores the max native semaphore count.
const MAX_NATIVE_SEMAPHORE_COUNT = 2147483647

#if TARGET_OS == "windows"

/// Native Win32 synchronization primitives. All MiniLang objects live in the process-wide managed heap; these handles serialize access between the OS threads and their private stacks. Close only after users/waiters have stopped.
const WAIT_OBJECT_0 = 0
/// Stores the wait abandoned.
const WAIT_ABANDONED = 0x80
/// Stores the wait timeout.
const WAIT_TIMEOUT = 0x102
/// Stores the infinite.
const INFINITE = 0xFFFFFFFF

/// Creates create mutex w.
/// @internal
extern function CreateMutexW(security as ptr, initialOwner as bool, name as ptr) from "kernel32.dll" returns ptr
/// Releases or resets release mutex.
/// @internal
extern function ReleaseMutex(handle as ptr) from "kernel32.dll" returns bool
/// Creates create semaphore w.
/// @internal
extern function CreateSemaphoreW(security as ptr, initialCount as int, maximumCount as int, name as ptr) from "kernel32.dll" returns ptr
/// Releases or resets release semaphore.
/// @internal
extern function ReleaseSemaphore(handle as ptr, releaseCount as int, previousCount as ptr) from "kernel32.dll" returns bool
/// Creates create event w.
/// @internal
extern function CreateEventW(security as ptr, manualReset as bool, initialState as bool, name as ptr) from "kernel32.dll" returns ptr
/// Updates set event.
/// @internal
extern function SetEvent(handle as ptr) from "kernel32.dll" returns bool
/// Releases or resets reset event.
/// @internal
extern function ResetEvent(handle as ptr) from "kernel32.dll" returns bool
/// Implements wait for single object.
/// @internal
extern function WaitForSingleObject(handle as ptr, milliseconds as u32) from "kernel32.dll" returns u32
/// Releases or resets close handle.
/// @internal
extern function CloseHandle(handle as ptr) from "kernel32.dll" returns bool

/// Treat an abandoned mutex as acquired, matching Win32 ownership semantics.
/// @internal
function _waitSucceeded(result)
  return result == WAIT_OBJECT_0 or result == WAIT_ABANDONED
end function

/// Re-entrant native mutex. Every successful acquire must be released.
struct Lock
  /// Stores the handle member of `Lock`.
  handle
  /// Stores the closed member of `Lock`.
  closed

  /// Create an initially unowned native mutex.
  static function new()
    h = CreateMutexW(void, false, void)
    if h == 0 then
      return error(1600, "could not create native lock")
    end if
    return Lock(h, false)
  end function

  /// Block until the current thread owns the mutex.
  function acquire()
    if this.closed then return false end if
    return _waitSucceeded(WaitForSingleObject(this.handle, INFINITE))
  end function

  /// Wait at most the requested number of milliseconds for ownership.
  /// @param milliseconds Maximum duration in milliseconds.
  function acquireFor(milliseconds)
    if this.closed or typeof(milliseconds) != "int" or milliseconds < 0 or milliseconds > MAX_PORTABLE_TIMEOUT_MS then
      return false
    end if
    return _waitSucceeded(WaitForSingleObject(this.handle, milliseconds))
  end function

  /// Attempt immediate acquisition without blocking.
  function tryAcquire()
    return this.acquireFor(0)
  end function

  /// Release one acquisition held by the current thread.
  function release()
    if this.closed then return false end if
    return ReleaseMutex(this.handle)
  end function

  /// Reports whether this Windows lock handle has been closed.
  function isClosed()
    return this.closed
  end function

  /// Close the mutex handle after all users have stopped accessing it.
  function close()
    if this.closed then return false end if
    ok = CloseHandle(this.handle)
    if ok then
      this.closed = true
      this.handle = 0
    end if
    return ok
  end function

  /// PascalCase aliases match the native Thread API.
  function Acquire() return this.acquire() end function
  /// Implements acquire for.
  /// @param milliseconds Maximum duration in milliseconds.
  function AcquireFor(milliseconds) return this.acquireFor(milliseconds) end function
  /// Implements try acquire.
  function TryAcquire() return this.tryAcquire() end function
  /// Releases or resets release.
  function Release() return this.release() end function
  /// Exposes the Windows lock closed state through a PascalCase alias.
  function IsClosed() return this.isClosed() end function
end struct

/// Counting semaphore with a fixed maximum permit count.
struct Semaphore
  /// Stores the handle member of `Semaphore`.
  handle
  /// Stores the maximum count member of `Semaphore`.
  maximumCount
  /// Stores the closed member of `Semaphore`.
  closed

  /// Create a semaphore with validated initial and maximum permit counts.
  /// @param initialCount Value supplied for `initialCount`.
  /// @param maximumCount Value supplied for `maximumCount`.
  static function new(initialCount, maximumCount)
    if typeof(initialCount) != "int" or typeof(maximumCount) != "int" then
      return error(1601, "semaphore counts must be integers")
    end if
    if initialCount < 0 or maximumCount <= 0 or initialCount > maximumCount or maximumCount > MAX_NATIVE_SEMAPHORE_COUNT then
      return error(1601, "invalid semaphore counts")
    end if
    h = CreateSemaphoreW(void, initialCount, maximumCount, void)
    if h == 0 then
      return error(1601, "could not create native semaphore")
    end if
    return Semaphore(h, maximumCount, false)
  end function

  /// Block until one permit can be consumed.
  function acquire()
    if this.closed then return false end if
    return _waitSucceeded(WaitForSingleObject(this.handle, INFINITE))
  end function

  /// Consume one permit within the requested timeout.
  /// @param milliseconds Maximum duration in milliseconds.
  function acquireFor(milliseconds)
    if this.closed or typeof(milliseconds) != "int" or milliseconds < 0 or milliseconds > MAX_PORTABLE_TIMEOUT_MS then
      return false
    end if
    return _waitSucceeded(WaitForSingleObject(this.handle, milliseconds))
  end function

  /// Attempt to consume one permit without blocking.
  function tryAcquire()
    return this.acquireFor(0)
  end function

  /// Return one permit to the semaphore.
  function release()
    return this.releaseMany(1)
  end function

  /// Return multiple permits in one native operation.
  /// @param count Number of items to process.
  function releaseMany(count)
    if this.closed or typeof(count) != "int" or count <= 0 or count > this.maximumCount then
      return false
    end if
    return ReleaseSemaphore(this.handle, count, void)
  end function

  /// Reports whether this Windows semaphore handle has been closed.
  function isClosed()
    return this.closed
  end function

  /// Close the handle after no thread can wait on it again.
  function close()
    if this.closed then return false end if
    ok = CloseHandle(this.handle)
    if ok then
      this.closed = true
      this.handle = 0
    end if
    return ok
  end function

  /// PascalCase aliases mirror the native Thread API.
  function Acquire() return this.acquire() end function
  /// Implements acquire for.
  /// @param milliseconds Maximum duration in milliseconds.
  function AcquireFor(milliseconds) return this.acquireFor(milliseconds) end function
  /// Implements try acquire.
  function TryAcquire() return this.tryAcquire() end function
  /// Releases or resets release.
  function Release() return this.release() end function
  /// Releases or resets release many.
  /// @param count Number of items to process.
  function ReleaseMany(count) return this.releaseMany(count) end function
  /// Exposes the Windows semaphore closed state through a PascalCase alias.
  function IsClosed() return this.isClosed() end function
end struct

/// Win32 manual- or auto-reset event for one-to-many notifications.
struct Event
  /// Stores the handle member of `Event`.
  handle
  /// Stores the manual reset member of `Event`.
  manualReset
  /// Stores the closed member of `Event`.
  closed

  /// Create an event with explicit reset mode and initial signal state.
  /// @param manualReset Value supplied for `manualReset`.
  /// @param initialState Value supplied for `initialState`.
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

  /// Wait indefinitely until the event is signaled.
  function wait()
    if this.closed then return false end if
    return _waitSucceeded(WaitForSingleObject(this.handle, INFINITE))
  end function

  /// Wait until signaled or until the timeout expires.
  /// @param milliseconds Maximum duration in milliseconds.
  function waitFor(milliseconds)
    if this.closed or typeof(milliseconds) != "int" or milliseconds < 0 or milliseconds > MAX_PORTABLE_TIMEOUT_MS then
      return false
    end if
    return _waitSucceeded(WaitForSingleObject(this.handle, milliseconds))
  end function

  /// Test the signal state without blocking.
  function tryWait()
    return this.waitFor(0)
  end function

  /// Signal the event and release the applicable waiters.
  function set()
    if this.closed then return false end if
    return SetEvent(this.handle)
  end function

  /// Return a manual-reset event to the nonsignaled state.
  function reset()
    if this.closed then return false end if
    return ResetEvent(this.handle)
  end function

  /// Reports whether this Windows event handle has been closed.
  function isClosed()
    return this.closed
  end function

  /// Close the event after no thread can wait on it again.
  function close()
    if this.closed then return false end if
    ok = CloseHandle(this.handle)
    if ok then
      this.closed = true
      this.handle = 0
    end if
    return ok
  end function

  /// PascalCase aliases mirror the native Thread API.
  function Wait() return this.wait() end function
  /// Exposes the Windows event timed wait through a PascalCase alias.
  /// @param milliseconds Maximum duration in milliseconds.
  function WaitFor(milliseconds) return this.waitFor(milliseconds) end function
  /// Implements try wait.
  function TryWait() return this.tryWait() end function
  /// Updates set.
  function Set() return this.set() end function
  /// Releases or resets reset.
  function Reset() return this.reset() end function
  /// Exposes the Windows event closed state through a PascalCase alias.
  function IsClosed() return this.isClosed() end function
end struct
#else

/// POSIX synchronization storage sizes are the glibc x86-64 ABI sizes. The buffers live in MiniLang's non-moving global heap and remain stable while a native primitive references them.
const PTHREAD_MUTEX_SIZE = 40
/// Stores the pthread mutexattr size.
const PTHREAD_MUTEXATTR_SIZE = 4
/// Stores the pthread cond size.
const PTHREAD_COND_SIZE = 48
/// Stores the semaphore size.
const SEMAPHORE_SIZE = 32
/// Stores the pthread mutex recursive.
const PTHREAD_MUTEX_RECURSIVE = 1

/// Implements mutex attr init.
/// @internal
extern function _mutexAttrInit(attribute as ptr) from "libc.so.6" symbol "pthread_mutexattr_init" returns i32
/// Implements mutex attr set type.
/// @internal
extern function _mutexAttrSetType(attribute as ptr, kind as int) from "libc.so.6" symbol "pthread_mutexattr_settype" returns i32
/// Implements mutex attr destroy.
/// @internal
extern function _mutexAttrDestroy(attribute as ptr) from "libc.so.6" symbol "pthread_mutexattr_destroy" returns i32
/// Implements mutex init.
/// @internal
extern function _mutexInit(mutex as ptr, attribute as ptr) from "libc.so.6" symbol "pthread_mutex_init" returns i32
/// Implements mutex lock.
/// @internal
extern function _mutexLock(mutex as ptr) from "libc.so.6" symbol "pthread_mutex_lock" returns i32
/// Implements mutex try lock.
/// @internal
extern function _mutexTryLock(mutex as ptr) from "libc.so.6" symbol "pthread_mutex_trylock" returns i32
/// Implements mutex unlock.
/// @internal
extern function _mutexUnlock(mutex as ptr) from "libc.so.6" symbol "pthread_mutex_unlock" returns i32
/// Implements mutex destroy.
/// @internal
extern function _mutexDestroy(mutex as ptr) from "libc.so.6" symbol "pthread_mutex_destroy" returns i32
/// Implements cond init.
/// @internal
extern function _condInit(condition as ptr, attribute as ptr) from "libc.so.6" symbol "pthread_cond_init" returns i32
/// Implements cond wait.
/// @internal
extern function _condWait(condition as ptr, mutex as ptr) from "libc.so.6" symbol "pthread_cond_wait" returns i32
/// Implements cond signal.
/// @internal
extern function _condSignal(condition as ptr) from "libc.so.6" symbol "pthread_cond_signal" returns i32
/// Implements cond broadcast.
/// @internal
extern function _condBroadcast(condition as ptr) from "libc.so.6" symbol "pthread_cond_broadcast" returns i32
/// Implements cond destroy.
/// @internal
extern function _condDestroy(condition as ptr) from "libc.so.6" symbol "pthread_cond_destroy" returns i32
/// Implements sem init.
/// @internal
extern function _semInit(semaphore as ptr, shared as int, value as u32) from "libc.so.6" symbol "sem_init" returns i32
/// Implements sem wait.
/// @internal
extern function _semWait(semaphore as ptr) from "libc.so.6" symbol "sem_wait" returns i32
/// Implements sem try wait.
/// @internal
extern function _semTryWait(semaphore as ptr) from "libc.so.6" symbol "sem_trywait" returns i32
/// Implements sem post.
/// @internal
extern function _semPost(semaphore as ptr) from "libc.so.6" symbol "sem_post" returns i32
/// Implements sem get value.
/// @internal
extern function _semGetValue(semaphore as ptr, value as ptr) from "libc.so.6" symbol "sem_getvalue" returns i32
/// Implements sem destroy.
/// @internal
extern function _semDestroy(semaphore as ptr) from "libc.so.6" symbol "sem_destroy" returns i32
/// Implements sleep micros.
/// @internal
extern function _sleepMicros(microseconds as u32) from "libc.so.6" symbol "usleep" returns i32

/// Creates new recursive mutex.
/// @internal
function _newRecursiveMutex()
  mutex = bytes(PTHREAD_MUTEX_SIZE, 0)
  attribute = bytes(PTHREAD_MUTEXATTR_SIZE, 0)
  if _mutexAttrInit(nativeBytesPtr(attribute)) != 0 then return end if
  if _mutexAttrSetType(nativeBytesPtr(attribute), PTHREAD_MUTEX_RECURSIVE) != 0 then
    _mutexAttrDestroy(nativeBytesPtr(attribute))
    return
  end if
  result = _mutexInit(nativeBytesPtr(mutex), nativeBytesPtr(attribute))
  _mutexAttrDestroy(nativeBytesPtr(attribute))
  if result != 0 then return end if
  return mutex
end function

/// Implements acquire for.
/// @internal
function _acquireFor(mutex, milliseconds)
  elapsed = 0
  while elapsed <= milliseconds
    if _mutexTryLock(nativeBytesPtr(mutex)) == 0 then return true end if
    if elapsed == milliseconds then return false end if
    _sleepMicros(1000)
    elapsed = elapsed + 1
  end while
  return false
end function

/// POSIX recursive mutex with the same public contract as the Win32 Lock.
struct Lock
  /// Stores the handle member of `Lock`.
  handle
  /// Stores the closed member of `Lock`.
  closed

  /// Allocate and initialize stable native mutex storage.
  static function new()
    mutex = _newRecursiveMutex()
    if typeof(mutex) != "bytes" then return error(1600, "could not create native lock") end if
    return Lock(mutex, false)
  end function

  /// Block until the current thread owns the recursive mutex.
  function acquire()
    if this.closed then return false end if
    return _mutexLock(nativeBytesPtr(this.handle)) == 0
  end function

  /// Poll for ownership until the requested timeout expires.
  /// @param milliseconds Maximum duration in milliseconds.
  function acquireFor(milliseconds)
    if this.closed or typeof(milliseconds) != "int" or milliseconds < 0 or milliseconds > MAX_PORTABLE_TIMEOUT_MS then return false end if
    return _acquireFor(this.handle, milliseconds)
  end function

  /// Attempt immediate acquisition without blocking.
  function tryAcquire() return this.acquireFor(0) end function

  /// Release one acquisition held by the current thread.
  function release()
    if this.closed then return false end if
    return _mutexUnlock(nativeBytesPtr(this.handle)) == 0
  end function

  /// Reports whether this POSIX lock has been closed.
  function isClosed() return this.closed end function

  /// Destroy native storage after all users have stopped accessing the lock.
  function close()
    if this.closed then return false end if
    ok = _mutexDestroy(nativeBytesPtr(this.handle)) == 0
    if ok then
      this.closed = true
      this.handle = void
    end if
    return ok
  end function

  /// Implements acquire.
  function Acquire() return this.acquire() end function
  /// Implements acquire for.
  /// @param milliseconds Maximum duration in milliseconds.
  function AcquireFor(milliseconds) return this.acquireFor(milliseconds) end function
  /// Implements try acquire.
  function TryAcquire() return this.tryAcquire() end function
  /// Releases or resets release.
  function Release() return this.release() end function
  /// Exposes the POSIX lock closed state through a PascalCase alias.
  function IsClosed() return this.isClosed() end function
end struct

/// POSIX counting semaphore. Releases are serialized and inspect the native count while holding the release guard, so an acquire cannot leave stale bookkeeping that spuriously rejects a valid handoff.
struct Semaphore
  /// Stores the handle member of `Semaphore`.
  handle
  /// Stores the count guard member of `Semaphore`.
  countGuard
  /// Stores the count value member of `Semaphore`.
  countValue
  /// Stores the maximum count member of `Semaphore`.
  maximumCount
  /// Stores the closed member of `Semaphore`.
  closed

  /// Create a semaphore with validated initial and maximum permit counts.
  /// @param initialCount Value supplied for `initialCount`.
  /// @param maximumCount Value supplied for `maximumCount`.
  static function new(initialCount, maximumCount)
    if typeof(initialCount) != "int" or typeof(maximumCount) != "int" then return error(1601, "semaphore counts must be integers") end if
    if initialCount < 0 or maximumCount <= 0 or initialCount > maximumCount or maximumCount > MAX_NATIVE_SEMAPHORE_COUNT then return error(1601, "invalid semaphore counts") end if
    semaphore = bytes(SEMAPHORE_SIZE, 0)
    guard = _newRecursiveMutex()
    if typeof(guard) != "bytes" then return error(1601, "could not create semaphore guard") end if
    if _semInit(nativeBytesPtr(semaphore), 0, initialCount) != 0 then
      _mutexDestroy(nativeBytesPtr(guard))
      return error(1601, "could not create native semaphore")
    end if
    return Semaphore(semaphore, guard, bytes(4, 0), maximumCount, false)
  end function

  /// Block until one permit can be consumed.
  function acquire()
    if this.closed then return false end if
    result = _semWait(nativeBytesPtr(this.handle))
    return result == 0
  end function

  /// Poll for one permit until the requested timeout expires.
  /// @param milliseconds Maximum duration in milliseconds.
  function acquireFor(milliseconds)
    if this.closed or typeof(milliseconds) != "int" or milliseconds < 0 or milliseconds > MAX_PORTABLE_TIMEOUT_MS then return false end if
    elapsed = 0
    while elapsed <= milliseconds
      if _semTryWait(nativeBytesPtr(this.handle)) == 0 then
        return true
      end if
      if elapsed == milliseconds then return false end if
      _sleepMicros(1000)
      elapsed = elapsed + 1
    end while
    return false
  end function

  /// Implements try acquire.
  function tryAcquire() return this.acquireFor(0) end function
  /// Releases or resets release.
  function release() return this.releaseMany(1) end function

  /// Validate and return multiple permits without exceeding the maximum.
  /// @param count Number of items to process.
  function releaseMany(count)
    if this.closed or typeof(count) != "int" or count <= 0 or count > this.maximumCount then return false end if
    _mutexLock(nativeBytesPtr(this.countGuard))
    if _semGetValue(nativeBytesPtr(this.handle), nativeBytesPtr(this.countValue)) != 0 then
      _mutexUnlock(nativeBytesPtr(this.countGuard))
      return false
    end if
    nativeCount = this.countValue[0] | (this.countValue[1] << 8) | (this.countValue[2] << 16) | (this.countValue[3] << 24)
    if nativeCount + count > this.maximumCount then
      _mutexUnlock(nativeBytesPtr(this.countGuard))
      return false
    end if
    i = 0
    while i < count
      if _semPost(nativeBytesPtr(this.handle)) != 0 then
        _mutexUnlock(nativeBytesPtr(this.countGuard))
        return false
      end if
      i = i + 1
    end while
    _mutexUnlock(nativeBytesPtr(this.countGuard))
    return true
  end function

  /// Reports whether this POSIX semaphore has been closed.
  function isClosed() return this.closed end function

  /// Destroy both native primitives after all users have stopped accessing them.
  function close()
    if this.closed then return false end if
    ok = _semDestroy(nativeBytesPtr(this.handle)) == 0
    if ok then ok = _mutexDestroy(nativeBytesPtr(this.countGuard)) == 0 end if
    if ok then
      this.closed = true
      this.handle = void
      this.countGuard = void
      this.countValue = void
    end if
    return ok
  end function

  /// Implements acquire.
  function Acquire() return this.acquire() end function
  /// Implements acquire for.
  /// @param milliseconds Maximum duration in milliseconds.
  function AcquireFor(milliseconds) return this.acquireFor(milliseconds) end function
  /// Implements try acquire.
  function TryAcquire() return this.tryAcquire() end function
  /// Releases or resets release.
  function Release() return this.release() end function
  /// Releases or resets release many.
  /// @param count Number of items to process.
  function ReleaseMany(count) return this.releaseMany(count) end function
  /// Exposes the POSIX semaphore closed state through a PascalCase alias.
  function IsClosed() return this.isClosed() end function
end struct

/// POSIX condition-variable implementation of manual- and auto-reset events.
struct Event
  /// Stores the mutex member of `Event`.
  mutex
  /// Stores the condition member of `Event`.
  condition
  /// Stores the manual reset member of `Event`.
  manualReset
  /// Stores the signaled member of `Event`.
  signaled
  /// Stores the closed member of `Event`.
  closed

  /// Allocate stable mutex/condition storage and set the initial signal state.
  /// @param manualReset Value supplied for `manualReset`.
  /// @param initialState Value supplied for `initialState`.
  static function new(manualReset, initialState)
    if typeof(manualReset) != "bool" or typeof(initialState) != "bool" then return error(1602, "event flags must be booleans") end if
    mutex = _newRecursiveMutex()
    condition = bytes(PTHREAD_COND_SIZE, 0)
    if typeof(mutex) != "bytes" or _condInit(nativeBytesPtr(condition), 0) != 0 then return error(1602, "could not create native event") end if
    return Event(mutex, condition, manualReset, initialState, false)
  end function

  /// Wait indefinitely, consuming an auto-reset signal exactly once.
  function wait()
    if this.closed then return false end if
    _mutexLock(nativeBytesPtr(this.mutex))
    while not this.signaled
      if _condWait(nativeBytesPtr(this.condition), nativeBytesPtr(this.mutex)) != 0 then
        _mutexUnlock(nativeBytesPtr(this.mutex))
        return false
      end if
    end while
    if not this.manualReset then this.signaled = false end if
    _mutexUnlock(nativeBytesPtr(this.mutex))
    return true
  end function

  /// Poll for a signal until the requested timeout expires.
  /// @param milliseconds Maximum duration in milliseconds.
  function waitFor(milliseconds)
    if this.closed or typeof(milliseconds) != "int" or milliseconds < 0 or milliseconds > MAX_PORTABLE_TIMEOUT_MS then return false end if
    elapsed = 0
    while elapsed <= milliseconds
      _mutexLock(nativeBytesPtr(this.mutex))
      ready = this.signaled
      if ready and not this.manualReset then this.signaled = false end if
      _mutexUnlock(nativeBytesPtr(this.mutex))
      if ready then return true end if
      if elapsed == milliseconds then return false end if
      _sleepMicros(1000)
      elapsed = elapsed + 1
    end while
    return false
  end function

  /// Implements try wait.
  function tryWait() return this.waitFor(0) end function

  /// Updates set.
  function set()
    if this.closed then return false end if
    _mutexLock(nativeBytesPtr(this.mutex))
    this.signaled = true
    result = 0
    if this.manualReset then
      result = _condBroadcast(nativeBytesPtr(this.condition))
    else
      result = _condSignal(nativeBytesPtr(this.condition))
    end if
    _mutexUnlock(nativeBytesPtr(this.mutex))
    return result == 0
  end function

  /// Releases or resets reset.
  function reset()
    if this.closed then return false end if
    _mutexLock(nativeBytesPtr(this.mutex))
    this.signaled = false
    _mutexUnlock(nativeBytesPtr(this.mutex))
    return true
  end function

  /// Reports whether this POSIX event has been closed.
  function isClosed() return this.closed end function

  /// Closes this POSIX event after all waiters have stopped.
  function close()
    if this.closed then return false end if
    ok = _condDestroy(nativeBytesPtr(this.condition)) == 0
    if ok then ok = _mutexDestroy(nativeBytesPtr(this.mutex)) == 0 end if
    if ok then
      this.closed = true
      this.mutex = void
      this.condition = void
    end if
    return ok
  end function

  /// Exposes the POSIX event wait through a PascalCase alias.
  function Wait() return this.wait() end function
  /// Exposes the POSIX event timed wait through a PascalCase alias.
  /// @param milliseconds Maximum duration in milliseconds.
  function WaitFor(milliseconds) return this.waitFor(milliseconds) end function
  /// Implements try wait.
  function TryWait() return this.tryWait() end function
  /// Updates set.
  function Set() return this.set() end function
  /// Releases or resets reset.
  function Reset() return this.reset() end function
  /// Exposes the POSIX event closed state through a PascalCase alias.
  function IsClosed() return this.isClosed() end function
end struct
#endif
