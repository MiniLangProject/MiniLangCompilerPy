/*
   Copyright 2026 Nils Kopal
   Licensed under the Apache License, Version 2.0.
*/

package std.concurrent.cancellation

import std.threading as threading

const CANCELLED_ERROR = 1650

// Read-only cancellation view passed to cooperative operations. Cancellation
// never terminates an OS thread; code observes the shared request explicitly.
struct CancellationToken
  source

  function isCancellationRequested()
    if typeof(this.source) != "struct" then return false end if
    return this.source.isCancellationRequested()
  end function

  function wait()
    if typeof(this.source) != "struct" then return false end if
    return this.source.wait()
  end function

  function waitFor(milliseconds)
    if typeof(this.source) != "struct" then return false end if
    return this.source.waitFor(milliseconds)
  end function

  // Return a regular error value when cancellation has been requested.
  function check()
    if this.isCancellationRequested() then
      return error(CANCELLED_ERROR, "operation cancelled")
    end if
    return true
  end function

  function IsCancellationRequested() return this.isCancellationRequested() end function
  function Wait() return this.wait() end function
  function WaitFor(milliseconds) return this.waitFor(milliseconds) end function
  function Check() return this.check() end function
end struct

// Owns the native event used to publish one idempotent cancellation request.
struct CancellationTokenSource
  guard
  event
  cancelled
  closed

  static function new()
    return CancellationTokenSource(
      threading.Lock.new(),
      threading.Event.new(true, false),
      false,
      false
    )
  end function

  function token()
    return CancellationToken(this)
  end function

  function cancel()
    if not this.guard.acquire() then return false end if
    if this.closed or this.cancelled then
      this.guard.release()
      return false
    end if
    this.cancelled = true
    // Publish while the source guard is held so Dispose cannot close the
    // native event between the state transition and its wake-up signal.
    published = this.event.set()
    this.guard.release()
    return published
  end function

  function isCancellationRequested()
    if not this.guard.acquire() then return true end if
    value = this.cancelled
    this.guard.release()
    return value
  end function

  function wait()
    if this.closed then return false end if
    return this.event.wait()
  end function

  function waitFor(milliseconds)
    if this.closed then return false end if
    return this.event.waitFor(milliseconds)
  end function

  // Dispose only after all operations using tokens from this source finished.
  function close()
    if not this.guard.acquire() then return false end if
    if this.closed then
      this.guard.release()
      return false
    end if
    this.closed = true
    this.guard.release()
    eventOk = this.event.close()
    guardOk = this.guard.close()
    return eventOk and guardOk
  end function

  function Token() return this.token() end function
  function Cancel() return this.cancel() end function
  function IsCancellationRequested() return this.isCancellationRequested() end function
  function Dispose() return this.close() end function
end struct
