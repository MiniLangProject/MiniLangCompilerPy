/*
   Copyright 2026 Nils Kopal
   Licensed under the Apache License, Version 2.0.
*/

//! Provides the std concurrent cancellation package.

package std.concurrent.cancellation

import std.threading as threading

/// Stores the cancelled error.
const CANCELLED_ERROR = 1650

/// Read-only cancellation view passed to cooperative operations. Cancellation never terminates an OS thread; code observes the shared request explicitly.
struct CancellationToken
  /// Stores the source member of `CancellationToken`.
  source

  /// Reports whether cancellation was requested for this token.
  function isCancellationRequested()
    if typeof(this.source) != "struct" then return false end if
    return this.source.isCancellationRequested()
  end function

  /// Blocks until cancellation is requested for this token.
  function wait()
    if typeof(this.source) != "struct" then return false end if
    return this.source.wait()
  end function

  /// Waits up to a bounded duration for this token to be cancelled.
  /// @param milliseconds Maximum duration in milliseconds.
  function waitFor(milliseconds)
    if typeof(this.source) != "struct" then return false end if
    return this.source.waitFor(milliseconds)
  end function

  /// Return a regular error value when cancellation has been requested.
  function check()
    if this.isCancellationRequested() then
      return error(CANCELLED_ERROR, "operation cancelled")
    end if
    return true
  end function

  /// Exposes the token cancellation state through a PascalCase alias.
  function IsCancellationRequested() return this.isCancellationRequested() end function
  /// Exposes the token wait operation through a PascalCase alias.
  function Wait() return this.wait() end function
  /// Exposes the timed token wait through a PascalCase alias.
  /// @param milliseconds Maximum duration in milliseconds.
  function WaitFor(milliseconds) return this.waitFor(milliseconds) end function
  /// Implements check.
  function Check() return this.check() end function
end struct

/// Owns the native event used to publish one idempotent cancellation request.
struct CancellationTokenSource
  /// Stores the guard member of `CancellationTokenSource`.
  guard
  /// Stores the event member of `CancellationTokenSource`.
  event
  /// Stores the cancelled member of `CancellationTokenSource`.
  cancelled
  /// Stores the closed member of `CancellationTokenSource`.
  closed

  /// Creates a cancellation token source.
  static function new()
    return CancellationTokenSource(
      threading.Lock.new(),
      threading.Event.new(true, false),
      false,
      false
    )
  end function

  /// Converts token.
  function token()
    return CancellationToken(this)
  end function

  /// Requests cancellation from this source.
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

  /// Reports whether this source has requested cancellation.
  function isCancellationRequested()
    if not this.guard.acquire() then return true end if
    value = this.cancelled
    this.guard.release()
    return value
  end function

  /// Blocks until this source requests cancellation.
  function wait()
    if this.closed then return false end if
    return this.event.wait()
  end function

  /// Waits up to a bounded duration for this source to request cancellation.
  /// @param milliseconds Maximum duration in milliseconds.
  function waitFor(milliseconds)
    if this.closed then return false end if
    return this.event.waitFor(milliseconds)
  end function

  /// Dispose only after all operations using tokens from this source finished.
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

  /// Converts token.
  function Token() return this.token() end function
  /// Exposes source cancellation through a PascalCase alias.
  function Cancel() return this.cancel() end function
  /// Exposes the source cancellation state through a PascalCase alias.
  function IsCancellationRequested() return this.isCancellationRequested() end function
  /// Closes this cancellation source through its PascalCase alias.
  function Dispose() return this.close() end function
end struct
