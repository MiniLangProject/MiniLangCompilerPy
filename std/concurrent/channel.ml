/*
   Copyright 2026 Nils Kopal
   Licensed under the Apache License, Version 2.0.
*/

//! Provides the std concurrent channel package.

package std.concurrent.channel

import std.threading as threading

/// Stores the channel error.
const CHANNEL_ERROR = 1652
/// Stores the channel poll milliseconds.
const CHANNEL_POLL_MILLISECONDS = 1

/// A receive result distinguishes a closed/drained channel from a valid void.
struct ChannelReceive
  /// Stores the received member of `ChannelReceive`.
  received
  /// Stores the value member of `ChannelReceive`.
  value
end struct

/// Private bounded FIFO. All state is protected by one native lock, so the capacity check and ring mutation form one atomic operation.
struct BoundedQueue
  /// Stores the guard member of `BoundedQueue`.
  guard
  /// Stores the closed event member of `BoundedQueue`.
  closedEvent
  /// Stores the slots member of `BoundedQueue`.
  slots
  /// Stores the items member of `BoundedQueue`.
  items
  /// Stores the buffer member of `BoundedQueue`.
  buffer
  /// Stores the void flags member of `BoundedQueue`.
  voidFlags
  /// Stores the capacity member of `BoundedQueue`.
  capacity
  /// Stores the head member of `BoundedQueue`.
  head
  /// Stores the tail member of `BoundedQueue`.
  tail
  /// Stores the size member of `BoundedQueue`.
  size
  /// Stores the closed member of `BoundedQueue`.
  closed

  /// Creates the bounded queue backing a channel.
  /// @param capacity Value supplied for `capacity`.
  static function new(capacity)
    return BoundedQueue(
      threading.Lock.new(),
      threading.Event.new(true, false),
      threading.Semaphore.new(capacity, capacity),
      threading.Semaphore.new(0, capacity),
      array(capacity, false),
      array(capacity, false),
      capacity,
      0,
      0,
      0,
      false
    )
  end function

  /// Implements try put.
  /// @param value Value to process.
  function tryPut(value)
    if this.closedEvent.tryWait() or not this.slots.tryAcquire() then return false end if
    if not this.guard.acquire() then this.slots.release(); return false end if
    if this.closedEvent.tryWait() then
      this.guard.release()
      this.slots.release()
      return false
    end if
    if typeof(value) == "void" then
      this.buffer[this.tail] = false
      this.voidFlags[this.tail] = true
    else
      this.buffer[this.tail] = value
      this.voidFlags[this.tail] = false
    end if
    this.tail = this.tail + 1
    if this.tail == this.capacity then this.tail = 0 end if
    this.size = this.size + 1
    this.guard.release()
    return this.items.release()
  end function

  /// Implements try take.
  function tryTake()
    if not this.items.tryAcquire() then return ChannelReceive(false, void) end if
    if not this.guard.acquire() then this.items.release(); return ChannelReceive(false, void) end if
    value = this.buffer[this.head]
    wasVoid = this.voidFlags[this.head]
    // Remove the managed reference immediately so consumed values can be GC'd.
    this.buffer[this.head] = false
    this.voidFlags[this.head] = false
    this.head = this.head + 1
    if this.head == this.capacity then this.head = 0 end if
    this.size = this.size - 1
    this.guard.release()
    this.slots.release()
    if wasVoid then return ChannelReceive(true, void) end if
    return ChannelReceive(true, value)
  end function

  /// Implements count value.
  function countValue()
    if not this.guard.acquire() then return 0 end if
    value = this.size
    this.guard.release()
    return value
  end function

  /// Reports whether is sealed.
  function isSealed()
    return this.closedEvent.tryWait()
  end function

  /// Implements seal.
  function seal()
    if this.closed or not this.guard.acquire() then return false end if
    if this.closedEvent.tryWait() then this.guard.release(); return false end if
    ok = this.closedEvent.set()
    this.guard.release()
    return ok
  end function

  /// Disposes the sealed and drained bounded queue.
  function dispose()
    if this.closed or not this.isSealed() or this.countValue() != 0 then return false end if
    this.closed = true
    itemsOk = this.items.close()
    slotsOk = this.slots.close()
    eventOk = this.closedEvent.close()
    guardOk = this.guard.close()
    return itemsOk and slotsOk and eventOk and guardOk
  end function
end struct

/// Bounded multi-producer/multi-consumer FIFO. Waiting always happens outside the short queue lock, so a full producer cannot prevent a consumer from freeing space and close remains observable by blocked operations.
struct Channel
  /// Stores the queue member of `Channel`.
  queue
  /// Stores the disposed member of `Channel`.
  disposed

  /// Creates a channel with bounded capacity.
  /// @param capacity Value supplied for `capacity`.
  static function new(capacity)
    if typeof(capacity) != "int" or capacity <= 0 then
      return error(CHANNEL_ERROR, "channel capacity must be a positive integer")
    end if
    return Channel(BoundedQueue.new(capacity), false)
  end function

  /// Implements send for.
  /// @param value Value to process.
  /// @param milliseconds Maximum duration in milliseconds.
  function sendFor(value, milliseconds)
    if this.disposed then return false end if
    if typeof(milliseconds) != "int" or milliseconds < -1 then return false end if
    elapsed = 0
    while milliseconds < 0 or elapsed <= milliseconds
      if this.queue.tryPut(value) then return true end if
      if this.queue.isSealed() or elapsed == milliseconds then return false end if
      threadSleep(CHANNEL_POLL_MILLISECONDS)
      elapsed = elapsed + CHANNEL_POLL_MILLISECONDS
    end while
    return false
  end function

  /// Implements send.
  /// @param value Value to process.
  function send(value) return this.sendFor(value, -1) end function
  /// Implements try send.
  /// @param value Value to process.
  function trySend(value) return this.sendFor(value, 0) end function

  /// Waits up to a bounded duration to receive a channel value.
  /// @param milliseconds Maximum duration in milliseconds.
  function receiveFor(milliseconds)
    if this.disposed then return ChannelReceive(false, void) end if
    if typeof(milliseconds) != "int" or milliseconds < -1 then return ChannelReceive(false, void) end if
    elapsed = 0
    while milliseconds < 0 or elapsed <= milliseconds
      result = this.queue.tryTake()
      if result.received then return result end if
      if this.queue.isSealed() or elapsed == milliseconds then return result end if
      threadSleep(CHANNEL_POLL_MILLISECONDS)
      elapsed = elapsed + CHANNEL_POLL_MILLISECONDS
    end while
    return ChannelReceive(false, void)
  end function

  /// Receives the next channel value, waiting when necessary.
  function receive() return this.receiveFor(-1) end function
  /// Implements try receive.
  function tryReceive() return this.receiveFor(0) end function
  /// Implements count value.
  function countValue()
    if this.disposed then return 0 end if
    return this.queue.countValue()
  end function
  /// Closes the channel to new sends.
  function close()
    if this.disposed then return false end if
    return this.queue.seal()
  end function

  /// Dispose only after every blocked caller has returned and the queue drained.
  function dispose()
    if this.disposed then return false end if
    if not this.queue.dispose() then return false end if
    this.disposed = true
    return true
  end function

  /// Implements send.
  /// @param value Value to process.
  function Send(value) return this.send(value) end function
  /// Implements send for.
  /// @param value Value to process.
  /// @param milliseconds Maximum duration in milliseconds.
  function SendFor(value, milliseconds) return this.sendFor(value, milliseconds) end function
  /// Implements try send.
  /// @param value Value to process.
  function TrySend(value) return this.trySend(value) end function
  /// Exposes blocking receive through a PascalCase alias.
  function Receive() return this.receive() end function
  /// Exposes timed receive through a PascalCase alias.
  /// @param milliseconds Maximum duration in milliseconds.
  function ReceiveFor(milliseconds) return this.receiveFor(milliseconds) end function
  /// Implements try receive.
  function TryReceive() return this.tryReceive() end function
  /// Implements count.
  function Count() return this.countValue() end function
  /// PascalCase Close is reserved by the native Thread API.
  function Dispose() return this.dispose() end function
end struct
