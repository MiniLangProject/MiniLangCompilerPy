/*
   Copyright 2026 Nils Kopal
   Licensed under the Apache License, Version 2.0.
*/

package std.concurrent.channel

import std.threading as threading

const CHANNEL_ERROR = 1652
const CHANNEL_POLL_MILLISECONDS = 1

// A receive result distinguishes a closed/drained channel from a valid void.
struct ChannelReceive
  received
  value
end struct

// Private bounded FIFO. All state is protected by one native lock, so the
// capacity check and ring mutation form one atomic operation.
struct BoundedQueue
  guard
  closedEvent
  slots
  items
  buffer
  voidFlags
  capacity
  head
  tail
  size
  closed

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

  function countValue()
    if not this.guard.acquire() then return 0 end if
    value = this.size
    this.guard.release()
    return value
  end function

  function isSealed()
    return this.closedEvent.tryWait()
  end function

  function seal()
    if this.closed or not this.guard.acquire() then return false end if
    if this.closedEvent.tryWait() then this.guard.release(); return false end if
    ok = this.closedEvent.set()
    this.guard.release()
    return ok
  end function

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

// Bounded multi-producer/multi-consumer FIFO. Waiting always happens outside
// the short queue lock, so a full producer cannot prevent a consumer from
// freeing space and close remains observable by blocked operations.
struct Channel
  queue
  disposed

  static function new(capacity)
    if typeof(capacity) != "int" or capacity <= 0 then
      return error(CHANNEL_ERROR, "channel capacity must be a positive integer")
    end if
    return Channel(BoundedQueue.new(capacity), false)
  end function

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

  function send(value) return this.sendFor(value, -1) end function
  function trySend(value) return this.sendFor(value, 0) end function

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

  function receive() return this.receiveFor(-1) end function
  function tryReceive() return this.receiveFor(0) end function
  function countValue()
    if this.disposed then return 0 end if
    return this.queue.countValue()
  end function
  function close()
    if this.disposed then return false end if
    return this.queue.seal()
  end function

  // Dispose only after every blocked caller has returned and the queue drained.
  function dispose()
    if this.disposed then return false end if
    if not this.queue.dispose() then return false end if
    this.disposed = true
    return true
  end function

  function Send(value) return this.send(value) end function
  function SendFor(value, milliseconds) return this.sendFor(value, milliseconds) end function
  function TrySend(value) return this.trySend(value) end function
  function Receive() return this.receive() end function
  function ReceiveFor(milliseconds) return this.receiveFor(milliseconds) end function
  function TryReceive() return this.tryReceive() end function
  function Count() return this.countValue() end function
  // PascalCase Close is reserved by the native Thread API.
  function Dispose() return this.dispose() end function
end struct
