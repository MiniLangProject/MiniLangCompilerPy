/* Task, channel and fine-grained synchronization throughput benchmark. */

import std.concurrent.channel as channels
import std.concurrent.task as tasks
import std.concurrent.thread_pool as threadPool
import std.threading as threading
import std.time as time

struct ChannelWork
  channel
  count
end struct

struct LockedCounter
  guard
  value
  iterations
end struct

function identity(value)
  return value
end function

function produce(work)
  for i = 0 to work.count - 1
    if not work.channel.Send(i) then return error(1670, "channel send failed") end if
  end for
  return work.count
end function

function consume(work)
  checksum = 0
  for i = 0 to work.count - 1
    item = work.channel.Receive()
    if not item.received then return error(1671, "channel receive failed") end if
    checksum = checksum + item.value
  end for
  return checksum
end function

function incrementLocked(counter)
  for i = 0 to counter.iterations - 1
    synchronized(counter.guard)
      counter.value = counter.value + 1
    end synchronized
  end for
  return counter.iterations
end function

function main(args)
  taskCount = 10000
  messageCount = 250000
  lockWorkers = 4
  lockIterations = 100000

  pool = threadPool.ThreadPool.withQueueCapacity(4, 16384)
  futures = array(taskCount, void)
  started = time.ticks()
  for i = 0 to taskCount - 1
    futures[i] = tasks.run(pool, identity, i)
    if typeof(futures[i]) != "struct" then return 1 end if
  end for
  results = tasks.whenAll(futures)
  taskElapsed = time.ticks() - started
  if len(results) != taskCount or results[taskCount - 1] != taskCount - 1 then return 2 end if
  for i = 0 to taskCount - 1
    if not futures[i].Dispose() then return 3 end if
  end for

  channel = channels.Channel.new(1024)
  work = ChannelWork(channel, messageCount)
  started = time.ticks()
  producer = tasks.run(pool, produce, work)
  consumer = tasks.run(pool, consume, work)
  channelResults = tasks.whenAll([producer, consumer])
  channelElapsed = time.ticks() - started
  expected = ((messageCount - 1) * messageCount) / 2
  if channelResults[0] != messageCount or channelResults[1] != expected then return 4 end if
  if not channel.close() or not producer.Dispose() or not consumer.Dispose() or not channel.Dispose() then return 5 end if

  counter = LockedCounter(threading.Lock.new(), 0, lockIterations)
  lockFutures = array(lockWorkers, void)
  started = time.ticks()
  for i = 0 to lockWorkers - 1
    lockFutures[i] = tasks.run(pool, incrementLocked, counter)
  end for
  lockResults = tasks.whenAll(lockFutures)
  lockElapsed = time.ticks() - started
  if counter.value != lockWorkers * lockIterations or len(lockResults) != lockWorkers then return 6 end if
  for i = 0 to lockWorkers - 1
    if not lockFutures[i].Dispose() then return 7 end if
  end for
  if not counter.guard.close() then return 8 end if

  if not pool.Shutdown() or not pool.AwaitTerminationFor(30000) or not pool.Dispose() then return 9 end if
  print "tasks=" + taskCount + " elapsed_ms=" + taskElapsed
  print "channel_messages=" + messageCount + " elapsed_ms=" + channelElapsed
  print "synchronized_updates=" + (lockWorkers * lockIterations) + " elapsed_ms=" + lockElapsed
  return 0
end function
