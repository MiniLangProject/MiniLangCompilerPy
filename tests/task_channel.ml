import std.concurrent.channel as channels
import std.concurrent.task as tasks
import std.concurrent.thread_pool as threadPool
import std.threading as threading

function square(value)
  return value * value
end function

function cancellableLoop(data, token)
  while not token.IsCancellationRequested()
    threadSleep(1)
  end while
  return token.Check()
end function

function waitOnEvent(event)
  if not event.WaitFor(10000) then return error(1655, "event wait timed out") end if
  return 77
end function

struct ChannelWork
  channel
  count
end struct

function produce(work)
  i = 0
  while i < work.count
    if not work.channel.SendFor(i, 1000) then return error(1653, "producer send failed") end if
    i = i + 1
  end while
  return work.count
end function

function consume(work)
  total = 0
  i = 0
  while i < work.count
    item = work.channel.ReceiveFor(1000)
    if not item.received then return error(1654, "consumer receive failed") end if
    total = total + item.value
    i = i + 1
  end while
  return total
end function

function main(args)
  pool = threadPool.ThreadPool.withQueueCapacity(4, 32)
  futures = []
  i = 0
  while i < 12
    future = tasks.run(pool, square, i)
    if typeof(future) != "struct" then return 1 end if
    futures = futures + [future]
    i = i + 1
  end while

  first = tasks.whenAnyFor(futures, 10000)
  if typeof(first) != "int" or first < 0 or first >= len(futures) then return 2 end if
  results = tasks.whenAll(futures)
  if typeof(results) != "array" or len(results) != 12 then return 3 end if
  i = 0
  while i < len(results)
    if results[i] != i * i then return 4 end if
    if not futures[i].Dispose() then return 5 end if
    i = i + 1
  end while

  cancelled = tasks.runCancellable(pool, cancellableLoop, 0)
  if typeof(cancelled) != "struct" then return 6 end if
  threadSleep(10)
  if not cancelled.Cancel() or not cancelled.WaitFor(10000) then return 7 end if
  if cancelled.status() != "Failed" then return 8 end if
  cancelledResult = try(cancelled.result())
  if typeof(cancelledResult) != "error" or cancelledResult.code != 1650 then return 9 end if
  if not cancelled.Dispose() then return 10 end if

  if not pool.Shutdown() or not pool.AwaitTerminationFor(10000) or not pool.Dispose() then return 20 end if
  channelPool = threadPool.ThreadPool.withQueueCapacity(2, 8)

  channel = channels.Channel.new(3)
  if typeof(channel) != "struct" then return 11 end if
  work = ChannelWork(channel, 100)
  producer = tasks.run(channelPool, produce, work)
  consumer = tasks.run(channelPool, consume, work)
  if typeof(producer) != "struct" or typeof(consumer) != "struct" then return 12 end if
  channelResults = tasks.whenAll([producer, consumer])
  if channelResults[0] != 100 or channelResults[1] != 4950 then return 13 end if
  if channel.Count() != 0 then return 14 end if
  if not channel.close() or channel.Send(1) then return 15 end if
  drained = channel.ReceiveFor(0)
  if drained.received then return 16 end if
  if not producer.Dispose() or not consumer.Dispose() or not channel.Dispose() then return 17 end if

  invalidChannel = try(channels.Channel.new(0))
  if typeof(invalidChannel) != "error" or invalidChannel.code != 1652 then return 21 end if
  edgeChannel = channels.Channel.new(2)
  if not edgeChannel.TrySend(void) or not edgeChannel.TrySend("last") then return 22 end if
  if edgeChannel.TrySend(3) or edgeChannel.Count() != 2 then return 23 end if
  if not edgeChannel.close() or edgeChannel.close() or edgeChannel.Send(4) then return 24 end if
  edgeFirst = edgeChannel.ReceiveFor(0)
  edgeSecond = edgeChannel.ReceiveFor(0)
  edgeEnd = edgeChannel.ReceiveFor(0)
  if not edgeFirst.received or typeof(edgeFirst.value) != "void" then return 25 end if
  if not edgeSecond.received or edgeSecond.value != "last" or edgeEnd.received then return 26 end if
  if not edgeChannel.Dispose() then return 27 end if
  disposedReceive = edgeChannel.ReceiveFor(0)
  if edgeChannel.Send(5) or edgeChannel.close() or edgeChannel.Count() != 0 or disposedReceive.received then return 35 end if

  if not channelPool.Shutdown() or not channelPool.AwaitTerminationFor(10000) then return 18 end if
  if not channelPool.Dispose() then return 19 end if

  cancelPool = threadPool.ThreadPool.withQueueCapacity(1, 4)
  gate = threading.Event.new(true, false)
  blocker = tasks.run(cancelPool, waitOnEvent, gate)
  queued = tasks.runCancellable(cancelPool, cancellableLoop, 0)
  if tasks.whenAnyFor([blocker], 0) != -1 then return 28 end if
  if not queued.Cancel() or not queued.WaitFor(10000) or queued.status() != "Cancelled" then return 29 end if
  if typeof(queued.result()) != "void" or not queued.Dispose() then return 30 end if
  if not gate.Set() or not blocker.WaitFor(10000) or blocker.result() != 77 then return 31 end if
  if not blocker.Dispose() then return 32 end if
  if not cancelPool.Shutdown() or not cancelPool.AwaitTerminationFor(10000) then return 33 end if
  if not cancelPool.Dispose() or not gate.close() then return 34 end if
  print "[OK] tasks, futures, cancellation and bounded channels"
  return 0
end function
