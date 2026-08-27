import std.threading as threading

function invalid(lock)
  synchronized(lock)
    break
  end synchronized
end function

function main(args)
  return invalid(threading.Lock.new())
end function
