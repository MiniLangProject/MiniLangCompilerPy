lazy iterator function invalidLazyIterator()
  synchronized(1)
    yield 1
  end synchronized
end function

