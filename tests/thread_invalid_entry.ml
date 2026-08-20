function worker(first, second)
  return first + second
end function

t = Thread(worker)
