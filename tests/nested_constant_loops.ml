// Adjacent nested loop entries may emit no bytes before the inner label.
// This program uses no threads, so safepoint polls cannot hide that case.
function main(args)
  count = 0
  while true
    while true
      count += 1
      break
    end while
    break
  end while
  if count != 1 then return 1 end if

  count = 0
  loop
    loop
      count += 1
      break
    end loop while false
    break
  end loop while false
  if count != 1 then return 2 end if

  count = 0
  while true
    while true
      count += 1
      if count < 3 then continue end if
      break
    end while
    break
  end while
  if count != 3 then return 3 end if

  outer = 0
  inner = 0
  skipped = 0
  loop
    loop
      inner += 1
      continue
      skipped += 1
    end loop while false
    outer += 1
    continue
    skipped += 1
  end loop while outer < 2
  if outer != 2 or inner != 2 or skipped != 0 then return 4 end if

  print "[OK] nested constant loops"
  return 0
end function
