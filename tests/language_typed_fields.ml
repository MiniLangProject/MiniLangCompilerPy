namespace fieldTypes
  struct Label
    text
  end struct
  struct Counter
    value as int,
    label as Label?
  end struct
end namespace

class Meter
  public reading as int = 1
  private history as array<int> = array<int>([1])

  function replaceHistory(nextHistory)
    this.history = nextHistory
  end function

  function firstReading() returns int
    return this.history[0]
  end function
end class

class DigitalMeter extends Meter
end class

function setValue(counter, value)
  counter.value = value
end function

function setLabel(counter, value)
  counter.label = value
end function

function setReading(meter, value)
  meter.reading = value
end function

function localScalar(nextValue)
  counter = fieldTypes.Counter(1, void)
  counter.value = nextValue
  return counter.value
end function

function isContractError(result)
  return typeof(result) == "error" and result.code == 1308
end function

function main(args)
  counter = fieldTypes.Counter(4, void)
  aliasCounter = counter
  setValue(aliasCounter, 9)
  if not isContractError(try(setValue(aliasCounter, "bad"))) or counter.value != 9 then return 1 end if
  setLabel(counter, fieldTypes.Label("ok"))
  if not isContractError(try(setLabel(counter, 2))) or counter.label.text != "ok" then return 2 end if
  setLabel(counter, void)
  if counter.label != void then return 3 end if
  if localScalar(8) != 8 or not isContractError(try(localScalar("bad"))) then return 4 end if
  constructor = fieldTypes.Counter
  if constructor(7, void).value != 7 then return 5 end if
  if not isContractError(try(constructor("bad", void))) then return 6 end if
  if not isContractError(try(fieldTypes.Counter("bad", void))) then return 7 end if
  meter = DigitalMeter()
  setReading(meter, 3)
  if not isContractError(try(setReading(meter, "bad"))) or meter.reading != 3 then return 8 end if
  meter.replaceHistory(array<int>([9]))
  if not isContractError(try(meter.replaceHistory([2]))) or meter.firstReading() != 9 then return 9 end if
  print "TYPED FIELDS [OK]"
  return 0
end function
