// Keep literal and comment examples opaque: a=[1,-2], f (x), and(y), return - x.
function pair(left,right)
return[left,right]
end function

function negate(value)
return-value
end function

function grouped(value)
return(value)
end function

iterator function signedValues()
yield-1
yield+2
yield~0
end function

async function asyncValue() returns int
return-3
end function

function main(args)
items=[1,-2,+3,~4]
rows=[[1,2],[-3,+4]]
first=items [0]
selected=rows [1] [0]
called=pair ( -1 , +2 )
chained=pair(1,-2) [1]
groupIndex=(items) [0]
literalIndex=[1,2] [1]
letter="ab" [1]
groupedValue=(first+(+2))
secondGroup=pair(1,(2+3))
nestedArgs=pair([1],[-2])
awaited=await(asyncValue())
logic=(true)and(false)or(not(false))
notFalse=not(false)
quotient=8 div(3)
negative=-first
positive=+first
flipped=~first
commaSigns=pair(-first,+first)
subtract=5- -first
doubleNegative=- -first
doublePositive=+ +first
doubleNot=~ ~first
mixedSigns=+ - +first
mixedNot=~ -first
negatedGroup=~(-first)
commaChains=pair(- -first,~ ~first)
groupedChains=(- -first)+(+ +first)
transform=function(value)=>-value
sum=0
for i=-2 to -1
sum=sum+i
end for
for each value in[1,-2]
sum=sum+value
end for
if -first==-1 then sum=sum+1 end if
if true then negative=-first end if
pulled=signedValues()
literal="a=[1,-2]; f (x); and(y); return - x; --x"
if len(items)!=4 or items[1]!=-2 or items[2]!=3 or items[3]!=-5 then return 1 end if
if selected!=-3 or called[0]!=-1 or called[1]!=2 or chained!=-2 then return 2 end if
if groupIndex!=1 or literalIndex!=2 or letter!="b" or nestedArgs[0][0]!=1 or nestedArgs[1][0]!=-2 then return 3 end if
if groupedValue!=3 or secondGroup[1]!=5 or grouped(7)!=7 or awaited!=-3 then return 4 end if
if not logic or not notFalse or quotient!=2 then return 5 end if
if negative!=-1 or positive!=1 or flipped!=-2 or negate(2)!=-2 then return 6 end if
if commaSigns[0]!=-1 or commaSigns[1]!=1 or subtract!=6 then return 7 end if
if doubleNegative!=1 or doublePositive!=1 or doubleNot!=1 or mixedSigns!=-1 then return 8 end if
if mixedNot!=0 or negatedGroup!=0 or commaChains[0]!=1 or commaChains[1]!=1 then return 9 end if
if groupedChains!=2 or transform(3)!=-3 or sum!=-3 then return 10 end if
if pulled[0]!=-1 or pulled[1]!=2 or pulled[2]!=-1 then return 11 end if
if literal!="a=[1,-2]; f (x); and(y); return - x; --x" then return 12 end if
print(-1)
print[1,-2]
print-negative
print "[OK] formatter spacing"
return 0
end function
