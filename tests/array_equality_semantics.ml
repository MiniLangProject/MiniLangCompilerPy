// A bounded truth table freezes existing leaf, identity and NaN behavior.
// Compare output with the preceding compiler; this fixture has no wide arrays
// or cyclic graphs whose previously broken results are intentionally changed.
#if TARGET_OS == "windows"
extern function nativeSqrt(value as double) from "msvcrt.dll" symbol "sqrt" returns double
#else
extern function nativeSqrt(value as double) from "libm.so.6" symbol "sqrt" returns double
#endif
struct IdentityOnly
  value
end struct
enum Token
  first
  second
end enum
function main(args)
  shared=IdentityOnly(7) sharedBytes=bytes(3,41)
  boxedNaN=nativeSqrt(-1.0)
  immediateNaN=nativeValueFromRaw((2143289344<<3)|5)
  otherNaN=nativeValueFromRaw((2143289345<<3)|5)
  values=[void,false,true,0,1,-1,0.5,-0.0,0.0,"a","a"+"b","ab",shared,IdentityOnly(7),sharedBytes,bytes(3,41),Token.first,Token.second,boxedNaN,nativeSqrt(-1.0),immediateNaN,otherNaN]
  count=0 checksum=17
  for i=0 to len(values)-1
    for j=0 to len(values)-1
      left=[values[i],i%3] right=[values[j],i%3]
      matched=left==right
      if matched then count=count+1 checksum=(checksum*31+i*23+j)%1000000007 end if
      if (left!=right)==matched then return 1 end if
    end for
  end for
  print "ARRAY EQUALITY SEMANTICS comparisons="+(len(values)*len(values))+" true="+count+" checksum="+checksum
  return 0
end function
