/* declaration comment */ function commentedHeader()
value=0
if true then /* conditional comment */
value=2
else value=99 end if
if true then /* multiline control header
 * end if // comment text
 */
value=value+1
end if
/* multiline comment before a control header
 * function ignored()
 */ if true then
value=value+1
end if
return value
end function

function nestedElse()
value=0
if false then
value=99
else value=1 if true then value=value+1 end if
value=value+1
end if
return value
end function

function main(args)
s = "hello
world"
payload = "  leading and trailing  
\"end if\" // not a comment



/* function fake() */  
	keep this tab and two spaces  
backslash \\
  tail  " + " // extra quoted string"
if len(s)!=11 then return 1 end if
if commentedHeader()!=4 then return 2 end if
if nestedElse()!=3 then return 3 end if
print len(s)
print payload
print "[OK] formatter lexical edges"
return 0
end function
