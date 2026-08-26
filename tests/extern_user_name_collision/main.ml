import tests.extern_user_name_collision.native
import tests.extern_user_name_collision.user as user

function main(args)
  if user.run() != 7 then return 1 end if
  print "extern/user basename collision [OK]"
  return 0
end function

