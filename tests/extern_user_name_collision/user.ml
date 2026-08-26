package tests.extern_user_name_collision.user

function bind(left, right)
  return left + right
end function

function run()
  return bind(3, 4)
end function

