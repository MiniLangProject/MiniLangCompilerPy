package tests.extern_user_name_collision.native

// A qualified native symbol may share its basename with an unrelated user
// function in another package without changing that user call's arity.
#if TARGET_OS == "windows"
extern function bind(socket as ptr, address as bytes, length as i32) from "ws2_32.dll" returns i32
#else
extern function bind(socket as int, address as bytes, length as u32) from "libc.so.6" returns i32
#endif

