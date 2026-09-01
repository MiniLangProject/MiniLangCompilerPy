#if TARGET_OS != "linux"
#error "extern_abi_conflict.ml requires the linux-x64 target"
#endif

extern function labsInt(value as int) from "libc.so.6" symbol "labs" returns int
extern function labsDouble(value as double) from "libc.so.6" symbol "labs" returns double
