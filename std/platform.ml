/*
Copyright 2026 Nils Kopal

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Compile-time target information exposed through a small runtime API.  The
// values describe the selected output target, not the host running the compiler.
//! Provides the std platform package.

package std.platform

/// Implements operating system.
function operatingSystem()
#if TARGET_OS == "windows"
  return "windows"
#else
  return "linux"
#endif
end function

/// Implements architecture.
function architecture()
  return "x64"
end function

/// Reports whether is windows.
function isWindows()
#if TARGET_OS == "windows"
  return true
#else
  return false
#endif
end function

/// Reports whether is linux.
function isLinux()
#if TARGET_OS == "linux"
  return true
#else
  return false
#endif
end function

/// Implements path separator.
function pathSeparator()
#if TARGET_OS == "windows"
  return "\\"
#else
  return "/"
#endif
end function

/// Implements line ending.
function lineEnding()
#if TARGET_OS == "windows"
  return "\r\n"
#else
  return "\n"
#endif
end function

/// Implements executable extension.
function executableExtension()
#if TARGET_OS == "windows"
  return ".exe"
#else
  return ""
#endif
end function

/// Implements dynamic library extension.
function dynamicLibraryExtension()
#if TARGET_OS == "windows"
  return ".dll"
#else
  return ".so"
#endif
end function
