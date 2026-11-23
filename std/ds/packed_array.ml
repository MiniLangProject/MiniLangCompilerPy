// Copyright 2026 Nils Kopal. Licensed under the Apache License, Version 2.0.
//! Fixed-size arrays with compact native cell storage.

namespace std.ds.packed_array

  /// A fixed-size sequence of signed 32-bit integers with four bytes per cell.
  /// Use external synchronization when several threads write to a shared instance.
  class Int32Array
    private data as bytes = bytes(0)

    /// Allocate a zero-filled sequence.
    /// @param size Number of elements in the sequence.
    function init(size as int)
      var length as int = size
      if length < 0 or length > 0x1fffffff then
        return error(1307, "Invalid Int32Array length")
      end if
      this.data = bytes(length * 4)
    end function

    /// Return the number of elements.
    /// @returns Number of cells in the sequence.
    function len() returns int
      return len(this.data) >> 2
    end function

    /// Read a signed integer from a checked index.
    /// @param index Zero-based index, or an index relative to the end when negative.
    /// @returns The signed integer stored at the checked index.
    function inline get(index as int) returns int
      return __ml_packed_i32_get(this.data, index)
    end function

    /// Replace a cell with a signed 32-bit integer.
    /// @param index Zero-based index, or an index relative to the end when negative.
    /// @param value Value in the signed 32-bit range.
    function inline set(index as int, value as int)
      return __ml_packed_i32_set(this.data, index, value)
    end function
  end class
end namespace
