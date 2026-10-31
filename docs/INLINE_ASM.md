# Typed inline x64 assembly

MiniLang accepts an `asm x64` expression inside a function or at module scope.
Operands are existing variable names. The compiler evaluates and checks them
before the block, assigns temporary machine registers for each instruction, and
converts `result` back to the declared MiniLang type. The block is emitted at
the call site; it does not call an external assembler or linker.

```ml
function inline trailingZeros(x as int) returns int
  if x == 0 then return -1 end if
  return asm x64(in x as int) returns int
    bsf result, x
  end asm
end function
```

The header accepts up to 24 operands, each `in name as Type` or
`inout name as Type`. `returns Type` is optional and defaults to `void`.
It also accepts zero-initialized `scratch name as int`, `bool` or `float` operands. Scratch values
exist only inside the block and are not written back to MiniLang variables.
An expression with a non-`void` result must assign `result` before reading it.
An `inout` operand may be assigned by assembly and is written back to its
MiniLang variable after the block. Instruction names and symbolic operands are
case-sensitive. Operand types use normal MiniLang contracts, including named
structs/enums, optional types (`T?`), and `unknown`.

| Type | Machine operand inside the block |
| --- | --- |
| `int`, `bool` | Unboxed integer, with `bool` normalized to 0 or 1 |
| `float` | Raw 64-bit double, loaded into compiler-managed XMM registers |
| `string`, `bytes`, `array`, `function`, `thread`, `error`, named structs/enums | Opaque, rooted MiniLang value |
| `T?`, `unknown` | Opaque, tagged MiniLang value; can also carry `void` |
| `void` | Opaque `void` input; a `void` result has no `result` operand |

An opaque value can be moved or conditionally selected between operands of
the same declared type. It cannot be forged or treated as a raw object pointer.
An `error` input or output follows MiniLang's ordinary automatic propagation;
wrap a call in `try(...)` when the error value is intentional.

Supported instructions use **symbolic operands**, not physical register names:

- Integer: `mov`, `add`, `sub`, `imul`, `xor`, `and`, `or`, `shl`, `shr`, `sar`, `rol`, `ror`, `bsf`, `popcnt`
- Comparison/selection: `test`, `cmp`, `cmovz`, `cmovnz`, `setz`/`sete`, `setnz`/`setne`, `setl`, `setle`, `setg`, `setge`, `setb`, `setbe`, `seta`, `setae`
- Double: `movsd`, `addsd`, `subsd`, `mulsd`, `divsd`
- Byte read: `movzx destination, byte [buffer.data + index]` in `asm unsafe x64`
- 32-bit read/write: `mov destination, dword [buffer.data + index]` and
  `mov dword [buffer.data + index], value` in `asm unsafe x64`
- Local control flow: `label`, `jmp`, `jz`/`je`, `jnz`/`jne`, `jl`, `jle`,
  `jg`, `jge`, `jb`, `jbe`, `ja`, `jae`

Arithmetic and comparison instructions take two operands; `label`, jumps and
`setcc` take one operand. Conditional jumps and `setcc` must immediately follow
`cmp` or `test`. The compiler checks that `result` is initialized on every
reachable exit, including paths through labels and jumps. All jump targets must
be declared exactly once in the same block. Backward jump targets include a
cooperative GC poll. Up to two integer operands are kept in registers within a
block, with synchronized stack slots for safepoints and output conversion.

```ml
return asm x64(in n as int, scratch i as int) returns int
  mov result, 0
  mov i, 0
  label scan
  cmp i, n
  jge done
  add result, i
  add i, 1
  jmp scan
  label done
end asm
```

Shift and rotate counts are immediates
from 0 through 63. `mov` and `cmov*` require compatible operand types. Raw
register names, external jumps, calls, stack instructions, arbitrary memory operands,
and new object allocation are not part of this interface. The compiler owns
register allocation, GC roots, and MiniLang value tagging.
`popcnt` counts set bits in the 64-bit integer representation. It currently
uses a bounded portable lowering, so it does not require the CPU POPCNT feature.

For a direct mutable-byte write, use the explicit `unsafe` form:

```ml
function setByte(buffer as bytes, index as int, value as int) returns void
  asm unsafe x64(inout buffer as bytes, in index as int, in value as int)
    mov byte [buffer.data + index], value
  end asm
end function
```

`buffer.data` is the start of the byte payload and remains rooted during the
block. `unsafe` does **not** check `index` against `len(buffer)` or `value`
against `0..255`; the instruction writes the low byte. Check both in MiniLang
before entering the block. Direct stores into arrays and struct fields are
excluded because they may require GC write barriers.

`movzx destination, byte [buffer.data + index]` reads an unsigned byte into an
`int` destination. The buffer may be an `in bytes` operand. The caller must
ensure `0 <= index < len(buffer)`; `unsafe` does not insert a bounds check.

`dword` access reads or writes four bytes in little-endian order. A read
zero-extends to an `int`; a write uses the low 32 bits of an `int`. Stores
require an `inout bytes` operand. The caller must ensure
`0 <= index` and `index + 4 <= len(buffer)`.

`--asm` still writes a diagnostic listing of the generated machine code.
The focused runtime fixtures are `tests/inline_asm.ml` and
`tests/inline_asm_types.ml`.
