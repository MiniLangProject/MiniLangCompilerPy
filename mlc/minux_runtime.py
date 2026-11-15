"""MinUX ELF startup, native runtime and eager SysV imports.

MinUX's loader has a global ELF symbol namespace. Unlike the Linux backend,
this target never pretends to provide library-local dlopen/dlsym semantics.
"""
from __future__ import annotations

from typing import Any
from . import minux_blob as blob
from .sysv_runtime import _CORE_IMPORTS, emit_extern_thunks

RUNTIME_IMPORTS = (
    ('__minux_libc_set_environ', 'elfiat_runtime_set_environ'),
    ('calloc', 'elfiat_runtime_calloc'),
    ('free', 'elfiat_runtime_free'),
    ('pthread_create', 'elfiat_runtime_pthread_create'),
    ('pthread_join', 'elfiat_runtime_pthread_join'),
)
PRIVATE_SYMBOLS = ('minux_sem_init', 'minux_sem_wait', 'minux_sem_trywait',
                   'minux_sem_post', 'minux_sem_getvalue', 'minux_sem_destroy', 'minux_executable_path')


def validate_externs(signatures: dict) -> None:
    """Reject imports which MinUX cannot represent before writing output."""
    from .errors import CompileError
    symbols = {}
    libraries = {'libc.so.1'}
    for qname, sig in signatures.items():
        library = str(sig.get('dll', ''))
        symbol = str(sig.get('symbol', '') or qname.split('.')[-1])
        message = ''
        if (not library or library != library.strip() or
                any(char in library for char in '/\\\0')):
            message = 'MinUX imports require an exact library basename'
        elif library in ('libc.so.6', 'libpthread.so.0', 'libdl.so.2', 'libm.so.6'):
            message = f'MinUX does not provide the Linux ABI library {library}; use MinUX libraries (libc.so.1) and native layouts'
        elif library == '__minilang_minux_runtime' and symbol not in PRIVATE_SYMBOLS:
            message = f'unknown private MinUX runtime symbol: {symbol}'
        previous = symbols.setdefault(symbol, library)
        if previous != library:
            message = f'MinUX global ELF namespace cannot disambiguate symbol {symbol} from {previous} and {library}'
        if library != '__minilang_minux_runtime':
            libraries.add(library)
        if len(libraries) > 15:
            message = 'MinUX supports at most 15 dependency libraries per executable'
        if message:
            raise CompileError(f'extern function {qname}: {message}',
                               pos=sig.get('pos'), filename=sig.get('filename'))


def _fragment(cg: Any, data: bytes, labels: list, patches: list) -> None:
    base = len(cg.asm.buf)
    cursor = 0
    for name, offset in labels:
        cg.asm.emit(data[cursor:offset])
        cg.asm.mark(name)
        cursor = offset
    cg.asm.emit(data[cursor:])
    cg.asm.patches.extend((base+offset, name, 'rip32') for offset, name in patches)


def emit_startup(cg: Any) -> None:
    """Bridge ld-minux's SysV argument block to the managed program entry."""
    if "minux_reserve_cursor" not in cg.data.labels:
        cg.data.pad_align(8)
        cg.data.add_u64("minux_reserve_cursor", 0x4000000000)
    if "minux_executable_name" not in cg.data.labels:
        cg.data.pad_align(8)
        cg.data.add_u64("minux_executable_name", 0)
    _fragment(cg, blob.STARTUP, blob.STARTUP_LABELS, blob.STARTUP_PATCHES)
    cg.asm.mark('minux_program_entry')


def dynamic_imports(cg: Any) -> list[tuple[str, str, int]]:
    """Create deterministic eager ELF imports and managed call slots."""
    result = []
    for symbol, label in RUNTIME_IMPORTS:
        if label not in cg.data.labels:
            cg.data.pad_align(8)
            cg.data.add_u64(label, 0)
        result.append(('libc.so.1', symbol, cg.data.labels[label]))
    seen = {}
    for qname, sig in cg.extern_sigs.items():
        library = str(sig.get('dll', ''))
        symbol = str(sig.get('symbol', '') or qname.split('.')[-1])
        if not library or not symbol:
            continue
        previous = seen.setdefault(symbol, library)
        if previous != library:
            raise ValueError(f'MinUX global ELF namespace: symbol {symbol!r} declared by both {previous!r} and {library!r}')
        iat = cg._extern_iat_label(library, symbol)
        slot = f'elfiat_{iat[4:]}'
        if iat not in cg.data.labels:
            cg.data.pad_align(8)
            offset = len(cg.data.data)
            cg.data.add_u64(iat, 0)
            cg.data.add_abs64_patch(offset, f'linux_extern_thunk_{iat[4:]}')
        if slot not in cg.data.labels:
            cg.data.pad_align(8)
            cg.data.add_u64(slot, 0)
            if library == '__minilang_minux_runtime':
                if symbol not in PRIVATE_SYMBOLS:
                    raise ValueError(f'unknown private MinUX runtime symbol: {symbol}')
                cg.data.add_abs64_patch(cg.data.labels[slot], symbol)
        if library == '__minilang_minux_runtime':
            continue
        record = (library, symbol, cg.data.labels[slot])
        if record not in result:
            result.append(record)
    return result


def emit_runtime(cg: Any) -> None:
    """Append the MinUX boundary and shared SysV native-call bridges."""
    for name in _CORE_IMPORTS:
        slot = f'iat_{name}'
        if slot not in cg.data.labels:
            cg.data.pad_align(8)
            offset = len(cg.data.data)
            cg.data.add_u64(slot, 0)
            cg.data.add_abs64_patch(offset, f'minux_{name}')
    dynamic_imports(cg)
    _fragment(cg, blob.RUNTIME, blob.RUNTIME_LABELS, blob.RUNTIME_PATCHES)
    emit_extern_thunks(cg, eager=True)
