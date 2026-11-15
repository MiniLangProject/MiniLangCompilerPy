"""Output-platform policy shared by ELF emission and the compiler driver."""

ELF_TARGETS = ('linux-x64', 'minux-x64')


def is_elf_target(target: str) -> bool:
    """Whether an output platform uses the shared ELF/SysV backend."""
    return target in ELF_TARGETS


def elf_image_base(target: str) -> int:
    """Return the fixed userspace load address required by the target OS."""
    if target == 'linux-x64':
        return 0x400000
    if target == 'minux-x64':
        return 0x100000000
    raise ValueError(f'unsupported ELF target: {target}')


def elf_interpreter(target: str) -> bytes:
    """Return the target's NUL-terminated ELF interpreter pathname."""
    elf_image_base(target)  # Validate even when selecting the default loader.
    return (b'/lib/ld-minux.so\0' if target == 'minux-x64'
            else b'/lib64/ld-linux-x86-64.so.2\0')
