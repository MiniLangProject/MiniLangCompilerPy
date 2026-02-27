"""
Memory-related codegen mixin.

This module owns the *low-level* heap / GC machinery in the backend:
- heap init + allocator (fn_alloc)
- GC globals + shadow-stack root frames
- mark/sweep GC (fn_gc_collect)
- optional refcount stubs (currently disabled)

Allocation-using language builtins were split out into:
- codegen_builtins_alloc.py (CodegenBuiltinsAlloc)
  (input, box_float, value_to_string, string/array concatenation)
"""

from __future__ import annotations

from ..constants import (GC_HEADER_SIZE, GC_OFF_BLOCK_SIZE, GC_OFF_NEXT_FREE, OBJ_ARRAY, OBJ_BOX, OBJ_ENV, OBJ_FREE,
                         OBJ_FUNCTION, OBJ_STRUCT, )
from ..tools import align_up, enc_void

# ============================================================
# Memory / GC tuning knobs (edit these)
# ============================================================
# Windows memory granularity
MEM_PAGE_SIZE = 0x1000  # 4 KiB
MEM_RESERVE_GRANULARITY = 0x10000  # 64 KiB (VirtualAlloc allocation granularity)

# Heap sizing (bump allocator: one fixed allocation; no grow / no GC)
HEAP_SIZE_DEFAULT = 0x02000000  # 32 MiB fixed heap (reserved+committed)
# Backward-compatible aliases (some code paths may still reference these names)
HEAP_COMMIT_DEFAULT = HEAP_SIZE_DEFAULT
HEAP_RESERVE_DEFAULT = 0x80000000  # 2 GiB default reserve (cheap on 64-bit)
HEAP_RESERVE_MIN = HEAP_SIZE_DEFAULT

# Heap growth (commits are page-based; min step avoids too many VirtualAlloc calls)
HEAP_GROW_MIN = 0x01000000  # 16 MiB

# Allocator / free-list
ALLOC_MIN_SPLIT = 32  # smallest remainder block when splitting free blocks (bytes)

# GC
GC_MARK_STACK_QWORDS = 1048576  # 1048576*8 = 8 MiB mark stack (prevents overflow on large graphs)
GC_DEFAULT_BYTES_LIMIT = 64 << 20  # 64 MiB periodic GC trigger (if enabled)
GC_DISABLE_PERIODIC_LIMIT = 0x7FFFFFFFFFFFFFFF

# NOTE on refcount helpers:
# This file currently implements a mark/sweep GC header layout:
#   [header+0]  u64 block_size
#   [header+8]  u64 mark (0/1)
#   [header+16] u64 next_free
# There is no refcount field. Therefore incref/decref would corrupt mark bits unless
# you redesign the header. Keep this disabled unless you implement a compatible layout.
MEMORY_ENABLE_REFCOUNT = False


class CodegenMemory:
    """Codegen mixin for low-level heap allocation and mark/sweep GC.

    This module emits the allocator, heap grow/shrink support, and the collector
    itself. Higher-level language builtins that allocate (e.g. input(),
    value_to_string, concatenation helpers) are implemented in
    ``codegen_builtins_alloc.py``.
    """

    # ------------------------------------------------------------------
    # Heap init (VirtualAlloc reserve+commit)
    # ------------------------------------------------------------------

    def emit_heap_init(self, heap_size: int = HEAP_SIZE_DEFAULT) -> None:
        """
        Emit heap initialization for the native runtime.

        design (reserve + commit separated):
        - Reserve a large address range once:
            VirtualAlloc(NULL, reserve_bytes, MEM_RESERVE, PAGE_READWRITE)
        - Commit an initial subset:
            VirtualAlloc(base, commit_bytes, MEM_COMMIT, PAGE_READWRITE)

        Heap globals in .data:
        - heap_base        = reserved base
        - heap_ptr         = heap_base
        - heap_end         = heap_base + committed_bytes        (== committed_end)
        - heap_min_end     = heap_end                           (lower bound for shrink)
        - heap_reserve_end = heap_base + reserve_bytes          (fixed upper bound)

        Inputs / defaults:
        - If self.heap_config is present, use:
            reserve_bytes, commit_bytes
        - Otherwise fall back to HEAP_RESERVE_DEFAULT / HEAP_COMMIT_DEFAULT.

        Notes:
        - reserve_bytes is aligned up to MEM_RESERVE_GRANULARITY (64 KiB).
        - commit_bytes is aligned up to MEM_PAGE_SIZE (4 KiB).
        - If commit_bytes > reserve_bytes after alignment, commit is clamped to reserve.
        """
        self.ensure_gc_data()
        a = self.asm

        # Read heap config (optional; provided by compiler.py via CodegenCore)
        cfg = getattr(self, 'heap_config', None) or {}

        reserve_bytes = int(cfg.get('reserve_bytes') or HEAP_RESERVE_DEFAULT)
        commit_bytes = int(cfg.get('commit_bytes') or HEAP_COMMIT_DEFAULT)

        # Minimum committed heap size after shrink (defaults to initial commit)
        shrink_min_bytes = int(cfg.get('shrink_min_bytes') or cfg.get('heap_shrink_min_bytes') or commit_bytes)

        # Backwards-compat: if caller uses heap_size (old API) and no explicit config
        # was provided, treat heap_size as both reserve+commit.
        if (not cfg) and heap_size != HEAP_SIZE_DEFAULT:
            reserve_bytes = int(heap_size)
            commit_bytes = int(heap_size)

        # Align per Windows requirements
        reserve_bytes = align_up(reserve_bytes, MEM_RESERVE_GRANULARITY)
        commit_bytes = align_up(commit_bytes, MEM_PAGE_SIZE)
        shrink_min_bytes = align_up(shrink_min_bytes, MEM_PAGE_SIZE)
        if commit_bytes > reserve_bytes:
            commit_bytes = reserve_bytes
        if shrink_min_bytes > commit_bytes:
            shrink_min_bytes = commit_bytes

        # ------------------------------------------------------------
        # 1) RESERVE: base = VirtualAlloc(NULL, reserve, MEM_RESERVE, PAGE_READWRITE)
        # ------------------------------------------------------------
        a.xor_ecx_ecx()  # rcx = NULL
        a.mov_rax_imm64(reserve_bytes)
        a.mov_rdx_rax()  # rdx = reserve size
        a.mov_r8d_imm32(0x2000)  # MEM_RESERVE
        a.mov_r9d_imm32(0x04)  # PAGE_READWRITE
        a.mov_rax_rip_qword('iat_VirtualAlloc')
        a.call_rax()

        # if rax == 0 => ExitProcess(1)
        a.test_r64_r64("rax", "rax")  # test rax,rax
        lbl_ok_res = f"heap_res_ok_{a.pos}"
        a.jcc('ne', lbl_ok_res)
        a.mov_rcx_imm32(1)
        a.mov_rax_rip_qword('iat_ExitProcess')
        a.call_rax()
        a.mark(lbl_ok_res)

        # Persist base immediately (avoid relying on volatile/non-volatile regs here).
        # This also makes heap init resilient against any ABI mishaps early in startup.
        a.mov_rip_qword_rax('heap_base')
        a.mov_rip_qword_rax('heap_ptr')

        # ------------------------------------------------------------
        # 2) COMMIT: VirtualAlloc(base, commit, MEM_COMMIT, PAGE_READWRITE)
        # ------------------------------------------------------------
        # rcx = base  (reload from global to avoid relying on saved registers)
        a.mov_rax_rip_qword('heap_base')
        a.mov_r64_r64("rcx", "rax")
        a.mov_rax_imm64(commit_bytes)
        a.mov_rdx_rax()  # rdx = commit size
        a.mov_r8d_imm32(0x1000)  # MEM_COMMIT
        a.mov_r9d_imm32(0x04)  # PAGE_READWRITE
        a.mov_rax_rip_qword('iat_VirtualAlloc')
        a.call_rax()

        # if rax == 0 => ExitProcess(1)
        a.test_r64_r64("rax", "rax")
        lbl_ok_com = f"heap_com_ok_{a.pos}"
        a.jcc('ne', lbl_ok_com)
        a.mov_rcx_imm32(1)
        a.mov_rax_rip_qword('iat_ExitProcess')
        a.call_rax()
        a.mark(lbl_ok_com)

        # ------------------------------------------------------------
        # 3) Initialize heap globals
        # ------------------------------------------------------------

        # heap_ptr = heap_base (heap_base was already stored right after reserve)
        a.mov_rax_rip_qword('heap_base')
        a.mov_rip_qword_rax('heap_ptr')

        # heap_end = heap_base + commit_bytes
        a.mov_r64_r64("rdx", "rax")  # rdx = base
        a.mov_rax_imm64(commit_bytes)
        a.add_r64_r64("rdx", "rax")
        a.mov_rip_qword_rdx('heap_end')

        # heap_min_end = base + shrink_min_bytes (lower bound for shrink)
        a.mov_rax_rip_qword('heap_base')
        a.mov_r64_r64("rdx", "rax")
        a.mov_rax_imm64(shrink_min_bytes)
        a.add_r64_r64("rdx", "rax")
        a.mov_rip_qword_rdx('heap_min_end')

        # heap_reserve_end = base + reserve_bytes
        a.mov_rax_rip_qword('heap_base')
        a.mov_r64_r64("rdx", "rax")
        a.mov_rax_imm64(reserve_bytes)
        a.add_r64_r64("rdx", "rax")
        a.mov_rip_qword_rdx('heap_reserve_end')

        # Store sizes (bytes) for diagnostics / self-healing
        a.mov_rax_imm64(commit_bytes)
        a.mov_rip_qword_rax('heap_commit_bytes')
        a.mov_rax_imm64(reserve_bytes)
        a.mov_rip_qword_rax('heap_reserve_bytes')

    def emit_gc_init_globals(self, *, disable_periodic: bool = True) -> None:
        """
        Initialize GC-related global variables for the program.

        What it does:
        - Clears root list head and free list head.
        - Clears the mark stack top.
        - Optionally disables periodic GC by setting gc_bytes_limit very large.
        - Initializes gc_tmp0..gc_tmp7 to TAG_VOID to avoid accidental '0' looking like a pointer.

        Correctness notes:
        - gc_tmp slots are scanned as roots by the collector; never leave them uninitialized.
        """
        self.ensure_gc_data()
        a = self.asm

        a.mov_rax_imm64(0)
        a.mov_rip_qword_rax('gc_roots_head')
        a.mov_rip_qword_rax('gc_free_head')
        a.mov_rip_qword_rax('gc_mark_top')

        # Optional periodic trigger
        if disable_periodic:
            a.mov_rax_imm64(0)
            a.mov_rip_qword_rax('gc_bytes_since')
            a.mov_rax_imm64(GC_DISABLE_PERIODIC_LIMIT)
            a.mov_rip_qword_rax('gc_bytes_limit')

        # Clear gc_tmp0..7 to VOID (avoid accidental TAG_PTR=0 values)
        a.mov_rax_imm64(enc_void())
        for i in range(8):
            a.mov_rip_qword_rax(f'gc_tmp{i}')

    def emit_gc_clear_root_slots(self, root_base: int, root_top: int) -> None:
        """
        Clear shadow-stack root slots on the *native* stack to TAG_VOID.

        This is a safety helper used by statement/codegen scaffolding:
        - When a new stack frame is created, slots may contain stale values.
        - Clearing ensures the GC doesn't keep garbage alive due to old stack contents.

        Correctness requirements:
        - The [rsp+off] offsets must refer to the caller's root slot area (not Windows shadow space).
        """
        a = self.asm
        a.mov_rax_imm64(enc_void())
        for off in range(root_base, root_top, 8):
            a.mov_rsp_disp32_rax(off)

    def emit_gc_push_root_frame(self, root_rec_off: int, root_base: int, root_top: int) -> None:
        """
        Push a shadow-stack root-frame record and make it the new gc_roots_head.

        Record layout at [rsp+root_rec_off]:
          +0   next pointer (previous head)
          +8   base address of root slots
          +16  count (number of qwords)

        The collector walks this list to discover roots.

        Correctness requirements:
        - root_base/root_top must describe an array of qword slots.
        - The record itself must stay live until emit_gc_pop_root_frame() is executed.
        """
        self.ensure_gc_data()
        a = self.asm
        root_count = (root_top - root_base) // 8

        # record:
        #   +0  next (previous head)
        #   +8  base (rsp + root_base)
        #  +16  count (qwords)
        a.mov_rax_rip_qword('gc_roots_head')
        a.mov_rsp_disp32_rax(root_rec_off + 0)

        a.lea_r64_membase_disp("rax", "rsp", root_base)  # lea rax,[rsp+root_base]
        a.mov_rsp_disp32_rax(root_rec_off + 8)

        a.mov_rax_imm64(root_count)
        a.mov_rsp_disp32_rax(root_rec_off + 16)

        a.lea_r64_membase_disp("rax", "rsp", root_rec_off)  # lea rax,[rsp+root_rec_off]
        a.mov_rip_qword_rax('gc_roots_head')

    def emit_gc_pop_root_frame(self, root_rec_off: int) -> None:
        """
        Pop the current shadow-stack root-frame record.

        Restores gc_roots_head from the 'next' field stored in the record.

        Correctness requirements:
        - root_rec_off must match the one used in emit_gc_push_root_frame().
        """
        self.ensure_gc_data()
        a = self.asm
        a.mov_r64_membase_disp("rdx", "rsp", root_rec_off + 0)
        a.mov_rip_qword_rdx('gc_roots_head')

    def emit_alloc_function(self) -> None:
        """
        Emit fn_alloc(payload_bytes) -> object_payload_ptr.

        Calling convention:
        - RCX = payload bytes (excluding GC_HEADER_SIZE)
        - Returns RAX = pointer to payload (header + GC_HEADER_SIZE)

        Allocator strategy (free-list + bump + grow + GC retry):
        1) total = align8(payload + GC_HEADER_SIZE)
        2) Try free-list (first-fit):
           - walk gc_free_head (header pointers)
           - pick first block with block_size >= total
           - unlink it from the list
           - split if remainder >= ALLOC_MIN_SPLIT
        3) Otherwise bump allocate from heap_ptr (committed region):
           - if new_ptr > heap_end: call fn_heap_grow(new_ptr)
             - if grow fails: call fn_gc_collect once, then retry
             - if still fails: ExitProcess(1)
        4) Initialize header (mark=0, next_free=0) and return payload pointer.

        Notes:
        - Free blocks are linked via header[+16] (next_free).
        - Splitting creates a new free block header at (old_header + total) and pushes
          it to the free-list head.
        """
        self.ensure_gc_data()

        a = self.asm

        # OOM diagnostics strings (rdata)
        if hasattr(self, "rdata"):
            r = self.rdata
            if "oom_hdr" not in r.labels:
                r.add_str("oom_hdr", "ERROR: out of memory (MiniLang heap exhausted)\n", add_newline=False)
            if "oom_requested" not in r.labels:
                r.add_str("oom_requested", "requested=", add_newline=False)
            if "oom_reserved" not in r.labels:
                r.add_str("oom_reserved", "reserved=", add_newline=False)
            if "oom_committed" not in r.labels:
                r.add_str("oom_committed", "committed=", add_newline=False)
            if "oom_used" not in r.labels:
                r.add_str("oom_used", "used=", add_newline=False)
            if "oom_nl" not in r.labels:
                r.add_str("oom_nl", "\n", add_newline=False)
        a.mark("fn_alloc")

        # Win64 ABI: reserve 32B shadow space + locals, keep 16-byte alignment for calls.
        # Entry RSP is 8 mod 16. Sub 0x48 => 0 mod 16.
        a.sub_rsp_imm8(0x48)

        # save original requested payload bytes (RCX) for OOM diagnostics
        a.mov_r64_r64("rax", "rcx")
        a.mov_rsp_disp32_rax(0x38)

        # ------------------------------------------------------------
        # Heap sanity / self-heal
        #
        # We've seen rare cases where heap_end / heap_reserve_end gets corrupted
        # very early (before the first real allocation), which makes the allocator
        # think the heap is exhausted. Repair obvious invariant violations here:
        #   heap_reserve_end > heap_base
        #   heap_end in [heap_base, heap_reserve_end]
        #   heap_ptr in [heap_base, heap_end]
        #
        # We can recompute ends from the remembered size globals and (re)commit
        # the initial range via VirtualAlloc(MEM_COMMIT).
        # ------------------------------------------------------------
        lid_fix = self.new_label_id()
        l_fix_ok = f"alloc_heap_ok_{lid_fix}"
        l_fix_do = f"alloc_heap_fix_{lid_fix}"
        l_fix_done = f"alloc_heap_fix_done_{lid_fix}"
        l_fix_res_ok = f"alloc_heap_fix_res_ok_{lid_fix}"
        l_fix_end_ok = f"alloc_heap_fix_end_ok_{lid_fix}"
        l_fix_ptr_ok = f"alloc_heap_fix_ptr_ok_{lid_fix}"

        # r10 = heap_base
        a.mov_rax_rip_qword("heap_base")
        a.mov_r64_r64("r10", "rax")
        # r11 = heap_reserve_end
        a.mov_rax_rip_qword("heap_reserve_end")
        a.mov_r64_r64("r11", "rax")

        # require reserve_end > base
        a.cmp_r64_r64("r11", "r10")
        a.jcc("a", l_fix_res_ok)
        a.jmp(l_fix_do)
        a.mark(l_fix_res_ok)

        # rax = heap_end
        a.mov_rax_rip_qword("heap_end")
        # require end >= base
        a.cmp_r64_r64("rax", "r10")
        a.jcc("ae", l_fix_end_ok)
        a.jmp(l_fix_do)
        a.mark(l_fix_end_ok)

        # require end <= reserve_end
        a.cmp_r64_r64("rax", "r11")
        a.jcc("be", l_fix_ptr_ok)
        a.jmp(l_fix_do)

        a.mark(l_fix_ptr_ok)
        # rdx = heap_ptr
        a.mov_rdx_rip_qword("heap_ptr")
        # require ptr >= base
        a.cmp_r64_r64("rdx", "r10")
        a.jcc("ae", l_fix_ok)
        a.jmp(l_fix_do)

        a.mark(l_fix_ok)
        # require ptr <= end (rax)
        a.cmp_r64_r64("rdx", "rax")
        a.jcc("be", l_fix_done)

        # fallthrough to fix
        a.mark(l_fix_do)

        # Recompute reserve_end = base + heap_reserve_bytes
        a.mov_rax_rip_qword("heap_reserve_bytes")
        a.add_r64_r64("rax", "r10")
        a.mov_rip_qword_rax("heap_reserve_end")
        a.mov_r64_r64("r11", "rax")

        # Recompute end = base + commit_bytes (robust against corrupted heap_commit_bytes)
        # rdx = reserve_bytes = reserve_end - base
        a.mov_r64_r64("rdx", "r11")
        a.sub_r64_r64("rdx", "r10")

        # rax = commit_candidate (bytes)
        a.mov_rax_rip_qword("heap_commit_bytes")

        # if commit_candidate == 0 -> default
        a.test_r64_r64("rax", "rax")
        a.jcc("nz", f"alloc_heap_fix_commit_nonzero_{lid_fix}")
        a.jmp(f"alloc_heap_fix_commit_default_{lid_fix}")
        a.mark(f"alloc_heap_fix_commit_nonzero_{lid_fix}")

        # if commit_candidate <= reserve_bytes -> ok
        a.cmp_r64_r64("rax", "rdx")
        a.jcc("be", f"alloc_heap_fix_commit_ok_{lid_fix}")

        # default commit = min(HEAP_COMMIT_DEFAULT, reserve_bytes)
        a.mark(f"alloc_heap_fix_commit_default_{lid_fix}")
        a.mov_rax_imm64(HEAP_COMMIT_DEFAULT)
        a.cmp_r64_r64("rax", "rdx")
        a.jcc("be", f"alloc_heap_fix_commit_ok_{lid_fix}")
        a.mov_r64_r64("rax", "rdx")

        a.mark(f"alloc_heap_fix_commit_ok_{lid_fix}")
        # end = base + commit
        a.add_r64_r64("rax", "r10")
        a.mov_rip_qword_rax("heap_end")

        # Fix heap_ptr into [base,end]
        a.mov_rdx_rip_qword("heap_ptr")
        a.cmp_r64_r64("rdx", "r10")
        a.jcc("ae", f"alloc_heap_fix_ptr_ge_base_{lid_fix}")
        a.mov_r64_r64("rdx", "r10")
        a.mark(f"alloc_heap_fix_ptr_ge_base_{lid_fix}")
        a.cmp_r64_r64("rdx", "rax")
        a.jcc("be", f"alloc_heap_fix_ptr_le_end_{lid_fix}")
        a.mov_r64_r64("rdx", "rax")
        a.mark(f"alloc_heap_fix_ptr_le_end_{lid_fix}")
        a.mov_rip_qword_rdx("heap_ptr")

        # Ensure [base,end) is committed (idempotent)
        # VirtualAlloc(base, end-base, MEM_COMMIT, PAGE_READWRITE)
        a.mov_r64_r64("rcx", "r10")
        a.mov_r64_r64("rdx", "rax")
        a.sub_r64_r64("rdx", "r10")
        a.mov_r8d_imm32(0x1000)  # MEM_COMMIT
        a.mov_r9d_imm32(0x04)    # PAGE_READWRITE
        a.mov_rax_rip_qword("iat_VirtualAlloc")
        a.call_rax()
        a.test_r64_r64("rax", "rax")
        a.jcc("ne", l_fix_done)
        # commit failed -> hard fail
        a.mov_rcx_imm32(1)
        a.mov_rax_rip_qword("iat_ExitProcess")
        a.call_rax()

        a.mark(l_fix_done)

        # Restore RCX (requested payload bytes) for the actual allocation path
        a.mov_r64_membase_disp("rcx", "rsp", 0x38)

        # total = align8(payload + GC_HEADER_SIZE)  (in RCX)
        a.add_rcx_imm8(GC_HEADER_SIZE)
        a.add_rcx_imm8(7)
        a.and_r64_imm("rcx", -8)

        # locals:
        #   [rsp+0x20] total
        #   [rsp+0x28] prev (free-list)
        #   [rsp+0x30] tried_gc flag (0/1)
        #   [rsp+0x40] periodic_accounted flag (0/1)  (avoid double-count on alloc_retry)
        a.mov_r64_r64("rax", "rcx")
        a.mov_rsp_disp32_rax(0x20)
        a.mov_rax_imm64(0)
        a.mov_rsp_disp32_rax(0x30)

        a.mov_rax_imm64(0)
        a.mov_rsp_disp32_rax(0x40)

        lid0 = self.new_label_id()
        l_retry = f"alloc_retry_{lid0}"
        l_periodic_done = f"alloc_periodic_done_{lid0}"
        l_try_free = f"alloc_try_free_{lid0}"
        l_free_loop = f"alloc_free_loop_{lid0}"
        l_free_advance = f"alloc_free_adv_{lid0}"
        l_free_found = f"alloc_free_found_{lid0}"
        l_free_head = f"alloc_free_head_{lid0}"
        l_free_unlinked = f"alloc_free_unlinked_{lid0}"
        l_free_nosplit = f"alloc_free_nosplit_{lid0}"
        l_bump = f"alloc_bump_{lid0}"
        l_grow = f"alloc_grow_{lid0}"
        l_after_gc = f"alloc_after_gc_{lid0}"
        l_ok = f"alloc_ok_{lid0}"
        l_oom = f"alloc_oom_{lid0}"

        a.mark(l_retry)

        # Reload total into RCX
        a.mov_r64_membase_disp("rcx", "rsp", 0x20)

        # ------------------------------------------------------------
        # Periodic GC trigger (allocation pressure)
        # ------------------------------------------------------------
        # Account allocation bytes once per fn_alloc call; alloc_retry must not double-count.
        a.mov_r64_membase_disp("r11", "rsp", 0x40)
        a.test_r64_r64("r11", "r11")
        a.jcc("nz", l_periodic_done)

        # gc_bytes_since += total
        a.mov_rax_rip_qword("gc_bytes_since")
        a.mov_r64_r64("rdx", "rax")
        a.add_r64_r64("rdx", "rcx")
        a.mov_r64_r64("rax", "rdx")
        a.mov_rip_qword_rax("gc_bytes_since")

        # if gc_bytes_since >= gc_bytes_limit: collect
        a.mov_rax_rip_qword("gc_bytes_limit")
        a.cmp_r64_r64("rdx", "rax")
        a.jcc("b", l_periodic_done)
        a.call("fn_gc_collect")

        a.mark(l_periodic_done)
        a.mov_rax_imm64(1)
        a.mov_rsp_disp32_rax(0x40)

        # Reload total into RCX (call may clobber)
        a.mov_r64_membase_disp("rcx", "rsp", 0x20)

        # ------------------------------------------------------------
        # 1) Try free list (first-fit)
        # ------------------------------------------------------------
        a.mark(l_try_free)

        # r8 = cur = gc_free_head
        a.mov_rax_rip_qword("gc_free_head")
        a.mov_r64_r64("r8", "rax")

        # prev = 0
        a.mov_rax_imm64(0)
        a.mov_rsp_disp32_rax(0x28)

        a.mark(l_free_loop)
        a.test_r64_r64("r8", "r8")
        a.jcc("z", l_bump)  # no free blocks -> bump

        # rdx = cur.block_size
        a.mov_r64_membase_disp("rdx", "r8", 0)

        # if block_size < total -> advance
        a.cmp_r64_r64("rdx", "rcx")
        a.jcc("b", l_free_advance)

        # found suitable block at r8
        a.jmp(l_free_found)

        a.mark(l_free_advance)
        # prev = cur
        a.mov_r64_r64("rax", "r8")
        a.mov_rsp_disp32_rax(0x28)
        # cur = cur.next_free
        a.mov_r64_membase_disp("r8", "r8", 16)
        a.jmp(l_free_loop)

        a.mark(l_free_found)
        # r9 = next = cur.next_free
        a.mov_r64_membase_disp("r9", "r8", 16)
        # r10 = prev
        a.mov_r64_membase_disp("r10", "rsp", 0x28)
        a.test_r64_r64("r10", "r10")
        a.jcc("z", l_free_head)

        # prev.next_free = next
        a.mov_membase_disp_r64("r10", 16, "r9")
        a.jmp(l_free_unlinked)

        a.mark(l_free_head)
        # gc_free_head = next
        a.mov_r64_r64("rax", "r9")
        a.mov_rip_qword_rax("gc_free_head")

        a.mark(l_free_unlinked)

        # r11 = remainder = block_size - total
        a.mov_r64_r64("r11", "rdx")
        a.sub_r64_r64("r11", "rcx")

        # if remainder < ALLOC_MIN_SPLIT -> no split
        a.cmp_r64_imm("r11", ALLOC_MIN_SPLIT)
        a.jcc("b", l_free_nosplit)

        # Split:
        # new_free = cur + total
        a.mov_r64_r64("rdx", "r8")
        a.add_r64_r64("rdx", "rcx")  # rdx = new_free header

        # new_free.block_size = remainder
        a.mov_membase_disp_r64("rdx", 0, "r11")
        # new_free.mark = 0
        a.mov_membase_disp_imm32("rdx", 8, 0, qword=True)

        # push new_free to free-list head:
        a.mov_rax_rip_qword("gc_free_head")
        a.mov_membase_disp_r64("rdx", 16, "rax")  # new_free.next = old_head
        a.mov_r64_r64("rax", "rdx")
        a.mov_rip_qword_rax("gc_free_head")

        # mark payload type as OBJ_FREE (debug/GC hygiene)
        a.mov_membase_disp_imm32("rdx", GC_HEADER_SIZE + 0, OBJ_FREE, qword=False)

        # shrink allocated block_size to total
        a.mov_membase_disp_r64("r8", 0, "rcx")

        a.mark(l_free_nosplit)

        # allocated header: mark=0, next_free=0
        a.mov_membase_disp_imm32("r8", 8, 0, qword=True)
        a.mov_membase_disp_imm32("r8", 16, 0, qword=True)

        # return payload ptr = cur + GC_HEADER_SIZE
        a.mov_r64_r64("rax", "r8")
        a.add_rax_imm8(GC_HEADER_SIZE)
        a.add_rsp_imm8(0x48)
        a.ret()

        # ------------------------------------------------------------
        # 2) Bump allocate (commit-on-demand)
        # ------------------------------------------------------------
        a.mark(l_bump)

        # rdx = header_base = heap_ptr
        a.mov_rax_rip_qword("heap_ptr")
        a.mov_rdx_rax()

        # r10 = new_ptr = header_base + total
        a.mov_r10_rax()
        a.add_r64_r64("r10", "rcx")

        # r11 = heap_end (committed_end)
        a.mov_rax_rip_qword("heap_end")
        a.mov_r64_r64("r11", "rax")

        # if new_ptr <= heap_end -> ok
        a.cmp_r64_r64("r10", "r11")
        a.jcc("be", l_ok)

        # ------------------------------------------------------------
        # Need to grow committed heap OR run GC
        # ------------------------------------------------------------
        a.mark(l_grow)

        # NEUE LOGIK: Zuerst Garbage Collector, DANN wachsen!
        # 1. Prüfen, ob wir in diesem Alloc-Aufruf schon GC probiert haben
        a.mov_r64_membase_disp("rax", "rsp", 0x30)
        a.test_r64_r64("rax", "rax")
        a.jcc("nz", f"alloc_do_grow_{lid0}")  # Ja, GC hat nicht geholfen -> Wir müssen wachsen!

        # 2. Nein, noch kein GC probiert. Wir merken uns das (tried_gc = 1)
        a.mov_rax_imm64(1)
        a.mov_rsp_disp32_rax(0x30)

        # 3. Garbage Collector aufrufen!
        a.call("fn_gc_collect")
        a.jmp(l_retry)  # Nach dem Aufräumen: Nochmal von vorne probieren (Free-List checken)

        # ------------------------------------------------------------
        # GC hat nicht genug gebracht -> Wir MÜSSEN den Heap vergrößern
        # ------------------------------------------------------------
        a.mark(f"alloc_do_grow_{lid0}")
        a.mov_r64_r64("rcx", "r10")
        a.call("fn_heap_grow")
        a.test_r64_r64("rax", "rax")
        a.jcc("nz", l_retry)  # Wachstum erfolgreich -> Nochmal versuchen zu allozieren

        # Wachstum auch fehlgeschlagen (2 GB Reserve erschöpft) -> Out of Memory
        a.jmp(l_oom)

        # tried_gc = 1
        a.mov_rax_imm64(1)
        a.mov_rsp_disp32_rax(0x30)

        a.call("fn_gc_collect")
        a.jmp(l_retry)

        # OOM hard fail
        a.mark(l_oom)
        # --- OOM diagnostics ---
        # get stderr handle (STD_ERROR_HANDLE = -12)
        a.mov_rcx_imm32(-12)
        a.mov_rax_rip_qword("iat_GetStdHandle")
        a.call_rax()
        a.mov_rsp_disp32_rax(0x40)
        off, ln = self.rdata.labels["oom_hdr"]
        a.mov_r64_membase_disp("rcx", "rsp", 0x40)  # handle
        a.lea_rdx_rip("oom_hdr")
        a.mov_r8d_imm32(ln)
        a.lea_r64_membase_disp("r9", "rsp", 0x30)  # FIX: Valid stack pointer for lpNumberOfBytesWritten
        a.mov_membase_disp_imm32("rsp", 0x20, 0, qword=True)  # lpOverlapped = NULL
        a.mov_rax_rip_qword("iat_WriteFile")
        a.call_rax()
        off, ln = self.rdata.labels["oom_requested"]
        a.mov_r64_membase_disp("rcx", "rsp", 0x40)  # handle
        a.lea_rdx_rip("oom_requested")
        a.mov_r8d_imm32(ln)
        a.lea_r64_membase_disp("r9", "rsp", 0x30)  # FIX: Valid stack pointer for lpNumberOfBytesWritten
        a.mov_membase_disp_imm32("rsp", 0x20, 0, qword=True)  # lpOverlapped = NULL
        a.mov_rax_rip_qword("iat_WriteFile")
        a.call_rax()
        a.mov_r64_membase_disp("rax", "rsp", 0x38)  # raw requested bytes
        a.shl_r64_imm8("rax", 3)
        a.or_r64_imm("rax", 1)  # TAG_INT
        # print tagged int currently in RAX via fn_int_to_dec + WriteFile
        a.mov_r64_r64("rcx", "rax")
        a.call("fn_int_to_dec")
        a.mov_r8d_edx()
        a.mov_r64_r64("rdx", "rax")
        a.mov_r64_membase_disp("rcx", "rsp", 0x40)  # handle
        a.lea_r64_membase_disp("r9", "rsp", 0x30)  # FIX: Valid stack pointer for lpNumberOfBytesWritten
        a.mov_membase_disp_imm32("rsp", 0x20, 0, qword=True)
        a.mov_rax_rip_qword("iat_WriteFile")
        a.call_rax()
        off, ln = self.rdata.labels["oom_nl"]
        a.mov_r64_membase_disp("rcx", "rsp", 0x40)  # handle
        a.lea_rdx_rip("oom_nl")
        a.mov_r8d_imm32(ln)
        a.lea_r64_membase_disp("r9", "rsp", 0x30)  # FIX: Valid stack pointer for lpNumberOfBytesWritten
        a.mov_membase_disp_imm32("rsp", 0x20, 0, qword=True)  # lpOverlapped = NULL
        a.mov_rax_rip_qword("iat_WriteFile")
        a.call_rax()
        off, ln = self.rdata.labels["oom_reserved"]
        a.mov_r64_membase_disp("rcx", "rsp", 0x40)  # handle
        a.lea_rdx_rip("oom_reserved")
        a.mov_r8d_imm32(ln)
        a.lea_r64_membase_disp("r9", "rsp", 0x30)  # FIX: Valid stack pointer for lpNumberOfBytesWritten
        a.mov_membase_disp_imm32("rsp", 0x20, 0, qword=True)  # lpOverlapped = NULL
        a.mov_rax_rip_qword("iat_WriteFile")
        a.call_rax()
        a.call("fn_heap_bytes_reserved")
        # print tagged int currently in RAX via fn_int_to_dec + WriteFile
        a.mov_r64_r64("rcx", "rax")
        a.call("fn_int_to_dec")
        a.mov_r8d_edx()
        a.mov_r64_r64("rdx", "rax")
        a.mov_r64_membase_disp("rcx", "rsp", 0x40)  # handle
        a.lea_r64_membase_disp("r9", "rsp", 0x30)  # FIX: Valid stack pointer for lpNumberOfBytesWritten
        a.mov_membase_disp_imm32("rsp", 0x20, 0, qword=True)
        a.mov_rax_rip_qword("iat_WriteFile")
        a.call_rax()
        off, ln = self.rdata.labels["oom_nl"]
        a.mov_r64_membase_disp("rcx", "rsp", 0x40)  # handle
        a.lea_rdx_rip("oom_nl")
        a.mov_r8d_imm32(ln)
        a.lea_r64_membase_disp("r9", "rsp", 0x30)  # FIX: Valid stack pointer for lpNumberOfBytesWritten
        a.mov_membase_disp_imm32("rsp", 0x20, 0, qword=True)  # lpOverlapped = NULL
        a.mov_rax_rip_qword("iat_WriteFile")
        a.call_rax()
        off, ln = self.rdata.labels["oom_committed"]
        a.mov_r64_membase_disp("rcx", "rsp", 0x40)  # handle
        a.lea_rdx_rip("oom_committed")
        a.mov_r8d_imm32(ln)
        a.lea_r64_membase_disp("r9", "rsp", 0x30)  # FIX: Valid stack pointer for lpNumberOfBytesWritten
        a.mov_membase_disp_imm32("rsp", 0x20, 0, qword=True)  # lpOverlapped = NULL
        a.mov_rax_rip_qword("iat_WriteFile")
        a.call_rax()
        a.call("fn_heap_bytes_committed")
        # print tagged int currently in RAX via fn_int_to_dec + WriteFile
        a.mov_r64_r64("rcx", "rax")
        a.call("fn_int_to_dec")
        a.mov_r8d_edx()
        a.mov_r64_r64("rdx", "rax")
        a.mov_r64_membase_disp("rcx", "rsp", 0x40)  # handle
        a.lea_r64_membase_disp("r9", "rsp", 0x30)  # FIX: Valid stack pointer for lpNumberOfBytesWritten
        a.mov_membase_disp_imm32("rsp", 0x20, 0, qword=True)
        a.mov_rax_rip_qword("iat_WriteFile")
        a.call_rax()
        off, ln = self.rdata.labels["oom_nl"]
        a.mov_r64_membase_disp("rcx", "rsp", 0x40)  # handle
        a.lea_rdx_rip("oom_nl")
        a.mov_r8d_imm32(ln)
        a.lea_r64_membase_disp("r9", "rsp", 0x30)  # FIX: Valid stack pointer for lpNumberOfBytesWritten
        a.mov_membase_disp_imm32("rsp", 0x20, 0, qword=True)  # lpOverlapped = NULL
        a.mov_rax_rip_qword("iat_WriteFile")
        a.call_rax()
        off, ln = self.rdata.labels["oom_used"]
        a.mov_r64_membase_disp("rcx", "rsp", 0x40)  # handle
        a.lea_rdx_rip("oom_used")
        a.mov_r8d_imm32(ln)
        a.lea_r64_membase_disp("r9", "rsp", 0x30)  # FIX: Valid stack pointer for lpNumberOfBytesWritten
        a.mov_membase_disp_imm32("rsp", 0x20, 0, qword=True)  # lpOverlapped = NULL
        a.mov_rax_rip_qword("iat_WriteFile")
        a.call_rax()
        a.call("fn_heap_bytes_used")
        # print tagged int currently in RAX via fn_int_to_dec + WriteFile
        a.mov_r64_r64("rcx", "rax")
        a.call("fn_int_to_dec")
        a.mov_r8d_edx()
        a.mov_r64_r64("rdx", "rax")
        a.mov_r64_membase_disp("rcx", "rsp", 0x40)  # handle
        a.lea_r64_membase_disp("r9", "rsp", 0x30)  # FIX: Valid stack pointer for lpNumberOfBytesWritten
        a.mov_membase_disp_imm32("rsp", 0x20, 0, qword=True)
        a.mov_rax_rip_qword("iat_WriteFile")
        a.call_rax()
        off, ln = self.rdata.labels["oom_nl"]
        a.mov_r64_membase_disp("rcx", "rsp", 0x40)  # handle
        a.lea_rdx_rip("oom_nl")
        a.mov_r8d_imm32(ln)
        a.lea_r64_membase_disp("r9", "rsp", 0x30)  # FIX: Valid stack pointer for lpNumberOfBytesWritten
        a.mov_membase_disp_imm32("rsp", 0x20, 0, qword=True)  # lpOverlapped = NULL
        a.mov_rax_rip_qword("iat_WriteFile")
        a.call_rax()
        # --- end OOM diagnostics ---

        a.mov_rcx_imm32(1)
        a.mov_rax_rip_qword("iat_ExitProcess")
        a.call_rax()

        # bump ok: update heap_ptr and init header
        a.mark(l_ok)

        # heap_ptr = new_ptr
        a.mov_rax_r10()
        a.mov_rip_qword_rax("heap_ptr")

        # init header at [header_base]:
        #   [0]  = block_size (total)
        #   [8]  = mark (0)
        #   [16] = next_free (0)
        a.mov_membase_disp_r64("rdx", 0, "rcx")
        a.mov_membase_disp_imm32("rdx", 8, 0, qword=True)
        a.mov_membase_disp_imm32("rdx", 16, 0, qword=True)

        # return payload ptr = header_base + GC_HEADER_SIZE
        a.mov_r64_r64("rax", "rdx")
        a.add_rax_imm8(GC_HEADER_SIZE)

        a.add_rsp_imm8(0x48)
        a.ret()

    def ensure_gc_data(self) -> None:
        """
        Ensure required GC/heap globals exist in the .data section.

        Safe to call multiple times; it only creates missing labels.

        Creates:
        - gc_roots_head, gc_free_head
        - gc_bytes_since, gc_bytes_limit
        - gc_tmp0..gc_tmp7
        - gc_mark_top, gc_mark_stack
        - heap_base, heap_ptr, heap_end, heap_reserve_end, heap_min_end

        Correctness notes:
        - Any label referenced by generated assembly MUST be defined here (or elsewhere),
          otherwise the PE patcher will error with "Unknown patch target".
        """
        d = self.data

        # Shadow stack + free list
        if 'gc_roots_head' not in d.labels:
            d.add_u64('gc_roots_head', 0)
        if 'gc_free_head' not in d.labels:
            d.add_u64('gc_free_head', 0)

        # Optional allocation counters (soft trigger)
        if 'gc_bytes_since' not in d.labels:
            d.add_u64('gc_bytes_since', 0)
        if 'gc_bytes_limit' not in d.labels:
            d.add_u64('gc_bytes_limit', GC_DEFAULT_BYTES_LIMIT)  # default periodic GC trigger

        # Temp roots (important: must not look like TAG_PTR=0)
        for i in range(8):
            name = f'gc_tmp{i}'
            if name not in d.labels:
                d.add_u64(name, enc_void())

        # Mark stack (iterative)
        if 'gc_mark_top' not in d.labels:
            d.add_u64('gc_mark_top', 0)

        # Heap globals (used by allocator / heap grow paths)
        if 'heap_base' not in d.labels:
            d.add_u64('heap_base', 0)
        if 'heap_ptr' not in d.labels:
            d.add_u64('heap_ptr', 0)
        if 'heap_end' not in d.labels:
            d.add_u64('heap_end', 0)
        if 'heap_reserve_end' not in d.labels:
            d.add_u64('heap_reserve_end', 0)
        if 'heap_min_end' not in d.labels:
            d.add_u64('heap_min_end', 0)

        # Remember initial heap sizes for diagnostics / self-healing
        if 'heap_commit_bytes' not in d.labels:
            d.add_u64('heap_commit_bytes', 0)
        if 'heap_reserve_bytes' not in d.labels:
            d.add_u64('heap_reserve_bytes', 0)

        if 'gc_mark_stack' not in d.labels:
            # 8192 entries * 8 bytes = 64 KiB
            d.add_bytes('gc_mark_stack', b'\x00' * (GC_MARK_STACK_QWORDS * 8))

    def emit_gc_collect_function(self) -> None:
        """
        Emit fn_gc_collect(): a mark/sweep garbage collector.

        Roots scanned:
        - gc_tmp0..gc_tmp7
        - global variable slots (self.global_slots)
        - shadow-stack frames via gc_roots_head
        - (optional) conservative scan of native stack (useful for debugging)

        Heap layout assumptions:
        - header = obj_ptr - GC_HEADER_SIZE
          [header+0]  u64 block_size
          [header+8]  u64 mark
          [header+16] u64 next_free

        Correctness requirements:
        - Preserve non-volatile registers per Windows x64 ABI (notably RDI if used).
        - Rebuild gc_free_head from scratch each collection (reset head before sweep),
          otherwise duplicates accumulate and the free list becomes corrupt.
        - Mark stack has a fixed capacity (GC_MARK_STACK_QWORDS); if you can overflow it,
          add a guard or increase its size.
        """
        self.ensure_gc_data()
        a = self.asm
        # GC diagnostic strings (rdata)
        if hasattr(self, "rdata"):
            r = self.rdata
            if "gc_ms_overflow" not in r.labels:
                r.add_str("gc_ms_overflow", "ERROR: GC mark stack overflow\n", add_newline=False)

        # Heap config (optional, provided by CLI via CodegenCore)
        cfg = getattr(self, 'heap_config', None) or {}
        shrink_enabled = bool(cfg.get('shrink_enabled'))
        # Decommit only if at least this many bytes can be released (avoid thrashing)
        shrink_threshold = int(cfg.get('shrink_threshold_bytes') or (4 << 20))  # 4 MiB

        a.mark('fn_gc_collect')

        # Save non-volatile regs we use
        a.push_rbx()
        a.push_r12()
        a.push_r13()
        a.push_r14()
        a.push_r15()
        a.push_reg("rdi")  # push rdi (non-volatile)

        # Win64 ABI: provide 32B shadow space + align stack for calls inside GC
        # After pushes, rsp is still 8 mod 16; sub 0x28 makes it 0 mod 16.
        a.sub_rsp_imm8(0x28)

        lid = self.new_label_id()
        L_MARK_VALUE = f"gc_mark_value_{lid}"
        L_MARK_VALUE_RET = f"gc_mark_value_ret_{lid}"
        L_BODY = f"gc_body_{lid}"
        L_MARK_LOOP = f"gc_mark_loop_{lid}"
        L_MARK_DONE = f"gc_mark_done_{lid}"
        L_SCAN_ARRAY = f"gc_scan_array_{lid}"
        L_SCAN_ARRAY_LOOP = f"gc_scan_array_loop_{lid}"
        L_SCAN_ARRAY_DONE = f"gc_scan_array_done_{lid}"
        L_SCAN_STRUCT = f"gc_scan_struct_{lid}"
        L_SCAN_STRUCT_LOOP = f"gc_scan_struct_loop_{lid}"
        L_SCAN_STRUCT_DONE = f"gc_scan_struct_done_{lid}"
        L_SCAN_FUNCTION = f"gc_scan_function_{lid}"
        L_SCAN_ENV = f"gc_scan_env_{lid}"
        L_SCAN_ENV_LOOP = f"gc_scan_env_loop_{lid}"
        L_SCAN_ENV_DONE = f"gc_scan_env_done_{lid}"
        L_SCAN_BOX = f"gc_scan_box_{lid}"
        L_ROOT_FRAMES = f"gc_root_frames_{lid}"
        L_ROOT_FRAME_LOOP = f"gc_root_frame_loop_{lid}"
        L_ROOT_FRAME_SLOTS = f"gc_root_frame_slots_{lid}"
        L_ROOT_FRAME_SLOTS_LOOP = f"gc_root_frame_slots_loop_{lid}"
        L_ROOT_FRAME_NEXT = f"gc_root_frame_next_{lid}"
        L_SWEEP_LOOP = f"gc_sweep_loop_{lid}"
        L_SWEEP_LIVE = f"gc_sweep_live_{lid}"
        L_SWEEP_DEAD = f"gc_sweep_dead_{lid}"
        L_SWEEP_DONE = f"gc_sweep_done_{lid}"
        L_REBUILD_LOOP = f"gc_rebuild_free_loop_{lid}"
        L_REBUILD_DONE = f"gc_rebuild_free_done_{lid}"
        L_REBUILD_NEXT = f"gc_rebuild_free_next_{lid}"
        L_TRIM_SKIP = f"gc_trim_skip_{lid}"
        L_TRIM_DONE = f"gc_trim_done_{lid}"
        L_MS_OVERFLOW = f"gc_mark_stack_overflow_{lid}"

        # r12 = &gc_mark_stack
        a.lea_rax_rip('gc_mark_stack')
        a.mov_r64_r64("r12", "rax")  # mov r12, rax

        # gc_mark_top = 0
        a.mov_rax_imm64(0)
        a.mov_rip_qword_rax('gc_mark_top')

        # IMPORTANT: gc_mark_value is an internal helper that ends with RET.
        # We must jump over its code so fn_gc_collect doesn't "fall into" it.
        a.jmp(L_BODY)

        # ------------------------------------------------------------
        # local helper: gc_mark_value( RAX = tagged value )
        # pushes object pointers onto mark stack
        # ------------------------------------------------------------
        a.mark(L_MARK_VALUE)
        # if ((rax & 7) != 0) return
        a.mov_r64_r64("rdx", "rax")  # mov rdx, rax
        a.and_r64_imm("rdx", 7)  # and rdx, 7
        a.test_r64_r64("rdx", "rdx")  # test rdx, rdx
        a.jcc('ne', L_MARK_VALUE_RET)

        # r11 = objptr (keep)
        a.mov_r64_r64("r11", "rax")

        # ---- ignore non-heap pointers (e.g. boxed constants in .rdata/.data) ----
        # rdx = objptr
        a.mov_r64_r64("rdx", "r11")  # mov rdx, r11

        # if rdx < heap_base -> return
        a.mov_rax_rip_qword('heap_base')
        a.cmp_r64_r64("rdx", "rax")  # cmp rdx, rax
        a.jcc('b', L_MARK_VALUE_RET)

        # if rdx >= heap_end -> return
        a.mov_rax_rip_qword('heap_end')
        a.cmp_r64_r64("rdx", "rax")  # cmp rdx, rax
        a.jcc('ae', L_MARK_VALUE_RET)

        # rdx = header = obj - GC_HEADER_SIZE
        a.sub_r64_imm("rdx", GC_HEADER_SIZE)  # sub rdx, GC_HEADER_SIZE

        # if [rdx+8] != 0 -> already marked
        a.mov_r64_membase_disp("rcx", "rdx", 8)  # mov rcx, [rdx+8]
        a.test_r64_r64("rcx", "rcx")  # test rcx, rcx
        a.jcc('ne', L_MARK_VALUE_RET)

        # [rdx+8] = 1 (mark)
        a.mov_membase_disp_imm32("rdx", 8, 1, qword=True)  # mov qword [rdx+8], 1        # r10 = gc_mark_top
        a.mov_rax_rip_qword('gc_mark_top')
        a.mov_r10_rax()

        # Guard against mark stack overflow (otherwise it will corrupt .data)
        a.cmp_r64_imm("r10", GC_MARK_STACK_QWORDS)
        a.jcc('ae', L_MS_OVERFLOW)

        # mark_stack[r10] = r11
        a.mov_mem_bis_r64("r12", "r10", 8, 0, "r11")  # mov [r12 + r10*8], r11
        # r10++
        a.inc_r64("r10")  # inc r10

        # gc_mark_top = r10
        a.mov_r64_r64("rax", "r10")  # mov rax, r10
        a.mov_rip_qword_rax('gc_mark_top')

        a.mark(L_MARK_VALUE_RET)
        a.ret()

        # ------------------------------------------------------------
        # Mark stack overflow handler (fatal): print to stderr and exit
        # ------------------------------------------------------------
        a.mark(L_MS_OVERFLOW)
        if hasattr(self, "rdata"):
            off, ln = self.rdata.labels["gc_ms_overflow"]
            a.mov_rcx_imm32(-12)  # STDERR
            a.mov_rax_rip_qword("iat_GetStdHandle")
            a.call_rax()
            a.mov_r64_r64("rcx", "rax")  # handle
            a.lea_rdx_rip("gc_ms_overflow")
            a.mov_r8d_imm32(ln)

            a.lea_r64_membase_disp("r9", "rsp", 0x28)
            a.mov_membase_disp_imm32("rsp", 0x20, 0, qword=True)  # lpOverlapped = NULL

            a.mov_rax_rip_qword("iat_WriteFile")
            a.call_rax()
        a.mov_rcx_imm32(1)
        a.mov_rax_rip_qword("iat_ExitProcess")
        a.call_rax()

        a.mark(L_BODY)

        # ------------------------------------------------------------
        # Mark roots: gc_tmp0..7
        # ------------------------------------------------------------
        for i in range(8):
            a.mov_rax_rip_qword(f'gc_tmp{i}')
            a.call(L_MARK_VALUE)

        # Mark roots: globals (var slots)
        for lbl in getattr(self, 'scope_global_slots', getattr(self, 'global_slots', [])):
            a.mov_rax_rip_qword(lbl)
            a.call(L_MARK_VALUE)

        # Mark roots: shadow stack frames (if any)
        a.mark(L_ROOT_FRAMES)
        a.mov_rax_rip_qword('gc_roots_head')
        a.mov_r64_r64("r13", "rax")  # mov r13, rax
        a.mark(L_ROOT_FRAME_LOOP)
        a.test_r64_r64("r13", "r13")  # test r13, r13
        a.jcc('e', L_MARK_LOOP)

        # r14 = [r13+8]  (base)
        a.mov_r64_membase_disp("r14", "r13", 8)  # mov r14, [r13+8]
        # r15 = [r13+16] (count)
        a.mov_r64_membase_disp("r15", "r13", 16)  # mov r15, [r13+16]

        # scan slots: while (r15 != 0) { rax = [r14]; mark; r14 +=8; r15--; }
        a.mark(L_ROOT_FRAME_SLOTS_LOOP)
        a.test_r64_r64("r15", "r15")  # test r15, r15
        a.jcc('e', L_ROOT_FRAME_NEXT)

        a.mov_r64_membase_disp("rax", "r14", 0)  # mov rax, [r14]
        a.call(L_MARK_VALUE)
        a.add_r64_imm("r14", 8)  # add r14, 8
        a.dec_r64("r15")  # dec r15
        a.jmp(L_ROOT_FRAME_SLOTS_LOOP)

        a.mark(L_ROOT_FRAME_NEXT)
        # r13 = [r13]  (next)   (r13 needs disp8=0)
        a.mov_r64_membase_disp("rax", "r13", 0)  # mov rax, [r13+0]
        a.mov_r64_r64("r13", "rax")  # mov r13, rax
        a.jmp(L_ROOT_FRAME_LOOP)

        # ------------------------------------------------------------
        # Mark loop: pop objects and scan children
        # ------------------------------------------------------------
        a.mark(L_MARK_LOOP)
        a.mov_rax_rip_qword('gc_mark_top')
        a.mov_r10_rax()
        a.test_r64_r64("r10", "r10")  # test r10, r10
        a.jcc('e', L_MARK_DONE)

        a.dec_r64("r10")  # dec r10
        a.mov_r64_r64("rax", "r10")  # mov rax, r10
        a.mov_rip_qword_rax('gc_mark_top')

        # r11 = mark_stack[r10]
        a.mov_r64_mem_bis("r11", "r12", "r10", 8, 0)  # mov r11, [r12 + r10*8]
        a.mov_r64_r64("rax", "r11")  # rax = objptr

        # type in ecx = [rax]
        a.mov_r32_membase_disp("ecx", "rax", 0)  # mov ecx, [rax]
        a.cmp_r32_imm("ecx", OBJ_ARRAY)  # cmp ecx, OBJ_ARRAY
        a.jcc('e', L_SCAN_ARRAY)

        a.cmp_r32_imm("ecx", OBJ_STRUCT)  # cmp ecx, OBJ_STRUCT
        a.jcc('e', L_SCAN_STRUCT)

        a.cmp_r32_imm("ecx", OBJ_FUNCTION)  # cmp ecx, OBJ_FUNCTION
        a.jcc('e', L_SCAN_FUNCTION)

        a.cmp_r32_imm("ecx", OBJ_ENV)  # cmp ecx, OBJ_ENV
        a.jcc('e', L_SCAN_ENV)

        a.cmp_r32_imm("ecx", OBJ_BOX)  # cmp ecx, OBJ_BOX
        a.jcc('e', L_SCAN_BOX)

        a.jmp(L_MARK_LOOP)

        # ------------------------------------------------------------
        # scan array elements
        # ------------------------------------------------------------
        a.mark(L_SCAN_ARRAY)
        # edx = len
        a.mov_r32_membase_disp("edx", "rax", 4)  # mov edx, [rax+4]
        # rbx = data base = rax + 8
        a.lea_r64_membase_disp("rbx", "rax", 8)  # lea rbx, [rax+8]
        # r9d = len
        a.mov_r32_r32("r9d", "edx")  # mov r9d, edx
        # i = 0 (r8d)
        a.xor_r32_r32("r8d", "r8d")  # xor r8d, r8d

        a.mark(L_SCAN_ARRAY_LOOP)
        a.cmp_r32_r32("r8d", "r9d")  # cmp r8d, r9d
        a.jcc('ge', L_SCAN_ARRAY_DONE)

        # rax = [rbx + r8*8]
        a.mov_r64_mem_bis("rax", "rbx", "r8", 8, 0)  # mov rax, [rbx + r8*8]
        a.call(L_MARK_VALUE)

        a.inc_r32("r8d")  # inc r8d
        a.jmp(L_SCAN_ARRAY_LOOP)

        a.mark(L_SCAN_ARRAY_DONE)
        a.jmp(L_MARK_LOOP)

        # ------------------------------------------------------------
        # scan struct fields
        # layout:
        #   [0] u32 type = OBJ_STRUCT
        #   [4] u32 nfields
        #   [8] u32 struct_id
        #   [12] u32 pad
        #   [16] qword field0 ...
        # ------------------------------------------------------------
        a.mark(L_SCAN_STRUCT)
        # edx = nfields
        a.mov_r32_membase_disp("edx", "rax", 4)  # mov edx, [rax+4]
        # rbx = fields base = rax + 16
        a.lea_r64_membase_disp("rbx", "rax", 16)  # lea rbx, [rax+16]
        # r9d = nfields
        a.mov_r32_r32("r9d", "edx")  # mov r9d, edx
        # i = 0 (r8d)
        a.xor_r32_r32("r8d", "r8d")  # xor r8d, r8d

        a.mark(L_SCAN_STRUCT_LOOP)
        a.cmp_r32_r32("r8d", "r9d")  # cmp r8d, r9d
        a.jcc('ge', L_SCAN_STRUCT_DONE)

        # rax = [rbx + r8*8]
        a.mov_r64_mem_bis("rax", "rbx", "r8", 8, 0)  # mov rax, [rbx + r8*8]
        a.call(L_MARK_VALUE)

        a.inc_r32("r8d")  # inc r8d
        a.jmp(L_SCAN_STRUCT_LOOP)

        a.mark(L_SCAN_STRUCT_DONE)
        a.jmp(L_MARK_LOOP)

        # ------------------------------------------------------------
        # scan function object (closure env)
        # layout:
        #   [0]  u32 type = OBJ_FUNCTION
        #   [4]  u32 arity
        #   [8]  u64 code_ptr (raw)
        #   [16] u64 env (Value)
        # ------------------------------------------------------------
        a.mark(L_SCAN_FUNCTION)
        a.mov_r64_membase_disp("rax", "r11", 16)  # rax = fn.env
        a.call(L_MARK_VALUE)
        a.jmp(L_MARK_LOOP)

        # ------------------------------------------------------------
        # scan env object
        # layout:
        #   [0]  u32 type = OBJ_ENV
        #   [4]  u32 nslots
        #   [8]  u64 parent (Value)
        #   [16] qword slot0 (Value) ...
        # ------------------------------------------------------------
        a.mark(L_SCAN_ENV)
        # preserve env pointer across calls (gc_mark_value clobbers r11)
        a.mov_r64_r64("rdi", "r11")  # rdi = env

        # mark parent
        a.mov_r64_membase_disp("rax", "rdi", 8)  # rax = env.parent
        a.call(L_MARK_VALUE)

        # edx = nslots
        a.mov_r32_membase_disp("edx", "rdi", 4)  # mov edx, [env+4]
        # rbx = slots base = env + 16
        a.lea_r64_membase_disp("rbx", "rdi", 16)  # lea rbx, [env+16]
        # r9d = nslots
        a.mov_r32_r32("r9d", "edx")
        # i = 0 (r8d)
        a.xor_r32_r32("r8d", "r8d")

        a.mark(L_SCAN_ENV_LOOP)
        a.cmp_r32_r32("r8d", "r9d")
        a.jcc('ge', L_SCAN_ENV_DONE)

        a.mov_r64_mem_bis("rax", "rbx", "r8", 8, 0)  # slot value
        a.call(L_MARK_VALUE)

        a.inc_r32("r8d")
        a.jmp(L_SCAN_ENV_LOOP)

        a.mark(L_SCAN_ENV_DONE)
        a.jmp(L_MARK_LOOP)

        # ------------------------------------------------------------
        # scan box/cell object
        # layout:
        #   [0]  u32 type = OBJ_BOX
        #   [4]  u32 pad
        #   [8]  u64 value (Value)
        # ------------------------------------------------------------
        a.mark(L_SCAN_BOX)
        a.mov_r64_membase_disp("rax", "r11", 8)  # rax = box.value
        a.call(L_MARK_VALUE)
        a.jmp(L_MARK_LOOP)

        a.mark(L_MARK_DONE)

        # ------------------------------------------------------------
        # Sweep pass 1:
        # - clear marks on live blocks
        # - turn dead blocks into OBJ_FREE
        # - compute new heap_ptr = end of highest live block (r15)
        # NOTE: We rebuild the free list in pass 2 so we can safely shrink.
        # ------------------------------------------------------------

        # Clear gc_free_head now; we rebuild it in pass 2.
        a.mov_rax_imm64(0)
        a.mov_rip_qword_rax('gc_free_head')

        # rbx = scan = heap_base
        a.mov_rax_rip_qword('heap_base')
        a.mov_rbx_rax()

        # r14 = old heap_ptr
        a.mov_rax_rip_qword('heap_ptr')
        a.mov_r64_r64("r14", "rax")  # mov r14, rax

        # r15 = max_live_end (init to heap_base)
        a.mov_r64_r64("r15", "rbx")  # mov r15, rbx

        a.mark(L_SWEEP_LOOP)
        # if (rbx >= old_heap_ptr) done
        a.cmp_r64_r64("rbx", "r14")
        a.jcc('ae', L_SWEEP_DONE)

        # r10 = block_size
        a.mov_r64_membase_disp("r10", "rbx", 0)
        a.test_r64_r64("r10", "r10")
        a.jcc('e', L_SWEEP_DONE)  # safety

        # rcx = mark
        a.mov_r64_membase_disp("rcx", "rbx", 8)
        a.test_r64_r64("rcx", "rcx")
        a.jcc('ne', L_SWEEP_LIVE)

        # -------- dead block: set object type to OBJ_FREE (0) --------
        a.lea_r64_membase_disp("rdx", "rbx", GC_HEADER_SIZE)  # rdx = payload
        a.mov_membase_disp_imm32("rdx", 0, 0, qword=False)  # mov dword [payload], 0

        # advance scan: rbx += block_size
        a.add_r64_r64("rbx", "r10")
        a.jmp(L_SWEEP_LOOP)

        # -------- live block --------
        a.mark(L_SWEEP_LIVE)

        # clear mark: [rbx+8] = 0
        a.mov_membase_disp_imm32("rbx", 8, 0, qword=True)

        # end = rbx + block_size
        a.mov_r64_r64("rdx", "rbx")
        a.add_r64_r64("rdx", "r10")

        # if end > max_live_end: max_live_end = end
        a.cmp_r64_r64("rdx", "r15")
        a.jcc('be', L_SWEEP_DEAD)
        a.mov_r64_r64("r15", "rdx")

        a.mark(L_SWEEP_DEAD)
        # advance scan
        a.add_r64_r64("rbx", "r10")
        a.jmp(L_SWEEP_LOOP)

        a.mark(L_SWEEP_DONE)

        # heap_ptr = max_live_end
        a.mov_r64_r64("rax", "r15")
        a.mov_rip_qword_rax('heap_ptr')

        # ------------------------------------------------------------
        # Sweep pass 2: rebuild free list in [heap_base, heap_ptr)
        # NEU: Mit Block-Coalescing (verhindert das "Hängen" durch O(N^2))
        # ------------------------------------------------------------

        a.mov_rax_imm64(0)
        a.mov_rip_qword_rax('gc_free_head')

        a.mov_rax_rip_qword('heap_base')
        a.mov_rbx_rax()

        a.mov_rax_rip_qword('heap_ptr')
        a.mov_r64_r64("r14", "rax")  # r14 = new heap_ptr

        a.mark(L_REBUILD_LOOP)
        a.cmp_r64_r64("rbx", "r14")
        a.jcc('ae', L_REBUILD_DONE)

        # r10 = block_size
        a.mov_r64_membase_disp("r10", "rbx", 0)
        a.test_r64_r64("r10", "r10")
        a.jcc('e', L_REBUILD_DONE)

        # payload type (u32) at [rbx+GC_HEADER_SIZE]
        a.lea_r64_membase_disp("rdx", "rbx", GC_HEADER_SIZE)
        a.mov_r32_membase_disp("ecx", "rdx", 0)
        a.test_r32_r32("ecx", "ecx")
        a.jcc('ne', L_REBUILD_NEXT)  # Block ist am Leben -> überspringen

        # --- COALESCING START (Benachbarte tote Blöcke verschmelzen) ---
        l_coal_loop = f"gc_coal_loop_{lid}"
        l_coal_done = f"gc_coal_done_{lid}"

        a.mark(l_coal_loop)
        # r11 = next_block = rbx + block_size (r10)
        a.mov_r64_r64("r11", "rbx")
        a.add_r64_r64("r11", "r10")

        # if next_block >= heap_ptr -> wir sind am Ende, stoppen
        a.cmp_r64_r64("r11", "r14")
        a.jcc('ae', l_coal_done)

        # Ist der nächste Block auch frei (tot)?
        a.lea_r64_membase_disp("rdx", "r11", GC_HEADER_SIZE)
        a.mov_r32_membase_disp("ecx", "rdx", 0)
        a.test_r32_r32("ecx", "ecx")
        a.jcc('ne', l_coal_done)  # Nein, live -> Coalescing beenden

        # Ja, frei! Größe des nächsten Blocks addieren
        a.mov_r64_membase_disp("rcx", "r11", 0)  # rcx = next_block.size
        a.add_r64_r64("r10", "rcx")  # r10 += rcx
        a.mov_membase_disp_r64("rbx", 0, "r10")  # Aktuelle Header-Größe im RAM updaten
        a.jmp(l_coal_loop)  # Weiter schauen, ob der übernächste auch frei ist!

        a.mark(l_coal_done)
        # --- COALESCING ENDE ---

        # Den (nun riesigen) zusammengefassten Block in die Free-List einhängen
        a.mov_rax_rip_qword('gc_free_head')
        a.mov_membase_disp_r64("rbx", 16, "rax")

        # gc_free_head = rbx
        a.mov_r64_r64("rax", "rbx")
        a.mov_rip_qword_rax('gc_free_head')

        a.mark(L_REBUILD_NEXT)
        a.add_r64_r64("rbx", "r10")  # Springt jetzt direkt über ALLE verschmolzenen Blöcke!
        a.jmp(L_REBUILD_LOOP)

        a.mark(L_REBUILD_DONE)

        if shrink_enabled:
            # ------------------------------------------------------------
            # Optional heap trim (decommit) "from the top" after GC.
            # Safe because we rebuilt free list and lowered heap_ptr.
            #
            # Decommit range: [target_end, heap_end) where:
            #   target_end = align_up(max(heap_ptr, heap_min_end), 4KiB)
            # Only decommit if at least `shrink_threshold` bytes can be released.
            # ------------------------------------------------------------

            # r11 = heap_end (current committed end)
            a.mov_rax_rip_qword('heap_end')
            a.mov_r64_r64("r11", "rax")

            # r10 = heap_ptr
            a.mov_rax_rip_qword('heap_ptr')
            a.mov_r64_r64("r10", "rax")

            # r10 = align_up(r10, 4096)
            a.add_r64_imm("r10", MEM_PAGE_SIZE - 1)
            a.and_r64_imm("r10", -MEM_PAGE_SIZE)

            # clamp to heap_min_end
            a.mov_rax_rip_qword('heap_min_end')
            a.cmp_r64_r64("r10", "rax")
            a.jcc('ae', L_TRIM_DONE)
            a.mov_r64_r64("r10", "rax")
            a.mark(L_TRIM_DONE)

            # if target_end >= heap_end: skip
            a.cmp_r64_r64("r10", "r11")
            a.jcc('ae', L_TRIM_SKIP)

            # rdx = bytes_to_decommit = heap_end - target_end
            a.mov_r64_r64("rdx", "r11")
            a.sub_r64_r64("rdx", "r10")

            # if bytes_to_decommit < threshold: skip
            a.cmp_r64_imm("rdx", shrink_threshold)
            a.jcc('b', L_TRIM_SKIP)

            # VirtualFree(target_end, bytes_to_decommit, MEM_DECOMMIT)
            # NOTE: VirtualFree may clobber volatile regs; preserve target_end in r13 (non-volatile).
            a.mov_r64_r64("r13", "r10")
            a.mov_r64_r64("rcx", "r10")
            a.mov_r8d_imm32(0x4000)  # MEM_DECOMMIT
            a.mov_rax_rip_qword('iat_VirtualFree')
            a.call_rax()

            # heap_end = target_end
            a.mov_r64_r64("rax", "r13")
            a.mov_rip_qword_rax('heap_end')

            a.mark(L_TRIM_SKIP)
        # reset gc_bytes_since (optional)
        a.mov_rax_imm64(0)
        a.mov_rip_qword_rax('gc_bytes_since')

        # restore stack (shadow space + alignment)
        a.add_rsp_imm8(0x28)

        # Restore regs and return
        a.pop_reg("rdi")  # pop rdi
        a.pop_r15()
        a.pop_r14()
        a.pop_r13()
        a.pop_r12()
        a.pop_rbx()
        a.ret()

    def emit_incref_function(self) -> None:
        """
        Emit fn_incref(value) (OPTIONAL / DISABLED BY DEFAULT).

        This project currently uses mark/sweep headers with no refcount field.
        If MEMORY_ENABLE_REFCOUNT is False, this function returns immediately.

        If you want refcounting:
        - Redesign the GC header layout to include a refcount field.
        - Update incref/decref AND the collector to respect it.
        """
        a = self.asm
        a.mark('fn_incref')
        if not MEMORY_ENABLE_REFCOUNT:
            a.ret()
        lid = self.new_label_id()
        l_ret = f"incref_ret_{lid}"

        # tag check: (rcx & 7) == TAG_PTR(0)
        a.mov_r64_r64("rax", "rcx")  # mov rax,rcx
        a.and_r64_imm("rax", 7)  # and rax,7
        a.cmp_r64_imm("rax", 0)  # cmp rax,0
        a.jcc('ne', l_ret)

        # rdx = rcx (ptr)
        a.mov_r64_r64("rdx", "rcx")  # mov rdx,rcx

        # if rdx < heap_base -> ret
        a.mov_rax_rip_qword('heap_base')
        a.cmp_r64_r64("rdx", "rax")  # cmp rdx,rax
        a.jcc('b', l_ret)

        # if rdx >= heap_end -> ret
        a.mov_rax_rip_qword('heap_end')
        a.cmp_r64_r64("rdx", "rax")  # cmp rdx,rax
        a.jcc('ae', l_ret)

        # inc qword [rdx-16] (refcount)
        a.inc_membase_disp_qword("rdx", -16)  # inc qword [rdx-16]

        a.mark(l_ret)
        a.ret()

    def emit_decref_function(self) -> None:
        """
        Emit fn_decref(value) (OPTIONAL / DISABLED BY DEFAULT).

        This project currently uses mark/sweep headers with no refcount field.
        If MEMORY_ENABLE_REFCOUNT is False, this function returns immediately.

        If you want refcounting:
        - Redesign the GC header layout to include a refcount field.
        - Update incref/decref AND the collector to respect it.
        """
        a = self.asm
        a.mark('fn_decref')
        if not MEMORY_ENABLE_REFCOUNT:
            a.ret()
        lid = self.new_label_id()
        l_ret = f"decref_ret_{lid}"
        l_push = f"decref_push_{lid}"

        # tag check: (rcx & 7) == TAG_PTR(0)
        a.mov_r64_r64("rax", "rcx")  # mov rax,rcx
        a.and_r64_imm("rax", 7)  # and rax,7
        a.cmp_r64_imm("rax", 0)  # cmp rax,0
        a.jcc('ne', l_ret)

        # rdx = rcx (ptr)
        a.mov_r64_r64("rdx", "rcx")  # mov rdx,rcx

        # if rdx < heap_base -> ret
        a.mov_rax_rip_qword('heap_base')
        a.cmp_r64_r64("rdx", "rax")  # cmp rdx,rax
        a.jcc('b', l_ret)

        # if rdx >= heap_end -> ret
        a.mov_rax_rip_qword('heap_end')
        a.cmp_r64_r64("rdx", "rax")  # cmp rdx,rax
        a.jcc('ae', l_ret)

        # if refcount == 0 -> ret (avoid underflow)
        a.mov_r64_membase_disp("rax", "rdx", -16)  # mov rax,[rdx-16]
        a.test_r64_r64("rax", "rax")  # test rax,rax
        a.jcc('e', l_ret)

        # dec qword [rdx-16]
        a.dec_membase_disp_qword("rdx", -16)  # dec qword [rdx-16]

        # if refcount != 0 -> ret
        a.mov_r64_membase_disp("rax", "rdx", -16)  # mov rax,[rdx-16]
        a.test_r64_r64("rax", "rax")  # test rax,rax
        a.jcc('ne', l_ret)

        # refcount == 0 -> push block header into gc_free_head
        a.mark(l_push)
        # r9 = header = rdx - GC_HEADER_SIZE (24)
        a.lea_r64_membase_disp("r9", "rdx", -24)  # lea r9,[rdx-24]

        # rax = gc_free_head
        a.mov_rax_rip_qword('gc_free_head')

        # [r9+16] = old_head
        a.mov_membase_disp_r64("r9", 16, "rax")  # mov [r9+16], rax

        # gc_free_head = r9
        a.mov_r64_r64("rax", "r9")  # mov rax,r9
        a.mov_rip_qword_rax('gc_free_head')

        a.mark(l_ret)
        a.ret()

    def emit_heap_count_function(self) -> None:
        """Emit fn_heap_count() -> tagged int.

        Counts *live* heap blocks in the range [heap_base, heap_ptr):
        blocks whose object type (u32 at obj_ptr) is not OBJ_FREE (0).
        """
        self.ensure_gc_data()
        a = self.asm
        a.mark('fn_heap_count')

        lid = self.new_label_id()
        L_LOOP = f"heap_count_loop_{lid}"
        L_LIVE = f"heap_count_live_{lid}"
        L_DONE = f"heap_count_done_{lid}"

        # r10 = scan = heap_base
        a.mov_rax_rip_qword('heap_base')
        a.mov_r10_rax()

        # r11 = end = heap_ptr
        a.mov_rax_rip_qword('heap_ptr')
        a.mov_r64_r64("r11", "rax")

        # r8 = count = 0
        a.xor_r64_r64('r8', 'r8')

        a.mark(L_LOOP)
        # if scan >= end: done
        a.cmp_r64_r64('r10', 'r11')
        a.jcc('ae', L_DONE)

        # edx = dword [scan + GC_HEADER_SIZE]  (object type)
        a.mov_r32_membase_disp("edx", "r10", GC_HEADER_SIZE)
        # if edx != OBJ_FREE: count++
        a.cmp_r32_imm("edx", OBJ_FREE)  # cmp edx, imm8
        a.jcc('ne', L_LIVE)

        # rcx = qword [scan] (block_size)
        a.mov_r64_membase_disp('rcx', 'r10', 0)
        a.add_r64_r64('r10', 'rcx')
        a.jmp(L_LOOP)

        a.mark(L_LIVE)
        a.add_r64_imm("r8", 1)  # add r8, 1
        # rcx = qword [scan] (block_size)
        a.mov_r64_membase_disp('rcx', 'r10', 0)
        a.add_r64_r64('r10', 'rcx')
        a.jmp(L_LOOP)

        a.mark(L_DONE)
        # return enc_int(count)
        a.mov_r64_r64('rax', 'r8')
        a.shl_rax_imm8(3)
        a.or_rax_imm8(1)  # TAG_INT
        a.ret()

    def emit_heap_bytes_used_function(self) -> None:
        """Emit fn_heap_bytes_used() -> tagged int.
        Returns (heap_ptr - heap_base) as a tagged int.
        """
        self.ensure_gc_data()
        a = self.asm
        a.mark('fn_heap_bytes_used')

        a.mov_rax_rip_qword('heap_ptr')
        a.mov_r10_rax()
        a.mov_rax_rip_qword('heap_base')
        a.sub_r64_r64('r10', 'rax')
        a.mov_r64_r64('rax', 'r10')
        a.shl_rax_imm8(3)
        a.or_rax_imm8(1)  # TAG_INT
        a.ret()

    def emit_heap_bytes_committed_function(self) -> None:
        """Emit fn_heap_bytes_committed() -> tagged int.

        Returns (heap_end - heap_base) as a tagged int.
        """
        self.ensure_gc_data()
        a = self.asm
        a.mark('fn_heap_bytes_committed')

        a.mov_rax_rip_qword('heap_end')
        a.mov_r10_rax()
        a.mov_rax_rip_qword('heap_base')
        a.sub_r64_r64('r10', 'rax')
        a.mov_r64_r64('rax', 'r10')
        a.shl_rax_imm8(3)
        a.or_rax_imm8(1)  # TAG_INT
        a.ret()

    def emit_heap_bytes_reserved_function(self) -> None:
        """Emit fn_heap_bytes_reserved() -> tagged int.

        Returns (heap_reserve_end - heap_base) as a tagged int.
        """
        self.ensure_gc_data()
        a = self.asm
        a.mark('fn_heap_bytes_reserved')

        a.mov_rax_rip_qword('heap_reserve_end')
        a.mov_r10_rax()
        a.mov_rax_rip_qword('heap_base')
        a.sub_r64_r64('r10', 'rax')
        a.mov_r64_r64('rax', 'r10')
        a.shl_rax_imm8(3)
        a.or_rax_imm8(1)  # TAG_INT
        a.ret()

    def emit_heap_free_blocks_function(self) -> None:
        """Emit fn_heap_free_blocks() -> tagged int.

        Counts the number of blocks in the GC free list (gc_free_head).

        Safety:
        - Validates that each node pointer is within [heap_base+GC_HEADER_SIZE, heap_end)
          and 8-byte aligned before dereferencing.
        - If an invalid pointer is detected (corruption), returns 0 instead of crashing.
        - Hard caps iterations to avoid infinite loops on cycles.
        """
        self.ensure_gc_data()
        a = self.asm
        a.mark('fn_heap_free_blocks')

        # r8 = count (u64)
        a.xor_r32_r32('r8d', 'r8d')

        # r10 = cur
        a.mov_rax_rip_qword('gc_free_head')
        a.mov_r64_r64('r10', 'rax')

        # r11 = heap_base_payload = heap_base + GC_HEADER_SIZE
        a.mov_rax_rip_qword('heap_base')
        a.add_rax_imm8(GC_HEADER_SIZE)
        a.mov_r64_r64('r11', 'rax')

        # r9 = heap_end
        a.mov_rax_rip_qword('heap_end')
        a.mov_r64_r64('r9', 'rax')

        # r13 = iter cap
        a.mov_r64_imm64('r13', 200000)  # plenty; avoids infinite loops

        lid = self.new_label_id()
        L_LOOP = f"hfb_loop_{lid}"
        L_DONE = f"hfb_done_{lid}"
        L_BAD = f"hfb_bad_{lid}"

        a.mark(L_LOOP)
        a.cmp_r64_imm('r10', 0)
        a.jcc('e', L_DONE)

        # iter cap
        a.sub_r64_imm('r13', 1)
        a.jcc('z', L_BAD)

        # sanity: heap_base_payload <= cur < heap_end
        a.cmp_r64_r64('r10', 'r11')
        a.jcc('b', L_BAD)
        a.cmp_r64_r64('r10', 'r9')
        a.jcc('ae', L_BAD)

        # alignment
        a.test_r64_imm32('r10', 7)
        a.jcc('ne', L_BAD)

        # count++
        a.add_r32_imm('r8d', 1)

        # next = [cur + GC_OFF_NEXT_FREE]
        a.mov_r64_membase_disp('r10', 'r10', GC_OFF_NEXT_FREE)
        a.jmp(L_LOOP)

        a.mark(L_BAD)
        a.xor_r32_r32('r8d', 'r8d')

        a.mark(L_DONE)
        a.mov_r64_r64('rax', 'r8')
        a.shl_rax_imm8(3)
        a.or_rax_imm8(1)  # TAG_INT
        a.ret()

    def emit_heap_free_bytes_function(self) -> None:
        """Emit fn_heap_free_bytes() -> tagged int.

        Sums GC_OFF_BLOCK_SIZE for each free block in gc_free_head.
        Note: block_size includes the GC header (i.e. total block bytes).

        Safety:
        - Validates that each node pointer is within [heap_base+GC_HEADER_SIZE, heap_end)
          and 8-byte aligned before dereferencing.
        - If an invalid pointer is detected (corruption), returns 0 instead of crashing.
        - Hard caps iterations to avoid infinite loops on cycles.
        """
        self.ensure_gc_data()
        a = self.asm
        a.mark('fn_heap_free_bytes')

        # r8 = sum_bytes (u64)
        a.xor_r32_r32('r8d', 'r8d')

        # r10 = cur
        a.mov_rax_rip_qword('gc_free_head')
        a.mov_r64_r64('r10', 'rax')

        # r11 = heap_base_payload = heap_base + GC_HEADER_SIZE
        a.mov_rax_rip_qword('heap_base')
        a.add_rax_imm8(GC_HEADER_SIZE)
        a.mov_r64_r64('r11', 'rax')

        # r9 = heap_end
        a.mov_rax_rip_qword('heap_end')
        a.mov_r64_r64('r9', 'rax')

        # r13 = iter cap
        a.mov_r64_imm64('r13', 200000)

        lid = self.new_label_id()
        L_LOOP = f"hfb2_loop_{lid}"
        L_DONE = f"hfb2_done_{lid}"
        L_BAD = f"hfb2_bad_{lid}"

        a.mark(L_LOOP)
        a.cmp_r64_imm('r10', 0)
        a.jcc('e', L_DONE)

        a.sub_r64_imm('r13', 1)
        a.jcc('z', L_BAD)

        # sanity
        a.cmp_r64_r64('r10', 'r11')
        a.jcc('b', L_BAD)
        a.cmp_r64_r64('r10', 'r9')
        a.jcc('ae', L_BAD)
        a.test_r64_imm32('r10', 7)
        a.jcc('ne', L_BAD)

        # load size and sum
        a.mov_r64_membase_disp('rax', 'r10', GC_OFF_BLOCK_SIZE)
        a.add_r64_r64('r8', 'rax')

        # next
        a.mov_r64_membase_disp('r10', 'r10', GC_OFF_NEXT_FREE)
        a.jmp(L_LOOP)

        a.mark(L_BAD)
        a.xor_r32_r32('r8d', 'r8d')

        a.mark(L_DONE)
        a.mov_r64_r64('rax', 'r8')
        a.shl_rax_imm8(3)
        a.or_rax_imm8(1)  # TAG_INT
        a.ret()

    def emit_heap_grow_function(self) -> None:
        self.ensure_gc_data()
        a = self.asm
        a.mark("fn_heap_grow")

        cfg = getattr(self, 'heap_config', None) or {}
        grow_min = int(cfg.get('grow_min_bytes') or HEAP_GROW_MIN)

        # Win64 ABI: rbx sichern und Shadow Space reservieren
        a.push_rbx()
        a.sub_rsp_imm8(0x20)

        lid = self.new_label_id()
        l_ok = f"hg_ok_{lid}"
        l_call = f"hg_call_{lid}"
        l_fail = f"hg_fail_{lid}"
        l_done = f"hg_done_{lid}"
        l_use_min = f"hg_use_min_{lid}"

        # r11 = old_end
        a.mov_rax_rip_qword("heap_end")
        a.mov_r64_r64("r11", "rax")

        a.cmp_r64_r64("rcx", "r11")
        a.jcc("be", l_ok)

        # Wachstum berechnen
        a.mov_r64_r64("rdx", "rcx")
        a.sub_r64_r64("rdx", "r11")
        a.add_r64_imm("rdx", 4095)
        a.and_r64_imm("rdx", -4096)

        a.cmp_r64_imm("rdx", grow_min)
        a.jcc("ae", l_use_min)
        a.mov_r64_imm64("rdx", grow_min)
        a.mark(l_use_min)

        # rbx = new_end (sicher vor API-Clobbering)
        a.mov_r64_r64("rbx", "r11")
        a.add_r64_r64("rbx", "rdx")

        a.mov_rax_rip_qword("heap_reserve_end")
        a.cmp_r64_r64("rbx", "rax")
        a.jcc("be", l_call)
        a.jmp(l_fail)

        a.mark(l_call)
        a.mov_r64_r64("rcx", "r11")
        a.mov_r8d_imm32(0x1000)  # MEM_COMMIT
        a.mov_r9d_imm32(0x04)    # PAGE_READWRITE
        a.mov_rax_rip_qword("iat_VirtualAlloc")
        a.call_rax()

        a.test_r64_r64("rax", "rax")
        a.jcc("e", l_fail)

        # heap_end aus rbx aktualisieren
        a.mov_r64_r64("rax", "rbx")
        a.mov_rip_qword_rax("heap_end")

        a.mark(l_ok)
        a.xor_eax_eax()
        a.add_rax_imm8(1)
        a.jmp(l_done)

        a.mark(l_fail)
        a.xor_eax_eax()

        a.mark(l_done)
        a.add_rsp_imm8(0x20)
        a.pop_rbx()
        a.ret()
