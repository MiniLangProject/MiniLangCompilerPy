"""Native Win64 threads, synchronization and shared-heap GC coordination."""

from __future__ import annotations

from ..constants import ERROR_STRUCT_ID, OBJ_STRUCT, OBJ_THREAD, TAG_PTR
from ..tools import enc_bool, enc_void


# Every OS thread has a small native context. Managed objects themselves live
# in the process-wide GC heap; tagged references stored here are published GC
# roots for the entry argument, logical id, result and temporary values.
THREAD_TYPE = 0
THREAD_STATUS = 4
THREAD_HANDLE = 8
THREAD_ID = 16
THREAD_CODE = 24
THREAD_STOP = 32
THREAD_RESULT = 40
THREAD_ROOTS = 48
THREAD_TMP0 = 56
THREAD_NEXT = 120
THREAD_GC_STATE = 128
THREAD_ALLOC_CURSOR = 136
THREAD_ARG = 144
THREAD_LOGICAL_ID = 152
THREAD_ARITY = 160
THREAD_HEAP_BYPASS_DEPTH = 168
THREAD_CONTEXT_SIZE = 176

THREAD_CREATED = 0
THREAD_RUNNING = 1
THREAD_STOP_REQUESTED = 2
THREAD_COMPLETED = 3
THREAD_STOPPED = 4
THREAD_FAILED = 5

GC_THREAD_RUNNING = 0
GC_THREAD_PARKED = 1
GC_THREAD_NATIVE = 2
GC_THREAD_INACTIVE = 3
GC_THREAD_COLLECTOR = 4


class CodegenThreads:
    """Runtime emitters shared by Thread(...), thread methods and synchronization."""

    def ensure_thread_data(self) -> None:
        d = self.data
        if 'sync_monitor' not in d.labels:
            d.pad_align(8)
            # sizeof(CRITICAL_SECTION) == 40 on Win64.
            d.add_bytes('sync_monitor', b'\x00' * 40)
        if 'heap_monitor' not in d.labels:
            d.pad_align(8)
            d.add_bytes('heap_monitor', b'\x00' * 40)
        if 'gc_coord_monitor' not in d.labels:
            d.pad_align(8)
            d.add_bytes('gc_coord_monitor', b'\x00' * 40)
        if 'main_thread_context' not in d.labels:
            d.pad_align(8)
            d.add_bytes('main_thread_context', b'\x00' * THREAD_CONTEXT_SIZE)
        if 'thread_contexts_head' not in d.labels:
            d.add_u64('thread_contexts_head', 0)
        if 'gc_requested' not in d.labels:
            d.add_u64('gc_requested', 0)
        if 'managed_thread_count' not in d.labels:
            d.add_u64('managed_thread_count', 1)

    def emit_sync_init(self) -> None:
        self.ensure_thread_data()
        a = self.asm
        # The main thread participates in the same per-thread root protocol as
        # workers. gs:[0x28] therefore always points at a valid context while
        # MiniLang managed code is running.
        a.lea_rax_rip('main_thread_context')
        a.mov_gs_qword_28_rax()
        a.mov_membase_disp_imm32('rax', THREAD_TYPE, 0, qword=False)
        a.mov_membase_disp_imm32('rax', THREAD_RESULT, enc_void(), qword=True)
        a.mov_membase_disp_imm32('rax', THREAD_ROOTS, 0, qword=True)
        for i in range(8):
            a.mov_membase_disp_imm32('rax', THREAD_TMP0 + i * 8, enc_void(), qword=True)
        a.mov_membase_disp_imm32('rax', THREAD_NEXT, 0, qword=True)
        a.mov_membase_disp_imm32('rax', THREAD_GC_STATE, GC_THREAD_RUNNING, qword=False)
        a.mov_membase_disp_imm32('rax', THREAD_ALLOC_CURSOR, 0, qword=False)
        a.mov_membase_disp_imm32('rax', THREAD_ARG, enc_void(), qword=True)
        a.mov_membase_disp_imm32('rax', THREAD_LOGICAL_ID, enc_void(), qword=True)
        a.mov_membase_disp_imm32('rax', THREAD_ARITY, 0, qword=False)
        a.mov_membase_disp_imm32('rax', THREAD_HEAP_BYPASS_DEPTH, 0, qword=False)
        a.mov_rip_qword_rax('thread_contexts_head')
        a.xor_r32_r32('eax', 'eax')
        a.mov_rip_qword_rax('gc_requested')
        a.mov_rax_imm64(1)
        a.mov_rip_qword_rax('managed_thread_count')
        for monitor in ('sync_monitor', 'heap_monitor', 'gc_coord_monitor'):
            a.lea_rax_rip(monitor)
            a.mov_r64_r64('rcx', 'rax')
            a.mov_rax_rip_qword('iat_InitializeCriticalSection')
            a.call_rax()

    def emit_gc_safepoint_poll(self) -> None:
        """Emit a cheap cooperative GC poll at a compiler-known safe boundary."""
        if not bool(getattr(self, 'native_threads_possible', True)):
            return
        self.used_helpers.add('fn_gc_safepoint')
        a = self.asm
        done = f'gc_poll_done_{self.new_label_id()}'
        a.mov_rax_rip_qword('gc_requested')
        a.test_r64_r64('rax', 'rax')
        a.jcc('e', done)
        a.call('fn_gc_safepoint')
        a.mark(done)

    def emit_thread_cancellation_poll(self) -> None:
        """Cooperatively stop workers at function and loop boundaries."""
        if not bool(getattr(self, 'native_threads_possible', True)):
            return
        if not bool(getattr(self, 'in_function', False)) or not getattr(self, 'func_ret_label', None):
            return
        a = self.asm
        lid = self.new_label_id()
        done = f'thread_cancel_done_{lid}'
        a.mov_r11_gs_qword_28()
        a.test_r64_r64('r11', 'r11')
        a.jcc('e', done)
        a.mov_r32_membase_disp('r10d', 'r11', THREAD_TYPE)
        a.cmp_r32_imm('r10d', OBJ_THREAD)
        a.jcc('ne', done)
        a.mov_r32_membase_disp('r10d', 'r11', THREAD_STATUS)
        a.cmp_r32_imm('r10d', THREAD_STOP_REQUESTED)
        a.jcc('ne', done)
        a.mov_rax_imm64(enc_void())
        a.jmp(self.func_ret_label)
        a.mark(done)

    def _emit_managed_thread_count_delta(self, delta: int) -> None:
        """Atomically add +/-1 to the active managed-thread count."""
        a = self.asm
        lid = self.new_label_id()
        retry = f'managed_thread_count_retry_{lid}'
        a.lea_r11_rip('managed_thread_count')
        a.mark(retry)
        a.mov_r32_membase_disp('eax', 'r11', 0)
        a.mov_r32_r32('edx', 'eax')
        if int(delta) >= 0:
            a.inc_r32('edx')
        else:
            a.dec_r32('edx')
        a.lock_cmpxchg_membase_disp_r32('r11', 0, 'edx')
        a.jcc('ne', retry)

    def emit_gc_safepoint_function(self) -> None:
        self.ensure_thread_data()
        a = self.asm
        a.mark('fn_gc_safepoint')
        a.sub_rsp_imm8(0x28)
        lid = self.new_label_id()
        l_done = f'gcsafe_done_{lid}'
        l_wait = f'gcsafe_wait_{lid}'
        l_recheck = f'gcsafe_recheck_{lid}'
        l_resume = f'gcsafe_resume_{lid}'
        a.mov_rax_rip_qword('gc_requested')
        a.test_r64_r64('rax', 'rax')
        a.jcc('e', l_done)
        a.lea_rax_rip('gc_coord_monitor')
        a.mov_r64_r64('rcx', 'rax')
        a.mov_rax_rip_qword('iat_EnterCriticalSection')
        a.call_rax()
        a.mov_rax_rip_qword('gc_requested')
        a.test_r64_r64('rax', 'rax')
        a.jcc('e', l_resume)
        a.mov_r11_gs_qword_28()
        a.mov_membase_disp_imm32('r11', THREAD_GC_STATE, GC_THREAD_PARKED, qword=False)
        a.lea_rax_rip('gc_coord_monitor')
        a.mov_r64_r64('rcx', 'rax')
        a.mov_rax_rip_qword('iat_LeaveCriticalSection')
        a.call_rax()
        a.mark(l_wait)
        a.xor_r32_r32('ecx', 'ecx')
        a.mov_rax_rip_qword('iat_Sleep')
        a.call_rax()
        a.mov_rax_rip_qword('gc_requested')
        a.test_r64_r64('rax', 'rax')
        a.jcc('ne', l_wait)
        a.mark(l_recheck)
        a.lea_rax_rip('gc_coord_monitor')
        a.mov_r64_r64('rcx', 'rax')
        a.mov_rax_rip_qword('iat_EnterCriticalSection')
        a.call_rax()
        a.mov_rax_rip_qword('gc_requested')
        a.test_r64_r64('rax', 'rax')
        a.jcc('ne', l_resume)
        a.mov_r11_gs_qword_28()
        a.mov_membase_disp_imm32('r11', THREAD_GC_STATE, GC_THREAD_RUNNING, qword=False)
        a.mark(l_resume)
        a.lea_rax_rip('gc_coord_monitor')
        a.mov_r64_r64('rcx', 'rax')
        a.mov_rax_rip_qword('iat_LeaveCriticalSection')
        a.call_rax()
        a.mov_rax_rip_qword('gc_requested')
        a.test_r64_r64('rax', 'rax')
        a.jcc('ne', l_wait)
        a.mark(l_done)
        a.add_rsp_imm8(0x28)
        a.ret()

    def emit_gc_native_enter_function(self) -> None:
        self.used_helpers.add('fn_gc_safepoint')
        self.ensure_thread_data()
        a = self.asm
        a.mark('fn_gc_native_enter')
        a.sub_rsp_imm8(0x28)
        lid = self.new_label_id()
        l_retry = f'gcnative_enter_retry_{lid}'
        l_ready = f'gcnative_enter_ready_{lid}'
        a.mark(l_retry)
        a.lea_rax_rip('gc_coord_monitor')
        a.mov_r64_r64('rcx', 'rax')
        a.mov_rax_rip_qword('iat_EnterCriticalSection')
        a.call_rax()
        a.mov_rax_rip_qword('gc_requested')
        a.test_r64_r64('rax', 'rax')
        a.jcc('e', l_ready)
        a.lea_rax_rip('gc_coord_monitor')
        a.mov_r64_r64('rcx', 'rax')
        a.mov_rax_rip_qword('iat_LeaveCriticalSection')
        a.call_rax()
        a.call('fn_gc_safepoint')
        a.jmp(l_retry)
        a.mark(l_ready)
        a.mov_r11_gs_qword_28()
        a.mov_membase_disp_imm32('r11', THREAD_GC_STATE, GC_THREAD_NATIVE, qword=False)
        a.lea_rax_rip('gc_coord_monitor')
        a.mov_r64_r64('rcx', 'rax')
        a.mov_rax_rip_qword('iat_LeaveCriticalSection')
        a.call_rax()
        a.add_rsp_imm8(0x28)
        a.ret()

    def emit_gc_native_leave_function(self) -> None:
        self.ensure_thread_data()
        a = self.asm
        a.mark('fn_gc_native_leave')
        # Preserve both legal Win64 return registers across coordination calls.
        a.sub_rsp_imm8(0x38)
        a.mov_membase_disp_r64('rsp', 0x20, 'rax')
        a.movsd_membase_disp_xmm('rsp', 0x28, 'xmm0')
        lid = self.new_label_id()
        l_wait = f'gcnative_leave_wait_{lid}'
        l_lock = f'gcnative_leave_lock_{lid}'
        l_running = f'gcnative_leave_running_{lid}'
        a.mark(l_lock)
        a.lea_rax_rip('gc_coord_monitor')
        a.mov_r64_r64('rcx', 'rax')
        a.mov_rax_rip_qword('iat_EnterCriticalSection')
        a.call_rax()
        a.mov_rax_rip_qword('gc_requested')
        a.test_r64_r64('rax', 'rax')
        a.jcc('e', l_running)
        a.mov_r11_gs_qword_28()
        a.mov_membase_disp_imm32('r11', THREAD_GC_STATE, GC_THREAD_PARKED, qword=False)
        a.lea_rax_rip('gc_coord_monitor')
        a.mov_r64_r64('rcx', 'rax')
        a.mov_rax_rip_qword('iat_LeaveCriticalSection')
        a.call_rax()
        a.mark(l_wait)
        a.xor_r32_r32('ecx', 'ecx')
        a.mov_rax_rip_qword('iat_Sleep')
        a.call_rax()
        a.mov_rax_rip_qword('gc_requested')
        a.test_r64_r64('rax', 'rax')
        a.jcc('ne', l_wait)
        a.jmp(l_lock)
        a.mark(l_running)
        a.mov_r11_gs_qword_28()
        a.mov_membase_disp_imm32('r11', THREAD_GC_STATE, GC_THREAD_RUNNING, qword=False)
        a.lea_rax_rip('gc_coord_monitor')
        a.mov_r64_r64('rcx', 'rax')
        a.mov_rax_rip_qword('iat_LeaveCriticalSection')
        a.call_rax()
        a.mov_r64_membase_disp('rax', 'rsp', 0x20)
        a.movsd_xmm_membase_disp('xmm0', 'rsp', 0x28)
        a.add_rsp_imm8(0x38)
        a.ret()

    def emit_gc_managed_exit_function(self) -> None:
        self.ensure_thread_data()
        a = self.asm
        a.mark('fn_gc_managed_exit')
        a.sub_rsp_imm8(0x28)
        a.lea_rax_rip('gc_coord_monitor')
        a.mov_r64_r64('rcx', 'rax')
        a.mov_rax_rip_qword('iat_EnterCriticalSection')
        a.call_rax()
        a.mov_r11_gs_qword_28()
        a.mov_membase_disp_imm32('r11', THREAD_GC_STATE, GC_THREAD_INACTIVE, qword=False)
        a.lea_rax_rip('gc_coord_monitor')
        a.mov_r64_r64('rcx', 'rax')
        a.mov_rax_rip_qword('iat_LeaveCriticalSection')
        a.call_rax()
        a.add_rsp_imm8(0x28)
        a.ret()

    def emit_heap_enter_function(self) -> None:
        self.used_helpers.update({'fn_gc_safepoint', 'fn_gc_native_enter'})
        self.ensure_thread_data()
        a = self.asm
        a.mark('fn_heap_enter')
        lid_fast = self.new_label_id()
        l_locked = f'heap_enter_locked_{lid_fast}'
        # A single active managed thread cannot race heap metadata. Remember
        # the bypass in TLS so fn_heap_leave remains correct if another worker
        # terminates while a genuinely locked outer operation is still active.
        a.mov_rax_rip_qword('managed_thread_count')
        a.cmp_r64_imm('rax', 1)
        a.jcc('a', l_locked)
        a.mov_r11_gs_qword_28()
        a.mov_r32_membase_disp('r10d', 'r11', THREAD_HEAP_BYPASS_DEPTH)
        a.inc_r32('r10d')
        a.mov_membase_disp_r32('r11', THREAD_HEAP_BYPASS_DEPTH, 'r10d')
        a.ret()
        a.mark(l_locked)
        a.sub_rsp_imm8(0x28)
        lid = self.new_label_id()
        l_retry = f'heap_enter_retry_{lid}'
        l_owned = f'heap_enter_owned_{lid}'
        a.mark(l_retry)
        a.call('fn_gc_safepoint')
        a.call('fn_gc_native_enter')
        a.lea_rax_rip('heap_monitor')
        a.mov_r64_r64('rcx', 'rax')
        a.mov_rax_rip_qword('iat_EnterCriticalSection')
        a.call_rax()
        a.lea_rax_rip('gc_coord_monitor')
        a.mov_r64_r64('rcx', 'rax')
        a.mov_rax_rip_qword('iat_EnterCriticalSection')
        a.call_rax()
        a.mov_rax_rip_qword('gc_requested')
        a.test_r64_r64('rax', 'rax')
        a.jcc('e', l_owned)
        a.lea_rax_rip('gc_coord_monitor')
        a.mov_r64_r64('rcx', 'rax')
        a.mov_rax_rip_qword('iat_LeaveCriticalSection')
        a.call_rax()
        a.lea_rax_rip('heap_monitor')
        a.mov_r64_r64('rcx', 'rax')
        a.mov_rax_rip_qword('iat_LeaveCriticalSection')
        a.call_rax()
        a.call('fn_gc_safepoint')
        a.jmp(l_retry)
        a.mark(l_owned)
        a.mov_r11_gs_qword_28()
        a.mov_membase_disp_imm32('r11', THREAD_GC_STATE, GC_THREAD_RUNNING, qword=False)
        a.lea_rax_rip('gc_coord_monitor')
        a.mov_r64_r64('rcx', 'rax')
        a.mov_rax_rip_qword('iat_LeaveCriticalSection')
        a.call_rax()
        a.add_rsp_imm8(0x28)
        a.ret()

    def emit_heap_leave_function(self) -> None:
        self.ensure_thread_data()
        a = self.asm
        a.mark('fn_heap_leave')
        lid = self.new_label_id()
        l_locked = f'heap_leave_locked_{lid}'
        a.mov_r11_gs_qword_28()
        a.mov_r32_membase_disp('r10d', 'r11', THREAD_HEAP_BYPASS_DEPTH)
        a.test_r32_r32('r10d', 'r10d')
        a.jcc('e', l_locked)
        a.dec_r32('r10d')
        a.mov_membase_disp_r32('r11', THREAD_HEAP_BYPASS_DEPTH, 'r10d')
        a.ret()
        a.mark(l_locked)
        a.sub_rsp_imm8(0x38)
        a.mov_membase_disp_r64('rsp', 0x20, 'rax')
        a.movsd_membase_disp_xmm('rsp', 0x28, 'xmm0')
        a.lea_rax_rip('heap_monitor')
        a.mov_r64_r64('rcx', 'rax')
        a.mov_rax_rip_qword('iat_LeaveCriticalSection')
        a.call_rax()
        a.mov_r64_membase_disp('rax', 'rsp', 0x20)
        a.movsd_xmm_membase_disp('xmm0', 'rsp', 0x28)
        a.add_rsp_imm8(0x38)
        a.ret()

    def emit_gc_world_stop_function(self) -> None:
        self.ensure_thread_data()
        a = self.asm
        a.mark('fn_gc_world_stop')
        a.sub_rsp_imm8(0x38)
        a.mov_r11_gs_qword_28()
        a.mov_membase_disp_r64('rsp', 0x30, 'r11')
        lid = self.new_label_id()
        l_wait = f'gcworld_wait_{lid}'
        l_scan = f'gcworld_scan_{lid}'
        l_next = f'gcworld_next_{lid}'
        l_not_ready = f'gcworld_not_ready_{lid}'
        l_ready = f'gcworld_ready_{lid}'
        a.lea_rax_rip('gc_coord_monitor')
        a.mov_r64_r64('rcx', 'rax')
        a.mov_rax_rip_qword('iat_EnterCriticalSection')
        a.call_rax()
        a.mov_r11_gs_qword_28()
        a.mov_membase_disp_imm32('r11', THREAD_GC_STATE, GC_THREAD_COLLECTOR, qword=False)
        a.mov_rax_imm64(1)
        a.mov_rip_qword_rax('gc_requested')
        a.lea_rax_rip('gc_coord_monitor')
        a.mov_r64_r64('rcx', 'rax')
        a.mov_rax_rip_qword('iat_LeaveCriticalSection')
        a.call_rax()
        a.mark(l_wait)
        a.lea_rax_rip('gc_coord_monitor')
        a.mov_r64_r64('rcx', 'rax')
        a.mov_rax_rip_qword('iat_EnterCriticalSection')
        a.call_rax()
        a.mov_rax_rip_qword('thread_contexts_head')
        a.mov_r64_r64('r11', 'rax')
        a.mark(l_scan)
        a.test_r64_r64('r11', 'r11')
        a.jcc('e', l_ready)
        a.mov_r64_membase_disp('r10', 'rsp', 0x30)
        a.cmp_r64_r64('r11', 'r10')
        a.jcc('e', l_next)
        a.mov_r32_membase_disp('eax', 'r11', THREAD_GC_STATE)
        a.cmp_r32_imm('eax', GC_THREAD_RUNNING)
        a.jcc('e', l_not_ready)
        a.mark(l_next)
        a.mov_r64_membase_disp('r11', 'r11', THREAD_NEXT)
        a.jmp(l_scan)
        a.mark(l_not_ready)
        a.lea_rax_rip('gc_coord_monitor')
        a.mov_r64_r64('rcx', 'rax')
        a.mov_rax_rip_qword('iat_LeaveCriticalSection')
        a.call_rax()
        a.xor_r32_r32('ecx', 'ecx')
        a.mov_rax_rip_qword('iat_Sleep')
        a.call_rax()
        a.jmp(l_wait)
        a.mark(l_ready)
        a.lea_rax_rip('gc_coord_monitor')
        a.mov_r64_r64('rcx', 'rax')
        a.mov_rax_rip_qword('iat_LeaveCriticalSection')
        a.call_rax()
        a.add_rsp_imm8(0x38)
        a.ret()

    def emit_gc_world_resume_function(self) -> None:
        self.ensure_thread_data()
        a = self.asm
        a.mark('fn_gc_world_resume')
        a.sub_rsp_imm8(0x28)
        a.lea_rax_rip('gc_coord_monitor')
        a.mov_r64_r64('rcx', 'rax')
        a.mov_rax_rip_qword('iat_EnterCriticalSection')
        a.call_rax()
        a.xor_r32_r32('eax', 'eax')
        a.mov_rip_qword_rax('gc_requested')
        a.mov_r11_gs_qword_28()
        a.mov_membase_disp_imm32('r11', THREAD_GC_STATE, GC_THREAD_RUNNING, qword=False)
        a.lea_rax_rip('gc_coord_monitor')
        a.mov_r64_r64('rcx', 'rax')
        a.mov_rax_rip_qword('iat_LeaveCriticalSection')
        a.call_rax()
        a.add_rsp_imm8(0x28)
        a.ret()

    def emit_sync_enter_function(self) -> None:
        self.used_helpers.update({'fn_gc_native_enter', 'fn_gc_native_leave'})
        self.ensure_thread_data()
        a = self.asm
        a.mark('fn_sync_enter')
        a.sub_rsp_imm8(0x28)
        a.call('fn_gc_native_enter')
        a.lea_rax_rip('sync_monitor')
        a.mov_r64_r64('rcx', 'rax')
        a.mov_rax_rip_qword('iat_EnterCriticalSection')
        a.call_rax()
        # A thread may have blocked on the user monitor. Do not execute managed
        # code until a concurrently active collection has resumed the world.
        a.call('fn_gc_native_leave')
        a.add_rsp_imm8(0x28)
        a.ret()

    def emit_sync_leave_function(self) -> None:
        self.ensure_thread_data()
        a = self.asm
        a.mark('fn_sync_leave')
        # Preserve the MiniLang expression result in RAX across the WinAPI call.
        a.push_reg('rax')
        a.sub_rsp_imm8(0x20)
        a.lea_rax_rip('sync_monitor')
        a.mov_r64_r64('rcx', 'rax')
        a.mov_rax_rip_qword('iat_LeaveCriticalSection')
        a.call_rax()
        a.add_rsp_imm8(0x20)
        a.pop_reg('rax')
        a.ret()

    def emit_thread_new_function(self) -> None:
        """RCX=entry code, EDX=entry arity, R8=logical id; returns context."""
        self.ensure_thread_data()
        a = self.asm
        a.mark('fn_thread_new')
        a.sub_rsp_imm8(0x58)
        a.mov_membase_disp_r64('rsp', 0x38, 'rcx')
        a.mov_membase_disp_r64('rsp', 0x40, 'rdx')
        a.mov_membase_disp_r64('rsp', 0x48, 'r8')
        a.xor_r32_r32('ecx', 'ecx')
        a.mov_r32_imm32('edx', THREAD_CONTEXT_SIZE)
        a.mov_r8d_imm32(0x3000)  # MEM_RESERVE | MEM_COMMIT
        a.mov_r9d_imm32(0x04)    # PAGE_READWRITE
        a.mov_rax_rip_qword('iat_VirtualAlloc')
        a.call_rax()
        lid = self.new_label_id()
        l_done = f'thnew_done_{lid}'
        a.test_r64_r64('rax', 'rax')
        a.jcc('e', l_done)
        a.mov_membase_disp_r64('rsp', 0x30, 'rax')
        a.mov_membase_disp_imm32('rax', THREAD_TYPE, OBJ_THREAD, qword=False)
        a.mov_membase_disp_imm32('rax', THREAD_STATUS, THREAD_CREATED, qword=False)
        a.mov_r64_membase_disp('r11', 'rsp', 0x38)
        a.mov_membase_disp_r64('rax', THREAD_CODE, 'r11')
        a.mov_membase_disp_imm32('rax', THREAD_RESULT, enc_void(), qword=True)
        a.mov_membase_disp_imm32('rax', THREAD_ROOTS, 0, qword=True)
        for i in range(8):
            a.mov_membase_disp_imm32('rax', THREAD_TMP0 + i * 8, enc_void(), qword=True)
        a.mov_membase_disp_imm32('rax', THREAD_GC_STATE, GC_THREAD_INACTIVE, qword=False)
        a.mov_membase_disp_imm32('rax', THREAD_ALLOC_CURSOR, 0, qword=False)
        a.mov_membase_disp_imm32('rax', THREAD_ARG, enc_void(), qword=True)
        a.mov_r64_membase_disp('r11', 'rsp', 0x48)
        a.mov_membase_disp_r64('rax', THREAD_LOGICAL_ID, 'r11')
        a.mov_r32_membase_disp('r11d', 'rsp', 0x40)
        a.mov_membase_disp_r32('rax', THREAD_ARITY, 'r11d')
        a.mov_membase_disp_imm32('rax', THREAD_HEAP_BYPASS_DEPTH, 0, qword=False)
        # Contexts remain registered for the process lifetime. Close() clears
        # their managed roots, so registration itself cannot retain user data.
        a.lea_rax_rip('gc_coord_monitor')
        a.mov_r64_r64('rcx', 'rax')
        a.mov_rax_rip_qword('iat_EnterCriticalSection')
        a.call_rax()
        a.mov_rax_rip_qword('thread_contexts_head')
        a.mov_r64_membase_disp('r11', 'rsp', 0x30)
        a.mov_membase_disp_r64('r11', THREAD_NEXT, 'rax')
        a.mov_r64_r64('rax', 'r11')
        a.mov_rip_qword_rax('thread_contexts_head')
        a.lea_rax_rip('gc_coord_monitor')
        a.mov_r64_r64('rcx', 'rax')
        a.mov_rax_rip_qword('iat_LeaveCriticalSection')
        a.call_rax()
        a.mov_r64_membase_disp('rax', 'rsp', 0x30)
        a.mark(l_done)
        a.add_rsp_imm8(0x58)
        a.ret()

    def emit_thread_start_function(self) -> None:
        """RCX=context, RDX=tagged argument, R8D=argument count; returns bool."""
        self.used_helpers.add('fn_thread_entry')
        a = self.asm
        a.mark('fn_thread_start')
        a.sub_rsp_imm8(0x58)
        a.mov_membase_disp_r64('rsp', 0x30, 'rcx')
        lid = self.new_label_id()
        l_not_created = f'thstart_not_created_{lid}'
        l_wrong_arity = f'thstart_wrong_arity_{lid}'
        l_create_fail = f'thstart_create_fail_{lid}'
        l_done = f'thstart_done_{lid}'
        a.mov_r32_membase_disp('eax', 'rcx', THREAD_STATUS)
        a.cmp_r32_imm('eax', THREAD_CREATED)
        a.jcc('ne', l_not_created)
        a.mov_r32_membase_disp('eax', 'rcx', THREAD_ARITY)
        a.cmp_r32_r32('eax', 'r8d')
        a.jcc('ne', l_wrong_arity)
        a.mov_membase_disp_imm32('rcx', THREAD_STOP, 0, qword=False)
        a.mov_membase_disp_r64('rcx', THREAD_ARG, 'rdx')
        a.mov_membase_disp_imm32('rcx', THREAD_STATUS, THREAD_RUNNING, qword=False)
        # Count the worker before CreateThread can enter managed execution.
        self._emit_managed_thread_count_delta(1)
        a.xor_r32_r32('eax', 'eax')
        a.mov_membase_disp_r64('rsp', 0x20, 'rax')  # creation flags
        a.lea_r64_membase_disp('rax', 'rsp', 0x40)  # thread id destination
        a.mov_membase_disp_r64('rsp', 0x28, 'rax')
        a.xor_r32_r32('ecx', 'ecx')
        a.xor_r32_r32('edx', 'edx')
        a.lea_r8_rip('fn_thread_entry')
        a.mov_r64_membase_disp('r9', 'rsp', 0x30)
        a.mov_rax_rip_qword('iat_CreateThread')
        a.call_rax()
        a.mov_r64_membase_disp('r11', 'rsp', 0x30)
        a.test_r64_r64('rax', 'rax')
        a.jcc('e', l_create_fail)
        a.mov_membase_disp_r64('r11', THREAD_HANDLE, 'rax')
        a.mov_r32_membase_disp('eax', 'rsp', 0x40)
        a.mov_membase_disp_r32('r11', THREAD_ID, 'eax')
        a.mov_rax_imm64(enc_bool(True))
        a.jmp(l_done)
        a.mark(l_create_fail)
        a.mov_r64_membase_disp('r11', 'rsp', 0x30)
        a.mov_membase_disp_imm32('r11', THREAD_STATUS, THREAD_FAILED, qword=False)
        a.mov_membase_disp_imm32('r11', THREAD_ARG, enc_void(), qword=True)
        self._emit_managed_thread_count_delta(-1)
        a.mark(l_wrong_arity)
        a.mark(l_not_created)
        a.mov_rax_imm64(enc_bool(False))
        a.mark(l_done)
        a.add_rsp_imm8(0x58)
        a.ret()

    def emit_thread_stop_function(self) -> None:
        a = self.asm
        a.mark('fn_thread_stop')
        lid = self.new_label_id()
        l_false = f'thstop_false_{lid}'
        l_done = f'thstop_done_{lid}'
        a.mov_r32_imm32('eax', THREAD_RUNNING)
        a.mov_r32_imm32('edx', THREAD_STOP_REQUESTED)
        a.lock_cmpxchg_membase_disp_r32('rcx', THREAD_STATUS, 'edx')
        a.cmp_r32_imm('eax', THREAD_RUNNING)
        a.jcc('ne', l_false)
        a.mov_rax_imm64(enc_bool(True))
        a.jmp(l_done)
        a.mark(l_false)
        a.mov_rax_imm64(enc_bool(False))
        a.mark(l_done)
        a.ret()

    def emit_thread_join_function(self) -> None:
        """RCX=thread object, EDX=raw timeout milliseconds; returns bool."""
        self.used_helpers.update({'fn_gc_native_enter', 'fn_gc_native_leave'})
        a = self.asm
        a.mark('fn_thread_join')
        a.sub_rsp_imm8(0x38)
        a.mov_membase_disp_r64('rsp', 0x20, 'rcx')
        a.mov_membase_disp_r64('rsp', 0x28, 'rdx')
        lid = self.new_label_id()
        l_false = f'thjoin_false_{lid}'
        l_done = f'thjoin_done_{lid}'
        a.call('fn_gc_native_enter')
        a.mov_r64_membase_disp('r11', 'rsp', 0x20)
        a.mov_r64_membase_disp('rax', 'r11', THREAD_HANDLE)
        a.test_r64_r64('rax', 'rax')
        a.jcc('e', l_false)
        a.mov_r64_r64('rcx', 'rax')
        a.mov_r32_membase_disp('edx', 'rsp', 0x28)
        a.mov_rax_rip_qword('iat_WaitForSingleObject')
        a.call_rax()
        a.call('fn_gc_native_leave')
        a.cmp_r32_imm('eax', 0)  # WAIT_OBJECT_0
        a.jcc('ne', l_false)
        a.mov_rax_imm64(enc_bool(True))
        a.jmp(l_done)
        a.mark(l_false)
        # If the handle was absent, balance the native transition before
        # returning. On the wait-failure path native_leave already ran.
        l_false_ready = f'thjoin_false_ready_{lid}'
        a.mov_r11_gs_qword_28()
        a.mov_r32_membase_disp('r10d', 'r11', THREAD_GC_STATE)
        a.cmp_r32_imm('r10d', GC_THREAD_NATIVE)
        a.jcc('ne', l_false_ready)
        a.call('fn_gc_native_leave')
        a.mark(l_false_ready)
        a.mov_rax_imm64(enc_bool(False))
        a.mark(l_done)
        a.add_rsp_imm8(0x38)
        a.ret()

    def emit_thread_alive_function(self) -> None:
        a = self.asm
        a.mark('fn_thread_alive')
        lid = self.new_label_id()
        l_true = f'thalive_true_{lid}'
        l_done = f'thalive_done_{lid}'
        a.mov_r32_membase_disp('eax', 'rcx', THREAD_STATUS)
        a.cmp_r32_imm('eax', THREAD_RUNNING)
        a.jcc('e', l_true)
        a.cmp_r32_imm('eax', THREAD_STOP_REQUESTED)
        a.jcc('e', l_true)
        a.mov_rax_imm64(enc_bool(False))
        a.jmp(l_done)
        a.mark(l_true)
        a.mov_rax_imm64(enc_bool(True))
        a.mark(l_done)
        a.ret()

    def emit_thread_id_function(self) -> None:
        a = self.asm
        a.mark('fn_thread_id')
        a.mov_r32_membase_disp('eax', 'rcx', THREAD_ID)
        a.shl_rax_imm8(3)
        a.or_rax_imm8(1)
        a.ret()

    def emit_thread_logical_id_function(self) -> None:
        a = self.asm
        a.mark('fn_thread_logical_id')
        a.mov_r64_membase_disp('rax', 'rcx', THREAD_LOGICAL_ID)
        a.ret()

    def emit_thread_set_logical_id_function(self) -> None:
        """Set a user-defined id before Start(). RCX=context, RDX=value."""
        a = self.asm
        a.mark('fn_thread_set_logical_id')
        lid = self.new_label_id()
        l_false = f'thsetid_false_{lid}'
        l_done = f'thsetid_done_{lid}'
        a.mov_r32_membase_disp('eax', 'rcx', THREAD_STATUS)
        a.cmp_r32_imm('eax', THREAD_CREATED)
        a.jcc('ne', l_false)
        a.mov_membase_disp_r64('rcx', THREAD_LOGICAL_ID, 'rdx')
        a.mov_rax_imm64(enc_bool(True))
        a.jmp(l_done)
        a.mark(l_false)
        a.mov_rax_imm64(enc_bool(False))
        a.mark(l_done)
        a.ret()

    def emit_thread_result_function(self) -> None:
        a = self.asm
        a.mark('fn_thread_result')
        a.mov_r64_membase_disp('rax', 'rcx', THREAD_RESULT)
        a.ret()

    def emit_thread_current_logical_id_function(self) -> None:
        a = self.asm
        a.mark('fn_thread_current_logical_id')
        a.mov_r11_gs_qword_28()
        a.mov_r64_membase_disp('rax', 'r11', THREAD_LOGICAL_ID)
        a.ret()

    def emit_thread_status_function(self) -> None:
        for lbl, value in (
            ('obj_thread_created', 'Created'), ('obj_thread_running', 'Running'),
            ('obj_thread_stop_requested', 'StopRequested'), ('obj_thread_completed', 'Completed'),
            ('obj_thread_stopped', 'Stopped'), ('obj_thread_failed', 'Failed')):
            if lbl not in self.rdata.labels:
                self.rdata.add_obj_string(lbl, value)
        a = self.asm
        a.mark('fn_thread_status')
        lid = self.new_label_id()
        done = f'thstatus_done_{lid}'
        a.mov_r32_membase_disp('eax', 'rcx', THREAD_STATUS)
        labels = ('obj_thread_created', 'obj_thread_running', 'obj_thread_stop_requested',
                  'obj_thread_completed', 'obj_thread_stopped', 'obj_thread_failed')
        for status, lbl in enumerate(labels):
            case = f'thstatus_{status}_{lid}'
            a.cmp_r32_imm('eax', status)
            a.jcc('e', case)
        a.lea_rax_rip('obj_thread_failed')
        a.jmp(done)
        for status, lbl in enumerate(labels):
            case = f'thstatus_{status}_{lid}'
            a.mark(case)
            a.lea_rax_rip(lbl)
            a.jmp(done)
        a.mark(done)
        a.ret()

    def emit_thread_close_function(self) -> None:
        a = self.asm
        a.mark('fn_thread_close')
        a.sub_rsp_imm8(0x38)
        a.mov_membase_disp_r64('rsp', 0x30, 'rcx')
        lid = self.new_label_id()
        l_false = f'thclose_false_{lid}'
        l_done = f'thclose_done_{lid}'
        a.mov_r32_membase_disp('eax', 'rcx', THREAD_STATUS)
        a.cmp_r32_imm('eax', THREAD_RUNNING)
        a.jcc('e', l_false)
        a.cmp_r32_imm('eax', THREAD_STOP_REQUESTED)
        a.jcc('e', l_false)
        a.mov_r64_membase_disp('rcx', 'rcx', THREAD_HANDLE)
        a.test_r64_r64('rcx', 'rcx')
        a.jcc('e', l_false)
        a.mov_rax_rip_qword('iat_CloseHandle')
        a.call_rax()
        a.mov_r64_membase_disp('r11', 'rsp', 0x30)
        a.mov_membase_disp_imm32('r11', THREAD_HANDLE, 0, qword=True)
        a.mov_membase_disp_imm32('r11', THREAD_CODE, enc_void(), qword=True)
        a.mov_membase_disp_imm32('r11', THREAD_RESULT, enc_void(), qword=True)
        a.mov_membase_disp_imm32('r11', THREAD_ARG, enc_void(), qword=True)
        a.mov_membase_disp_imm32('r11', THREAD_LOGICAL_ID, enc_void(), qword=True)
        for i in range(8):
            a.mov_membase_disp_imm32('r11', THREAD_TMP0 + i * 8, enc_void(), qword=True)
        a.mov_rax_imm64(enc_bool(True))
        a.jmp(l_done)
        a.mark(l_false)
        a.mov_rax_imm64(enc_bool(False))
        a.mark(l_done)
        a.add_rsp_imm8(0x38)
        a.ret()

    def emit_thread_stop_requested_function(self) -> None:
        a = self.asm
        a.mark('fn_thread_stop_requested')
        lid = self.new_label_id()
        l_false = f'thsr_false_{lid}'
        l_done = f'thsr_done_{lid}'
        a.mov_r11_gs_qword_28()
        a.mov_r32_membase_disp('eax', 'r11', THREAD_TYPE)
        a.cmp_r32_imm('eax', OBJ_THREAD)
        a.jcc('ne', l_false)
        a.mov_r32_membase_disp('eax', 'r11', THREAD_STATUS)
        a.cmp_r32_imm('eax', THREAD_STOP_REQUESTED)
        a.jcc('ne', l_false)
        a.mov_rax_imm64(enc_bool(True))
        a.jmp(l_done)
        a.mark(l_false)
        a.mov_rax_imm64(enc_bool(False))
        a.mark(l_done)
        a.ret()

    def emit_thread_alloc_function(self) -> None:
        """Compatibility label: every thread now uses the global allocator."""
        self.used_helpers.add('fn_alloc')
        a = self.asm
        a.mark('fn_thread_alloc')
        a.jmp('fn_alloc')

    def emit_thread_entry_function(self) -> None:
        self.used_helpers.update({'fn_gc_native_leave', 'fn_gc_managed_exit'})
        a = self.asm
        a.mark('fn_thread_entry')
        a.push_reg('rbx')
        a.push_reg('r12')
        a.sub_rsp_imm8(0x28)
        a.mov_r64_r64('r12', 'rcx')
        a.mov_r64_r64('rax', 'rcx')
        a.mov_gs_qword_28_rax()
        lid = self.new_label_id()
        l_finish = f'thentry_finish_{lid}'
        l_finalize = f'thentry_finalize_{lid}'

        # User functions preserve RBX because the main runtime keeps stdout
        # there. Native worker entry points do not inherit the main thread's
        # register state, so initialize and preserve it explicitly.
        a.mov_rcx_imm32(0xFFFFFFF5)  # STD_OUTPUT_HANDLE = -11
        a.mov_rax_rip_qword('iat_GetStdHandle')
        a.call_rax()
        a.mov_rbx_rax()

        # Enter managed execution. A collection already in progress keeps this
        # worker parked before it can touch the shared heap.
        a.call('fn_gc_native_leave')

        # Invoke the capture-free MiniLang function with its published argument.
        a.mov_r64_imm64('r10', enc_void())
        a.mov_r64_membase_disp('rcx', 'r12', THREAD_ARG)
        # Once managed execution is running, the callee's parameter slot is the
        # precise root. No safepoint exists between this clear and its prologue.
        a.mov_membase_disp_imm32('r12', THREAD_ARG, enc_void(), qword=True)
        a.mov_r64_membase_disp('rax', 'r12', THREAD_CODE)
        a.call_rax()
        a.mov_membase_disp_r64('r12', THREAD_RESULT, 'rax')
        # An automatically propagated MiniLang error marks the worker Failed.
        l_not_error = f'thentry_not_error_{lid}'
        a.mov_r64_r64('r11', 'rax')
        a.and_r64_imm('r11', 7)
        a.cmp_r64_imm('r11', TAG_PTR)
        a.jcc('ne', l_not_error)
        a.mov_r32_membase_disp('r11d', 'rax', 0)
        a.cmp_r32_imm('r11d', OBJ_STRUCT)
        a.jcc('ne', l_not_error)
        a.mov_r32_membase_disp('r11d', 'rax', 4)
        a.cmp_r32_imm('r11d', ERROR_STRUCT_ID)
        a.jcc('ne', l_not_error)
        a.mov_r32_imm32('edx', THREAD_FAILED)
        a.jmp(l_finalize)
        a.mark(l_not_error)
        a.mov_r32_imm32('edx', THREAD_COMPLETED)
        a.mark(l_finalize)
        # Atomically publish the terminal state without losing a Stop() racing
        # with function completion or error propagation.
        a.mov_r32_imm32('eax', THREAD_RUNNING)
        a.lock_cmpxchg_membase_disp_r32('r12', THREAD_STATUS, 'edx')
        a.cmp_r32_imm('eax', THREAD_STOP_REQUESTED)
        a.jcc('ne', l_finish)
        a.mov_membase_disp_imm32('r12', THREAD_STATUS, THREAD_STOPPED, qword=False)
        a.jmp(l_finish)
        a.mark(l_finish)
        # The stack-root chain is empty after the user function epilogue. Mark
        # the context inactive; its published result remains a registered root
        # until Close() clears it.
        a.call('fn_gc_managed_exit')
        self._emit_managed_thread_count_delta(-1)
        a.xor_r32_r32('eax', 'eax')
        a.mov_gs_qword_28_rax()
        a.add_rsp_imm8(0x28)
        a.pop_reg('r12')
        a.pop_reg('rbx')
        a.ret()
