"""Optional Windows snapshot-at-the-beginning collector and deletion log.

The persistent native worker never enters managed application code. Keep helper
emission order, register preservation and data layout identical to the ML port.
"""

SATB_CAPACITY = 1048576
HEAP_LOCK_DEPTH = 208


class CodegenConcurrentGC:
    """Emit the worker, request/wait protocol and allocation-free SATB helpers."""

    def _gc_satb_capacity(self):
        """Capacity is in qwords; clamp the diagnostic byte limit before division."""
        return min(67108864, max(64, int(self.heap_config.get('gc_satb_limit_bytes', SATB_CAPACITY * 8)))) // 8

    def ensure_concurrent_gc_data(self):
        """Materialize optional worker state without changing default-mode data."""
        self.ensure_gc_data()
        for name in ["gc_concurrent_handle", "gc_concurrent_go", "gc_concurrent_done", "gc_concurrent_frontier", "gc_concurrent_free_head", "gc_concurrent_free_tail", "gc_concurrent_pause_start", "gc_satb_active", "gc_satb_count", "gc_satb_lock", "gc_satb_overflow"]:
            if name not in self.data.labels:
                self.data.add_u64(name, 0)
        if 'gc_concurrent_context' not in self.data.labels:
            self.data.pad_align(8)
            self.data.add_bytes('gc_concurrent_context', bytes(216))
        if 'gc_satb_buffer' not in self.bss.labels:
            self.bss.reserve('gc_satb_buffer', self._gc_satb_capacity() * 8, align=8)

    def emit_concurrent_gc_satb_record(self):
        """Emit a nonallocating leaf that logs RAX and preserves all registers."""
        a = self.asm
        self.ensure_concurrent_gc_data()
        a.mark("fn_gc_satb_record")
        a.push_reg("rcx")
        a.mov_r64_r64("rcx", "rax")
        a.mov_rax_rip_qword("gc_satb_active")
        a.test_r64_r64("rax", "rax")
        a.jcc("e", "satb_record_done")
        a.test_r64_imm32("rcx", 7)
        a.jcc("ne", "satb_record_done")
        a.mov_rax_rip_qword("heap_base")
        a.add_r64_imm("rax", 8)
        a.cmp_r64_r64("rcx", "rax")
        a.jcc("b", "satb_record_done")
        a.mov_rax_rip_qword("gc_concurrent_frontier")
        a.cmp_r64_r64("rcx", "rax")
        a.jcc("ae", "satb_record_done")
        a.push_reg("rdx")
        a.push_reg("r10")
        a.push_reg("r11")
        a.mov_r64_r64("r10", "rcx")
        # Marked values (including gray objects) already belong to the snapshot.
        # Filtering these duplicate deletions bounds log growth and worker traffic.
        a.mov_rax_rip_qword("heap_base")
        a.mov_r64_r64("r11", "rcx")
        a.sub_r64_r64("r11", "rax")
        a.sub_r64_imm("r11", 8)
        a.shr_r64_imm8("r11", 3)
        a.mov_r64_r64("rdx", "r11")
        a.shr_r64_imm8("rdx", 6)
        a.mov_rax_rip_qword("gc_mark_bits_base")
        a.mov_r64_mem_bis("rax", "rax", "rdx", 8, 0)
        a.bt_r64_r64("rax", "r11")
        a.jcc("b", "satb_record_restore")
        a.lea_r64_rip("r11", "gc_satb_lock")
        a.mark("satb_record_lock")
        a.xor_r32_r32("eax", "eax")
        a.mov_r32_imm32("edx", 1)
        a.lock_cmpxchg_membase_disp_r32("r11", 0, "edx")
        a.jcc("e", "satb_record_owned")
        a.emit(bytes.fromhex("f390"))
        a.jmp("satb_record_lock")
        a.mark("satb_record_owned")
        a.mov_rax_rip_qword("gc_satb_count")
        a.cmp_r64_imm("rax", self._gc_satb_capacity())
        a.jcc("ae", "satb_record_overflow")
        a.lea_r64_rip("rdx", "gc_satb_buffer")
        a.mov_mem_bis_r64("rdx", "rax", 8, 0, "r10")
        a.inc_r64("rax")
        a.mov_rip_qword_rax("gc_satb_count")
        a.jmp("satb_record_unlock")
        a.mark("satb_record_overflow")
        # Never drop an edge and then reclaim. Overflow retains the entire snapshot.
        a.mov_rax_imm64(1)
        a.mov_rip_qword_rax("gc_satb_overflow")
        a.mark("satb_record_unlock")
        a.mov_membase_disp_imm32("r11", 0, 0, qword=False)
        a.mark("satb_record_restore")
        a.pop_reg("r11")
        a.pop_reg("r10")
        a.pop_reg("rdx")
        a.mark("satb_record_done")
        a.mov_r64_r64("rax", "rcx")
        a.pop_reg("rcx")
        a.ret()
        return

    def emit_concurrent_gc_satb_pop(self):
        """Pop one logged reference under the spinlock; return zero when empty."""
        a = self.asm
        self.ensure_concurrent_gc_data()
        a.mark("fn_gc_satb_pop")
        a.lea_r64_rip("r11", "gc_satb_lock")
        a.mark("satb_pop_lock")
        a.xor_r32_r32("eax", "eax")
        a.mov_r32_imm32("edx", 1)
        a.lock_cmpxchg_membase_disp_r32("r11", 0, "edx")
        a.jcc("e", "satb_pop_owned")
        a.emit(bytes.fromhex("f390"))
        a.jmp("satb_pop_lock")
        a.mark("satb_pop_owned")
        a.mov_rax_rip_qword("gc_satb_count")
        a.test_r64_r64("rax", "rax")
        a.jcc("e", "satb_pop_empty")
        a.dec_r64("rax")
        a.mov_rip_qword_rax("gc_satb_count")
        a.lea_r64_rip("rdx", "gc_satb_buffer")
        a.mov_r64_mem_bis("rax", "rdx", "rax", 8, 0)
        a.mark("satb_pop_empty")
        a.mov_membase_disp_imm32("r11", 0, 0, qword=False)
        a.ret()
        return

    def emit_concurrent_gc_worker(self):
        """Emit the native worker's private context and persistent event loop."""
        a = self.asm
        self.ensure_concurrent_gc_data()
        self.used_helpers.update(["fn_gc_concurrent_cycle"])
        a.mark("fn_gc_concurrent_worker")
        a.sub_rsp_imm8(0x28)
        a.lea_rax_rip("gc_concurrent_context")
        a.mov_gs_qword_28_rax()
        a.mark("gc_worker_wait")
        a.mov_rax_rip_qword("gc_concurrent_go")
        a.mov_r64_r64("rcx", "rax")
        a.mov_r32_imm32("edx", -1)
        a.mov_rax_rip_qword("iat_WaitForSingleObject")
        a.call_rax()
        a.call("fn_gc_concurrent_cycle")
        a.jmp("gc_worker_wait")
        return

    def emit_concurrent_gc_request(self):
        """Coalesce requests under the monitor and return a completion sequence."""
        a = self.asm
        self.ensure_concurrent_gc_data()
        self.used_helpers.update(["fn_gc_concurrent_worker", "fn_heap_enter", "fn_heap_leave"])
        a.mark("fn_gc_concurrent_request")
        a.sub_rsp_imm8(0x38)
        a.call("fn_heap_enter")
        a.mov_rax_rip_qword("gc_concurrent_phase")
        a.mov_membase_disp_r64("rsp", 0x30, "rax")
        a.test_r64_r64("rax", "rax")
        a.jcc("ne", "gc_request_return")
        a.mov_rax_rip_qword("gc_concurrent_handle")
        a.test_r64_r64("rax", "rax")
        a.jcc("ne", "gc_request_ready")
        # Both events are private unnamed Win32 handles.
        for name in ["gc_concurrent_go", "gc_concurrent_done"]:
            a.xor_r32_r32("ecx", "ecx")
            manual = 0
            if name == "gc_concurrent_done":
                manual = 1
            a.mov_r32_imm32("edx", manual)
            a.xor_r32_r32("r8d", "r8d")
            a.xor_r32_r32("r9d", "r9d")
            a.mov_rax_rip_qword("iat_CreateEventW")
            a.call_rax()
            a.test_r64_r64("rax", "rax")
            a.jcc("e", "gc_worker_init_failed")
            a.mov_rip_qword_rax(name)
        a.mov_membase_disp_imm32("rsp", 0x20, 0, qword=True)
        a.mov_membase_disp_imm32("rsp", 0x28, 0, qword=True)
        a.xor_r32_r32("ecx", "ecx")
        a.xor_r32_r32("edx", "edx")
        a.lea_r8_rip("fn_gc_concurrent_worker")
        a.xor_r32_r32("r9d", "r9d")
        a.mov_rax_rip_qword("iat_CreateThread")
        a.call_rax()
        a.test_r64_r64("rax", "rax")
        a.jcc("e", "gc_worker_init_failed")
        a.mov_rip_qword_rax("gc_concurrent_handle")
        a.mark("gc_request_ready")
        a.mov_rax_rip_qword("gc_concurrent_done")
        a.mov_r64_r64("rcx", "rax")
        a.mov_rax_rip_qword("iat_ResetEvent")
        a.call_rax()
        a.mov_rax_imm64(3)
        a.mov_rip_qword_rax("gc_concurrent_phase")
        a.mov_rax_rip_qword("gc_concurrent_go")
        a.mov_r64_r64("rcx", "rax")
        a.mov_rax_rip_qword("iat_SetEvent")
        a.call_rax()
        a.mark("gc_request_return")
        # Account another threshold only after allocations made since this request.
        a.xor_r32_r32("eax", "eax")
        a.mov_rip_qword_rax("gc_bytes_since")
        a.mov_rip_qword_rax("gc_young_bytes_since")
        a.mov_rax_rip_qword("gc_concurrent_completed")
        a.inc_r64("rax")
        a.call("fn_heap_leave")
        a.mov_r64_membase_disp("rdx", "rsp", 0x30)
        a.add_rsp_imm8(0x38)
        a.ret()
        a.mark("gc_worker_init_failed")
        a.mov_r32_imm32("ecx", 1)
        a.mov_rax_rip_qword("iat_ExitProcess")
        a.call_rax()
        return

    def emit_concurrent_gc_collect(self):
        """Wait for a fresh snapshot without retaining recursive monitor ownership."""
        a = self.asm
        self.ensure_concurrent_gc_data()
        self.used_helpers.update(["fn_gc_concurrent_request", "fn_gc_native_enter", "fn_gc_native_leave", "fn_heap_enter", "fn_heap_leave"])
        a.mark("fn_gc_collect")
        a.push_reg("rbx")
        a.push_reg("r12")
        a.sub_rsp_imm8(0x28)
        a.mov_r11_gs_qword_28()
        a.mov_r32_membase_disp("ebx", "r11", HEAP_LOCK_DEPTH)
        a.mov_r64_r64("r12", "rbx")
        a.mark("gc_collect_release")
        a.test_r64_r64("r12", "r12")
        a.jcc("e", "gc_collect_request")
        a.call("fn_heap_leave")
        a.dec_r64("r12")
        a.jmp("gc_collect_release")
        a.mark("gc_collect_request")
        a.call("fn_gc_concurrent_request")
        # If another cycle was already active, wait for it and then request a fresh
        # snapshot. Do not wait to observe an idle phase: continuous allocation can
        # legitimately request the next cycle before that observation is possible.
        a.mov_membase_disp_r64("rsp", 0x20, "rdx")
        a.mov_r64_r64("r12", "rax")
        a.mark("gc_collect_wait_enter")
        a.call("fn_gc_native_enter")
        a.mark("gc_collect_wait")
        a.mov_rax_rip_qword("gc_concurrent_completed")
        a.cmp_r64_r64("rax", "r12")
        a.jcc("ae", "gc_collect_restore")
        a.mov_rax_rip_qword("gc_concurrent_done")
        a.mov_r64_r64("rcx", "rax")
        a.mov_r32_imm32("edx", 10)
        a.mov_rax_rip_qword("iat_WaitForSingleObject")
        a.call_rax()
        a.jmp("gc_collect_wait")
        a.mark("gc_collect_restore")
        a.call("fn_gc_native_leave")
        a.mov_r64_membase_disp("rax", "rsp", 0x20)
        a.test_r64_r64("rax", "rax")
        a.jcc("e", "gc_collect_relock")
        a.call("fn_gc_concurrent_request")
        a.mov_r64_r64("r12", "rax")
        a.mov_membase_disp_imm32("rsp", 0x20, 0, qword=True)
        a.jmp("gc_collect_wait_enter")
        a.mark("gc_collect_relock")
        a.test_r64_r64("rbx", "rbx")
        a.jcc("e", "gc_collect_return")
        a.call("fn_heap_enter")
        # Another emergency waiter may have started a new snapshot before this
        # allocator reacquired the monitor. That snapshot temporarily hides all
        # reusable old blocks. Wait for it instead of returning a false OOM on the
        # allocator's one retry; observe idle while holding the monitor.
        a.mov_rax_rip_qword("gc_concurrent_phase")
        a.test_r64_r64("rax", "rax")
        a.jcc("e", "gc_collect_relock_owned")
        a.call("fn_heap_leave")
        a.call("fn_gc_concurrent_request")
        a.mov_r64_r64("r12", "rax")
        a.mov_membase_disp_imm32("rsp", 0x20, 0, qword=True)
        a.jmp("gc_collect_wait_enter")
        a.mark("gc_collect_relock_owned")
        a.dec_r64("rbx")
        a.jmp("gc_collect_relock")
        a.mark("gc_collect_return")
        a.add_rsp_imm8(0x28)
        a.pop_reg("r12")
        a.pop_reg("rbx")
        a.ret()
        return
