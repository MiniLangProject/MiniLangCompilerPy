#!/usr/bin/env python3
"""Sample original MiniLang float kernels with Linux user CPU-clock events.

This x86-64-only diagnostic leaves program bytes untouched. Sampled instruction
pointers are attributed to verified ELF/label ranges. Software-clock sampling
has arbitrary interrupt skid: these are approximate sampled user-time shares,
not exclusive instruction costs, hardware cycles, or removable CPU fractions.
Sampling covers startup, full untimed warmup, timed calls and printing. Calls
outside bench are separate; no causal caller attribution is claimed.
"""
from __future__ import annotations

import argparse
from collections import Counter
import ctypes
import fcntl
import hashlib
import json
import mmap
import os
from pathlib import Path
import re
import select
import signal
import struct
import time

MASK = 2147483647
PERIODS = (997003, 1000003, 1009003)
SAMPLE_TYPE = 1 | 2 | 4 | 128 | 256  # IP, TID, TIME, CPU, PERIOD


class PerfAttr(ctypes.Structure):
    _fields_ = [("type", ctypes.c_uint32), ("size", ctypes.c_uint32),
                ("config", ctypes.c_uint64), ("sample_period", ctypes.c_uint64),
                ("sample_type", ctypes.c_uint64), ("read_format", ctypes.c_uint64),
                ("flags", ctypes.c_uint64), ("wakeup_events", ctypes.c_uint32),
                ("bp_type", ctypes.c_uint32), ("config1", ctypes.c_uint64),
                ("config2", ctypes.c_uint64), ("branch_sample_type", ctypes.c_uint64),
                ("sample_regs_user", ctypes.c_uint64), ("sample_stack_user", ctypes.c_uint32),
                ("clockid", ctypes.c_int32), ("sample_regs_intr", ctypes.c_uint64),
                ("aux_watermark", ctypes.c_uint32), ("sample_max_stack", ctypes.c_uint16),
                ("reserved2", ctypes.c_uint16), ("aux_sample_size", ctypes.c_uint32),
                ("reserved3", ctypes.c_uint32), ("sig_data", ctypes.c_uint64)]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, data):
    Path(path).write_text(json.dumps(data, indent=2) + "\n")


def ranges_for(binary, labels):
    data = binary.read_bytes()
    assert data[:6] == b"\x7fELF\x02\x01" and struct.unpack_from("<H", data, 16)[0] == 2
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phsize, phnum = struct.unpack_from("<HH", data, 54)
    loads = [struct.unpack_from("<IIQQQQQQ", data, phoff + i * phsize) for i in range(phnum)]
    loads = [p for p in loads if p[0] == 1]
    base = min(p[3] - p[2] for p in loads)
    assert len({p[3] - p[2] for p in loads}) == 1
    text = next(p for p in loads if p[1] & 1)
    table = {name: base + int(offset) for name, offset in re.findall(
        r"(?m)^\[label\] ([^ ]+) (\d+)\s*$", labels.read_text())}
    bench_start = table["fn_user_bench"]
    bench_end = min(v for k, v in table.items() if k.startswith("fn_user_") and v > bench_start)
    loop_ids = [k.removeprefix("float_loop_fast_") for k, v in table.items()
                if re.fullmatch(r"float_loop_fast_\d+", k) and bench_start <= v < bench_end]
    assert len(loop_ids) == 1
    lid = loop_ids[0]
    points = {name: table[f"float_loop_{name}_{lid}"] for name in
              ("guard", "fast", "commit", "exit", "deopt", "slow", "done")}
    major = [("guard", points["guard"], points["fast"]),
             ("raw_other", points["fast"], points["commit"]),
             ("commit_counter", points["commit"], points["exit"]),
             ("exit_materialization", points["exit"], points["deopt"]),
             ("deopt_materialization", points["deopt"], points["slow"]),
             ("ordinary_other", points["slow"], points["done"])]
    ranges = []
    for name, start in sorted(table.items(), key=lambda pair: pair[1]):
        if not re.fullmatch(r"float_tree_normalize_\d+", name) or not bench_start <= start < bench_end:
            continue
        offset = start - base
        # The unchanged Phase7/Phase8 normalizer is seven instructions /32B.
        # Assert its bytes (only the relative branch displacement varies).
        code = data[offset:offset + 32]
        assert code[:16] == bytes.fromhex("f2 48 0f 2c c0 f2 48 0f 2a c8 66 0f 2e c1 0f 84"), name
        assert code[20:] == bytes.fromhex("f2 0f 5a d0 f3 0f 5a da 66 0f 2e c3"), name
        stage = "raw" if points["fast"] <= start < points["commit"] else "ordinary"
        ranges.append((stage + "_normalizer_int_guard", start, start + 20))
        ranges.append((stage + "_normalizer_f32_probe", start + 20, start + 32))
    rejoin_ranges = []
    for name, start in sorted(table.items(), key=lambda pair: pair[1]):
        match = re.fullmatch(r"float_loop_consumer_int_(\d+)", name)
        if not match or not bench_start <= start < bench_end:
            continue
        offset = start - base
        code = data[offset:offset + 22]
        assert code[:18] == bytes.fromhex("48 c1 e0 03 48 83 c8 01 48 c1 f8 03 f2 48 0f 2a c0 e9"), (name, code.hex())
        resume = table["float_loop_consumer_resume_" + match[1]]
        assert start + 22 + struct.unpack_from("<i", code, 18)[0] == resume
        rejoin_ranges.append(("integer_rejoin", start, start + 22))
    ranges += rejoin_ranges
    ranges += major + [("bench_other", bench_start, bench_end),
                       ("executable_other", text[3], text[3] + text[5])]
    return dict(image_base=base, bench_start=bench_start, bench_end=bench_end,
                major_ranges=[dict(category=n, start=s, end=e) for n, s, e in major],
                integer_rejoin_ranges=[dict(category=n, start=s, end=e) for n, s, e in rejoin_ranges],
                ranges=[dict(category=n, start=s, end=e) for n, s, e in ranges])


def profile(command, cpu, period, env, stdout_path, stderr_path, timeout=45):
    libc = ctypes.CDLL(None, use_errno=True)
    atomic = ctypes.CDLL("libatomic.so.1")
    load = atomic.__atomic_load_8
    load.argtypes = (ctypes.c_void_p, ctypes.c_int)
    load.restype = ctypes.c_uint64
    store = atomic.__atomic_store_8
    store.argtypes = (ctypes.c_void_p, ctypes.c_uint64, ctypes.c_int)
    store.restype = None
    fd = None
    ring = None
    child_done = False
    pid = os.fork()
    if pid == 0:
        try:
            os.sched_setaffinity(0, {cpu})
            for target, path in ((1, stdout_path), (2, stderr_path)):
                output = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                os.dup2(output, target)
                os.close(output)
            os.kill(os.getpid(), signal.SIGSTOP)
            os.execve(command[0], command, env)
        finally:
            os._exit(127)
    try:
        waited, status = os.waitpid(pid, os.WUNTRACED)
        assert waited == pid and os.WIFSTOPPED(status)
        attr = PerfAttr()
        attr.type, attr.size, attr.config = 1, ctypes.sizeof(attr), 0
        attr.sample_period, attr.sample_type = period, SAMPLE_TYPE
        attr.flags = 1 | (1 << 5) | (1 << 6)  # disabled, exclude_kernel/hv
        attr.wakeup_events = 32
        fd = libc.syscall(298, ctypes.byref(attr), pid, -1, -1, 0)
        if fd < 0:
            raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
        page = mmap.PAGESIZE
        ring = mmap.mmap(fd, page * 129, flags=mmap.MAP_SHARED, prot=mmap.PROT_READ | mmap.PROT_WRITE)
        address = ctypes.addressof(ctypes.c_char.from_buffer(ring))
        data_offset, data_size = struct.unpack_from("<QQ", ring, 1040)
        assert data_offset == page and data_size == page * 128
        tail = 0
        ips, weighted = Counter(), Counter()
        events, lost, periods = Counter(), 0, Counter()
        first_time = last_time = None

        def bytes_at(offset, size):
            start = offset % data_size
            left = min(size, data_size - start)
            value = ring[data_offset + start:data_offset + start + left]
            return value + ring[data_offset:data_offset + size - left] if left < size else value

        def drain():
            nonlocal tail, lost, first_time, last_time
            head = load(address + 1024, 2)  # acquire
            assert head - tail <= data_size, "Ring overwrite"
            while tail < head:
                kind, misc, size = struct.unpack("<IHH", bytes_at(tail, 8))
                assert 8 <= size <= data_size and tail + size <= head
                data = bytes_at(tail, size)
                events[kind] += 1
                if kind == 9:
                    ip, sample_pid, tid, stamp, sample_cpu, _reserved, sample_period = struct.unpack_from("<QIIQIIQ", data, 8)
                    assert sample_pid == pid and tid == pid and sample_cpu == cpu
                    assert misc & 7 == 2, f"Non-user CPU mode {misc}"
                    ips[ip] += 1
                    weighted[ip] += sample_period
                    periods[sample_period] += 1
                    first_time = stamp if first_time is None else min(first_time, stamp)
                    last_time = stamp if last_time is None else max(last_time, stamp)
                elif kind == 2:
                    lost += struct.unpack_from("<Q", data, 16)[0]
                elif kind == 13:
                    lost += struct.unpack_from("<Q", data, 8)[0]
                tail += size
            store(address + 1032, tail, 3)  # release

        fcntl.ioctl(fd, 0x2400, 0)  # PERF_EVENT_IOC_ENABLE
        start_time = time.monotonic()
        os.kill(pid, signal.SIGCONT)
        while True:
            drain()
            waited, status = os.waitpid(pid, os.WNOHANG)
            if waited:
                child_done = True
                break
            if time.monotonic() - start_time > timeout:
                raise TimeoutError(command)
            select.select([fd], [], [], 0.05)
        fcntl.ioctl(fd, 0x2401, 0)  # DISABLE
        drain()
        event_count = struct.unpack("<Q", os.read(fd, 8))[0]
        assert os.waitstatus_to_exitcode(status) == 0, (status, stdout_path.read_text(), stderr_path.read_text())
        assert lost == 0 and not events[5] and not events[6], (lost, events)
        return dict(samples=sum(ips.values()), weighted_period_ns=sum(weighted.values()),
                    cpu_clock_count_ns=event_count, lost_samples=lost, events=dict(events),
                    periods_ns=dict(periods), first_sample_time_ns=first_time, last_sample_time_ns=last_time,
                    ips=ips, weighted=weighted)
    finally:
        if not child_done:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        if ring is not None:
            ring.close()
        if fd is not None and fd >= 0:
            os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--images", type=Path, required=True)
    parser.add_argument("--suite", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cpu", type=int, default=2)
    parser.add_argument("--reps", type=int, default=256)
    parser.add_argument("--processes-per-period", type=int, default=1)
    args = parser.parse_args()
    assert os.uname().machine == "x86_64" and args.cpu in os.sched_getaffinity(0)
    assert args.reps >= 8 and args.reps % 8 == 0
    assert args.processes_per_period >= 1
    args.images, args.suite, args.output = (x.resolve() for x in (args.images, args.suite, args.output))
    args.output.mkdir(parents=True, exist_ok=True)
    calibration = json.loads((args.suite / "results/calibration.json").read_text())
    rows = []
    for case in ("float_recurrence", "mandelbrot"):
        folder = args.images / case
        binary, labels = folder / "native", folder / "python.labels"
        assert binary.read_bytes() == (folder / "python").read_bytes()
        mapping = ranges_for(binary, labels)
        save(args.output / (case + ".ranges.json"), mapping)
        cfg = calibration[case]
        expected = cfg["configs"]["minilang"]["cycle_checksum"] * (args.reps // 8) & MASK
        schedule = [(period, repetition) for period in PERIODS
                    for repetition in range(args.processes_per_period)]
        for index, (period, repetition) in enumerate(schedule):
            stdout = args.output / (case + f".{index}.stdout")
            stderr = args.output / (case + f".{index}.stderr")
            env = dict(os.environ, LC_ALL="C")
            env["LD_LIBRARY_PATH"] = str(args.suite / "build") + ":" + env.get("LD_LIBRARY_PATH", "")
            result = profile([str(binary), str(cfg["n"]), str(args.reps), "12345"], args.cpu, period, env, stdout, stderr)
            match = re.search(r"^RESULT (-?\d+) (\d+) (-?\d+)\s*$", stdout.read_text(), re.M)
            assert match and int(match[1]) == expected and int(match[3]) == cfg["configs"]["minilang"]["warmup_checksum"]
            assert result["samples"] >= 1, result["samples"]
            category_counts, category_weights = Counter(), Counter()
            samples = []
            for ip, count in result.pop("ips").items():
                category = next((row["category"] for row in mapping["ranges"] if row["start"] <= ip < row["end"]), "outside_executable")
                weight = result["weighted"][ip]
                category_counts[category] += count
                category_weights[category] += weight
                samples.append(dict(ip=ip, image_rva=ip - mapping["image_base"] if category != "outside_executable" else None,
                                    category=category, samples=count, weighted_period_ns=weight))
            result.pop("weighted")
            row = dict(case=case, round=index, period_repetition=repetition,
                       period_ns=period, cpu=args.cpu, n=cfg["n"], reps=args.reps,
                       seed=12345, checksum=int(match[1]), warmup_checksum=int(match[3]), correct=True,
                       profiled_elapsed_ns=int(match[2]), binary_sha256=sha(binary), labels_sha256=sha(labels),
                       source_sha256=sha(args.suite / "inputs" / (case + ".ml")),
                       category_counts=dict(category_counts), category_weights_ns=dict(category_weights),
                       category_sample_shares={k: v / result["samples"] for k, v in category_counts.items()},
                       samples_by_ip=sorted(samples, key=lambda x: (-x["samples"], x["ip"])), **result)
            rows.append(row)
            save(args.output / "profiles.json", rows)
            if args.processes_per_period == 1 or repetition == args.processes_per_period - 1:
                print(json.dumps(dict(case=case, period_ns=period,
                                     processes_completed=index + 1)), flush=True)
        assert sum(row["samples"] for row in rows if row["case"] == case) >= 500
    save(args.output / "method.json", dict(method=__doc__, helper_sha256=sha(Path(__file__)),
         periods_ns=PERIODS, reps=args.reps, processes_per_period=args.processes_per_period,
         seed_cycle=list(range(12345, 12353)),
         warmup_seed=77881, hardware_cycles_available=False, software_cpu_clock_available=True,
         no_program_instrumentation=True, no_callchain_attribution=True,
         precision="Approximate sampled user CPU shares; arbitrary interrupt skid and correlated samples. "
                   "Includes startup and one full warmup; runtime callees remain executable_other. "
                   "Do not interpret as exclusive instruction cost or realizable speedup."))


if __name__ == "__main__":
    main()
