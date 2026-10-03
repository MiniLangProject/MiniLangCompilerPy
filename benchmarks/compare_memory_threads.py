"""Parallel allocation A/B comparison; do not pin all workers to one CPU."""
import compare_runtime_codegen as harness

original_run = harness.run_measured

def measured(path, case):
    output, peak = original_run(path, case)
    fields = dict(line.split("=", 1) for line in output.strip().splitlines())
    assert fields["threads"] == case
    normalized = (f"{case} ms={fields['elapsed_ms']} bytes={fields['heap_committed']} "
                  f"checksum={fields['checksum']}")
    return normalized, peak

harness.CASES = ("1", "2", "4", "8", "12", "24")
harness.run_measured = measured

if __name__ == "__main__":
    harness.main()
