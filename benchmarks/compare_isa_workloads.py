"""Compare isa_workloads.ml images using the shared A/B/RSS measurement runner."""
import compare_runtime_codegen as runner

runner.CASES = ('crc', 'copy', 'fill', 'copy-small', 'fill-small', 'base64-encode', 'base64-decode')

if __name__ == '__main__':
    runner.main()
