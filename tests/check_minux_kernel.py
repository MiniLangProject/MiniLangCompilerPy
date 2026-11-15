"""Run relevant MinUX kernel host tests with ASan/UBSan (Linux/WSL)."""
from pathlib import Path
import argparse
import sys


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--minux-root',type=Path,required=True)
    parser.add_argument('--work',type=Path,default=Path(__file__).resolve().parents[1]/'build/minux-kernel-tests')
    args=parser.parse_args()
    root=args.minux_root.resolve();work=args.work.resolve();work.mkdir(parents=True,exist_ok=True)
    sys.path.insert(0,str(root/'tools'))
    import run_host_tests as host
    names=('virtual_memory_tests','process_file_descriptors_tests','syscall_abi_resource_tests',
           'vfs_open_flags_tests','vfs_operation_protocol_tests','posix_regular_file_io_protocol_tests')
    failures=[]
    for name in names:
        test=next(test for test in host.TEST_BINARIES if test.name==name)
        binary=host.compile_test('g++','gcc',root,work,test,True)
        if host.run_test(binary,root):failures.append(name)
    if failures:raise RuntimeError('failed kernel tests: '+', '.join(failures))
    print('MinUX VM/resource/descriptor/VFS tests passed with ASan/UBSan')


if __name__=='__main__':main()
