"""Run compiled MiniLang programs in an isolated copy of a MinUX BIOS image.

Run on Linux/WSL. Requires QEMU, e2fsprogs and OpenSSH. The source image and
MinUX working tree are never modified. Guest programs are staged with debugfs.
"""
from __future__ import annotations

import argparse
import os
import json
from pathlib import Path
import queue
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time


def run_checked_ssh(port, known, askpass, command, log, timeout):
    """Drain output continuously; send shell exit only after the child result.

    Prequeueing `exit` can close a PTY session before a spawned program and
    its supervisor have both reported their status. Preserve live transcripts
    and the copied disk so a failing long self-build remains inspectable.
    """
    askpass.write_text("#!/bin/sh\nprintf '%s\\n' 'user'\n")
    askpass.chmod(0o700)
    environment = os.environ.copy()
    environment.update(SSH_ASKPASS=str(askpass), SSH_ASKPASS_REQUIRE='force', DISPLAY=':0')
    ssh = subprocess.Popen(['ssh', '-tt', '-p', str(port), '-o', 'BatchMode=no',
        '-o', 'NumberOfPasswordPrompts=3', '-o', 'PreferredAuthentications=password',
        '-o', 'PubkeyAuthentication=no', '-o', 'KexAlgorithms=curve25519-sha256',
        '-o', 'HostKeyAlgorithms=ssh-ed25519', '-o', 'Ciphers=aes128-ctr',
        '-o', 'MACs=hmac-sha2-256', '-o', 'StrictHostKeyChecking=accept-new',
        '-o', f'UserKnownHostsFile={known}', 'user@127.0.0.1'],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, errors='replace', env=environment)
    output = queue.Queue()
    def read_output():
        try:
            for line in ssh.stdout:
                output.put(line)
        finally:
            output.put(None)
    reader = threading.Thread(target=read_output, daemon=True)
    reader.start()
    deadline = time.monotonic() + timeout
    complete = False
    transcript = []
    try:
        ssh.stdin.write(command + '\n')
        ssh.stdin.flush()
        with log.open('w') as stream:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(f'guest command timed out; see {log}')
                try:
                    line = output.get(timeout=min(remaining, 1))
                except queue.Empty:
                    continue
                if line is None:
                    break
                transcript.append(line)
                stream.write(line)
                stream.flush()
                if line.rstrip('\r\n') == 'MINILANG_GUEST_PROGRAM_PASSED' and not complete:
                    complete = True
                    ssh.stdin.write('exit\n')
                    ssh.stdin.flush()
                if line.startswith('MINILANG_GUEST_PROGRAM_FAILED'):
                    raise RuntimeError(f'guest child failed; see {log}: {line.strip()}')
        ssh.wait(timeout=max(1, deadline-time.monotonic()))
        result = ''.join(transcript)
        if not complete or ssh.returncode:
            raise RuntimeError(f'guest command failed (SSH {ssh.returncode}); see {log}')
        print(result if len(result) < 8000 else result[-3000:] + f'\nFull transcript: {log}\n', flush=True)
        return result
    finally:
        if ssh.poll() is None:
            ssh.terminate()
            try:
                ssh.wait(timeout=5)
            except subprocess.TimeoutExpired:
                ssh.kill()
                ssh.wait(timeout=5)
        reader.join(timeout=5)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--minux-root', type=Path, required=True)
    parser.add_argument('--image', type=Path)
    parser.add_argument('--kernel', type=Path, help='optional kernel staged only into the copied image')
    parser.add_argument('--modules', type=Path, help='matching kernel-driver directory; *.kmod files are staged into /boot/modules')
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=180)
    parser.add_argument('--expected-exit', type=int, default=37)
    parser.add_argument('--native-libraries', type=Path)
    parser.add_argument('--fixtures', type=Path, help='directory copied into /home/user/fixtures')
    parser.add_argument('--selfhost', type=Path)
    parser.add_argument('--selfbuild', action='store_true')
    parser.add_argument('--selfbuild-pipeline', choices=('direct', 'mlo'), default='direct')
    parser.add_argument('--fixed-point', action='store_true', help='rebuild stage3 and require byte-identical stage2/stage3 output')
    parser.add_argument('--image-size-mib', type=int, help='copied image capacity (default: 1024 for self-builds, otherwise 256 MiB)')
    parser.add_argument('--audio',action='store_true',help='attach an SB16 device with a silent host sink')
    parser.add_argument('--forward-tcp',action='append',default=[],metavar='HOST:GUEST',help='additional loopback-only QEMU forward')
    parser.add_argument('program', type=Path, nargs='*')
    args = parser.parse_args()
    if args.fixed_point:
        args.selfbuild = True
    if args.selfbuild and not args.selfhost:
        parser.error('--selfbuild/--fixed-point requires --selfhost')
    if args.image_size_mib is None:
        args.image_size_mib = 1024 if args.selfbuild else 256
    root = args.minux_root.resolve()
    image = (args.image or root/'MinUX_disk.img').resolve()
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(root/'tools'))
    from qemu_sshd import run_ssh, wait_for_ssh_marker

    # Preserve boot sectors/GRUB and modify only the copied ext2 partition.
    raw = bytearray(image.read_bytes())
    if raw[510:512] != b'\x55\xaa' or raw[450] != 0x83:
        raise RuntimeError('expected a MinUX MBR/ext2 BIOS image')
    start, count = struct.unpack_from('<II', raw, 454)
    offset, length = start*512, count*512
    if not start or offset+length > len(raw):
        raise RuntimeError('invalid image partition bounds')
    partition = work/'root.ext2'
    partition.write_bytes(raw[offset:offset+length])
    desired = args.image_size_mib*1024*1024-offset
    if desired > length:
        with partition.open('r+b') as file:
            file.truncate(desired)
        repair = subprocess.run(['e2fsck','-fy',str(partition)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if repair.returncode not in (0,1):
            raise RuntimeError(repair.stdout.decode(errors='replace'))
        subprocess.run(['resize2fs',str(partition)],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        raw.extend(b'\0'*(offset+desired-len(raw)))
        length = desired
        struct.pack_into('<I',raw,458,length//512)
    config = work/'minux.ini'
    text = (root/'diskroot/etc/minux.ini').read_text()
    config.write_text(re.sub(r'(?m)^session=.*$', 'session=text', text))
    staged = [('minux.ini', '/etc/minux.ini', config, False)]
    if args.kernel:
        staged.append(('kernel','/boot/MinUX_kernel.bin',args.kernel.resolve(),False))
    if args.modules:
        modules = sorted(args.modules.glob('*.kmod'))
        if not modules:
            parser.error('--modules contains no kernel-driver modules')
        for module in modules:
            staged.append((module.name, '/boot/modules/'+module.name, module.resolve(), False))
    supervisor = work/'supervisor'
    subprocess.run(['gcc', '-std=c11', '-fno-stack-protector', '-fno-pie', '-no-pie', '-mcmodel=large', '-nostdlib', '-static',
        '-Wl,--build-id=none',
        '-I', str(root/'sdk/include'), '-Wl,-T,'+str(root/'user/linker.ld'),
        '-o', str(supervisor), str(root/'obj/user/libc/crt0.o'),
        str(Path(__file__).with_name('minux_guest_supervisor.c')),
        str(root/'obj/user/libc.a'), '-lgcc'], check=True)
    staged.append(('supervisor', '/home/user/ml-run', supervisor, True))
    fixture = work/'libmlc_abi.so'
    subprocess.run(['gcc', '-shared', '-fPIC', '-nostdlib', '-Wl,--build-id=none',
        '-Wl,--hash-style=sysv', '-Wl,-soname,libmlc_abi.so',
        '-Wl,-T,'+str(root/'user/shared_library.ld'),
        '-o', str(fixture), str(Path(__file__).with_name('minux_abi_fixture.c'))], check=True)
    staged.append(('abi-library', '/lib/libmlc_abi.so', fixture, True))
    if args.native_libraries:
        for library in args.native_libraries.glob('*.so*'):
            staged.append((library.name,'/lib/'+library.name,library.resolve(),True))
    if args.fixtures:
        for fixture in args.fixtures.rglob('*'):
            if fixture.is_file():
                with fixture.open('rb') as source:
                    native_image = source.read(4) == b'\x7fELF'
                staged.append((fixture.name,'/home/user/fixtures/'+fixture.relative_to(args.fixtures).as_posix(),fixture.resolve(),fixture.suffix=='.elf' or native_image))
    if args.selfhost:
        staged.append(('compiler','/home/user/compiler',args.selfhost.resolve(),True))
        hello = work/'hello.ml'
        hello.write_text('function main(args)\n  print "MINUX_NATIVE_COMPILATION_OK"\n  return 37\nend function\n')
        staged.append(('source','/home/user/hello.ml',hello,False))
        if args.selfbuild:
            source_root = Path(__file__).resolve().parents[2]/'MiniLangCompilerML'
            for directory in ('mlc','std'):
                for source in (source_root/directory).rglob('*.ml'):
                    relative = source.relative_to(source_root).as_posix()
                    staged.append((relative,'/home/user/ml/'+relative,source,False))
            staged.append(('compiler-entry','/home/user/ml/mlc_win64.ml',source_root/'mlc_win64.ml',False))
    for index, program in enumerate(args.program):
        # debugfs has its own quoting grammar: keep all host paths simple.
        source = work/f'program-{index}'
        shutil.copyfile(program, source)
        staged.append((program.name, f'/home/user/ml-{index}', source, True))
    commands = []
    directories = set()
    for _, target, source, executable in staged:
        parent = Path(target).parent
        while str(parent) not in ('/','.'): directories.add(str(parent)); parent=parent.parent
    for directory in sorted(directories,key=lambda name:(name.count('/'),name)):
        commands.append(f'mkdir {directory}')
    for _, target, source, executable in staged:
        commands += [f'rm {target}', f'write "{source}" {target}']
        if executable:
            commands += [f'set_inode_field {target} mode 0100755']
    command_file = work/'debugfs.commands'
    command_file.write_text('\n'.join(commands)+'\n')
    subprocess.run(['debugfs', '-w', '-f', str(command_file), str(partition)], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    raw[offset:offset+length] = partition.read_bytes()
    guest_image = work/'MinUX_test.img'
    guest_image.write_bytes(raw)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    (work/'connection.json').write_text(json.dumps({'host':'127.0.0.1', 'port':port})+'\n')
    serial = work/'serial.log'
    forwarding=''
    for spec in args.forward_tcp:
        host,guest=map(int,spec.split(':'))
        if not 0<host<65536 or not 0<guest<65536:parser.error('invalid TCP forwarding ports')
        forwarding+=f',hostfwd=tcp:127.0.0.1:{host}-:{guest}'
    command = ['qemu-system-x86_64', '-m', '8G' if args.selfhost else '2G', '-smp', '2', '-cpu', 'max',
               '-display', 'none', '-monitor', 'none', '-serial', f'file:{serial}',
               '-no-reboot', '-netdev',
               f'user,id=net0,hostfwd=tcp:127.0.0.1:{port}-:22'+forwarding,
               '-device', 'e1000,netdev=net0', '-drive', f'file={guest_image},format=raw,if=ide']
    if args.audio:
        command += ['-audiodev','none,id=audio0','-device','sb16,audiodev=audio0']
    process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=(work/'qemu.log').open('w'))
    known, askpass = work/'known_hosts', work/'askpass.sh'
    known.unlink(missing_ok=True)
    try:
        deadline = time.monotonic()+args.timeout
        wait_for_ssh_marker('127.0.0.1', port, known, askpass, 'user', 'user',
                            'echo MINILANG_GUEST_READY\nexit\n', 'MINILANG_GUEST_READY', deadline)
        def checked(command, log):
            print(f'Running guest check: {log}', flush=True)
            return run_checked_ssh(port, known, askpass, command, work/log, args.timeout)
        if args.selfhost:
            checked('/home/user/ml-run 0 /home/user/compiler --version', 'selfhost-version.log')
            checked('/home/user/ml-run 0 /home/user/compiler /home/user/hello.ml /home/user/hello --target minux-x64 --no-object-pipeline --pack', 'selfhost-compile.log')
            checked('/home/user/ml-run 37 /home/user/hello', 'selfhost-run.log')
            checked('/home/user/ml-run 0 /home/user/compiler /home/user/hello.ml /home/user/hello-mlo --target minux-x64 --object-pipeline --pack','selfhost-mlo.log')
            checked('/home/user/ml-run 37 /home/user/hello-mlo','selfhost-mlo-run.log')
            checked('/home/user/ml-run --compare /home/user/hello /home/user/hello-mlo', 'compare-equal.log')
            checked('/home/user/ml-run 1 /home/user/ml-run --compare /home/user/hello /home/user/compiler', 'compare-different.log')
            if args.selfbuild:
                pipeline = '--object-pipeline' if args.selfbuild_pipeline == 'mlo' else '--no-object-pipeline'
                build_flags = f'--target minux-x64 -I /home/user/ml {pipeline} --pack'
                checked(f'/home/user/ml-run 0 /home/user/compiler /home/user/ml/mlc_win64.ml /home/user/compiler-stage2 {build_flags}','selfbuild.log')
                checked('/home/user/ml-run 0 /home/user/compiler-stage2 --version','selfbuild-version.log')
                checked('/home/user/ml-run 0 /home/user/compiler-stage2 /home/user/hello.ml /home/user/stage2-hello --target minux-x64 --no-object-pipeline','selfbuild-compile.log')
                checked('/home/user/ml-run 37 /home/user/stage2-hello','selfbuild-run.log')
                if args.fixed_point:
                    checked(f'/home/user/ml-run 0 /home/user/compiler-stage2 /home/user/ml/mlc_win64.ml /home/user/compiler-stage3 {build_flags}', 'selfbuild-stage3.log')
                    comparison = checked('/home/user/ml-run --compare /home/user/compiler-stage2 /home/user/compiler-stage3', 'selfbuild-fixed-point.log')
                    if not re.search(r'(?m)^MINILANG_FIXED_POINT_OK bytes=[1-9][0-9]*\r?$', comparison):
                        raise RuntimeError('missing full-file fixed-point comparison evidence')
                    checked('/home/user/ml-run 0 /home/user/compiler-stage3 /home/user/hello.ml /home/user/stage3-hello --target minux-x64 --object-pipeline --pack', 'selfbuild-stage3-compile.log')
                    checked('/home/user/ml-run 37 /home/user/stage3-hello', 'selfbuild-stage3-run.log')
        for index, program in enumerate(args.program):
            checked(f'/home/user/ml-run {args.expected_exit} /home/user/ml-{index}', f'{program.name}.log')
        faults = serial.read_text(errors='replace').lower()
        for marker in ('kernel panic', 'kernel lock stall', '[userfault]', 'triple fault'):
            if marker in faults:
                raise RuntimeError(f'MinUX fault: {marker}')
        print('MinUX guest programs passed', flush=True)
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)


if __name__ == '__main__':
    main()
