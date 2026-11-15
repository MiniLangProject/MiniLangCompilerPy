"""Build MinUX native adapters against the user's pinned MinUX SDK/toolchain.

Run on Linux/WSL. Rebuilds the user's verified Mbed TLS 3.6.5 source with PIC
and native pthread locking in a private directory. Downloads, changes to the
MinUX checkout, and system installation are not performed by this script.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--minux-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=ROOT/'build/minux-native')
    parser.add_argument('--toolchain', type=Path,
                        default=Path.home()/'.cache/minux-toolchain/output')
    parser.add_argument('--mbedtls-source', type=Path)
    parser.add_argument('--dependency-build', type=Path,
                        default=Path.home()/'.cache/minilang-minux/mbedtls-3.6.5-gcc12-pic')
    parser.add_argument('--jobs', type=int, default=4)
    parser.add_argument('--core-only',action='store_true',help='omit the optional MiniGui/media libraries')
    parser.add_argument('--minigui-root',type=Path,default=ROOT.parent/'MiniGui')
    args = parser.parse_args()
    root, output = args.minux_root.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    toolchain = args.toolchain.resolve()
    gcc = toolchain/'cross-modern/bin/x86_64-pc-minux-gcc'
    source = (args.mbedtls_source or toolchain.parent/'sources/native-mbedtls/mbedtls-3.6.5').resolve()
    dependency = args.dependency_build.resolve()
    if not (source/'include/mbedtls/version.h').is_file():
        parser.error('verified Mbed TLS 3.6.5 source is required; pass --mbedtls-source')
    if '#define MBEDTLS_VERSION_STRING         "3.6.5"' not in (source/'include/mbedtls/build_info.h').read_text():
        parser.error('this adapter is pinned to the MinUX toolchain Mbed TLS 3.6.5 source')
    if not (dependency/'Makefile').is_file():
        shutil.copytree(source, dependency, ignore=shutil.ignore_patterns('*.o','*.a','*.so','.git'), dirs_exist_ok=True)
    config = dependency/'include/mbedtls/mbedtls_config.h'
    settings = config.read_text()
    for setting in ('MBEDTLS_THREADING_C','MBEDTLS_THREADING_PTHREAD'):
        if '\n#define '+setting+'\n' not in settings:
            settings += '\n#define '+setting+'\n'
    config.write_text(settings)
    environment = os.environ.copy()
    environment.update(CC=str(gcc),AR=str(toolchain/'cross-modern/bin/x86_64-pc-minux-ar'),
                       CFLAGS='-O2 -std=gnu99 -fPIC -I"'+str(root/'sdk/include')+'"')
    with (output/'mbedtls-build.log').open('w') as log:
        subprocess.run(['make','-j'+str(args.jobs),'lib'],cwd=dependency,env=environment,
                       check=True,stdout=log,stderr=subprocess.STDOUT)
    objects = []
    for source in sorted((ROOT/'native/minux').glob('*.c')):
        obj = output/(source.stem+'.o')
        subprocess.run([str(gcc), '-O2', '-std=gnu99', '-fPIC', '-mcmodel=large',
            '-fno-stack-protector', '-I'+str(root/'sdk/include'), '-I'+str(dependency/'include'),
            '-c', str(source), '-o', str(obj)], check=True)
        objects.append(obj)
    libraries = []
    if (ROOT/'native/minux/tls.c').exists():
        libraries = [dependency/'library'/name for name in ('libmbedtls.a','libmbedx509.a','libmbedcrypto.a')]
    libgcc = subprocess.check_output([str(gcc), '-print-libgcc-file-name'], text=True).strip()
    command = ['ld', '-shared', '--build-id=none', '--hash-style=sysv', '--exclude-libs','ALL','-z', 'max-page-size=4096',
        '-soname', 'libminilang_minux.so', '-T', root/'user/shared_library.ld',
        '-o', output/'libminilang_minux.so', *objects, *libraries,
        '-L'+str(root/'obj/user'), '-l:libc.so.1', libgcc]
    subprocess.run([str(item) for item in command], check=True)
    if not args.core_only:
        subprocess.run(['python3',str(args.minigui_root/'tools/build_minux_native.py'),
            '--minux-root',str(root),'--output',str(output)],check=True)
        obj=output/'media.o'
        subprocess.run(['g++','-std=c++17','-O2','-fPIC','-fno-exceptions','-fno-rtti',
            '-fno-stack-protector','-I'+str(root/'include'),'-I'+str(root/'sdk/include'),
            '-c',str(ROOT/'native/minux/media.cpp'),'-o',str(obj)],check=True)
        subprocess.run(['ld','-shared','--build-id=none','--hash-style=sysv','-z','max-page-size=4096',
            '-soname','libminilang_video.so','-T',str(root/'user/shared_library.ld'),
            '-o',str(output/'libminilang_video.so'),str(obj),'-L'+str(output),'-l:libminigui_minux.so',
            '-L'+str(root/'obj/user'),'-l:libc.so.1'],check=True)
    # Fail the build if an adapter asks for a symbol absent from the actual
    # user's SDK runtime. Keep archive internals out of MinUX's global namespace.
    exports,required=set(),set()
    libraries=sorted(output.glob('*.so'))
    for library in [root/'obj/user/libc.so.1',*libraries]:
        symbols=subprocess.check_output(['readelf','--wide','--dyn-syms',str(library)],text=True)
        for line in symbols.splitlines():
            columns=line.split()
            if len(columns)<8 or not columns[0].endswith(':'):continue
            if columns[6]=='UND':
                if columns[4]=='GLOBAL':required.add(columns[7])
            elif columns[4] in ('GLOBAL','WEAK') and columns[5]=='DEFAULT':exports.add(columns[7])
    if required-exports:raise RuntimeError('missing MinUX native exports: '+', '.join(sorted(required-exports)))
    for library in libraries:
        dynamic=subprocess.check_output(['readelf','-d',str(library)],text=True)
        if '(TEXTREL)' in dynamic:raise RuntimeError('text relocations are forbidden: '+str(library))
        if library.stat().st_size>16*1024*1024:raise RuntimeError('MinUX loader image limit exceeded: '+str(library))
    licenses=output/'licenses';licenses.mkdir(exist_ok=True)
    shutil.copyfile(dependency/'LICENSE',licenses/'Mbed-TLS-3.6.5-LICENSE')
    ca=toolchain/'native-root/etc/ssl/certs/ca-certificates.crt'
    if ca.is_file():shutil.copyfile(ca,output/'ca-certificates.crt')
    manifest={'mbedtls':'3.6.5','compiler':subprocess.check_output([str(gcc),'--version'],text=True).splitlines()[0],
              'libraries':{library.name:{'bytes':library.stat().st_size,'sha256':hashlib.sha256(library.read_bytes()).hexdigest()} for library in libraries},
              'undefined_symbols':sorted(required),'unresolved_symbols':[],'text_relocations':False}
    (output/'runtime-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(f'MinUX native adapters built and audited: {output}/libminilang_minux.so')


if __name__ == '__main__':
    main()
