"""Build and boot the MinUX file/crypto/media/GUI acceptance fixtures (Linux/WSL)."""
from pathlib import Path
import argparse
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--minux-root',type=Path,required=True)
    parser.add_argument('--kernel',type=Path,required=True,help='kernel including VM-budget and advisory-lock changes')
    parser.add_argument('--work',type=Path,default=ROOT/'build/minux-extensions')
    parser.add_argument('--skip-native-build',action='store_true')
    parser.add_argument('--build-only',action='store_true')
    args=parser.parse_args()
    root=args.minux_root.resolve();work=args.work.resolve();work.mkdir(parents=True,exist_ok=True)
    native=ROOT/'build/minux-native';fixtures=work/'fixtures'
    def run(command):subprocess.run(list(map(str,command)),cwd=ROOT,check=True)
    if not args.skip_native_build:run([sys.executable,ROOT/'tools/build_minux_native.py','--minux-root',root])
    run([sys.executable,ROOT/'tests/make_minux_media_fixtures.py',fixtures])
    programs=[]
    for name in ('minux_stdlib','minux_files','minux_media'):
        output=work/name
        run([sys.executable,ROOT/'mlc_win64.py',ROOT/'tests'/(name+'.ml'),output,'--target','minux-x64','-I',ROOT,'--pack'])
        programs.append(output)
    run([sys.executable,ROOT/'mlc_win64.py',ROOT/'tests/minux_gui.ml',fixtures/'gui-app.elf','--target','minux-x64','-I',ROOT,'-I',ROOT.parent/'MiniGui','--pack'])
    for name in ('minux_gui_driver','minux_lock_lifetime','minux_console_driver'):
        obj=work/(name+'.o');output=work/name
        run(['gcc','-O2','-std=c11','-fPIC','-fno-stack-protector','-mcmodel=large',
             '-I'+str(root/'sdk/include'),'-c',ROOT/'tests'/(name+'.c'),'-o',obj])
        crt=root/'obj/user/libc/dynamic_crt0.o'
        run(['ld','-nostdlib','--hash-style=sysv','-z','now','--build-id=none','-dynamic-linker','/lib/ld-minux.so',
            '-T',root/'user/dynamic_program.ld','-o',output,crt,obj,'-L'+str(native),'-l:libminilang_minux.so',
            '-L'+str(root/'obj/user'),'-l:libc.so.1'])
        programs.append(output)
    if args.build_only:return
    run([sys.executable,ROOT/'tests/run_minux_guest.py','--minux-root',root,'--kernel',args.kernel.resolve(),
         '--native-libraries',native,'--fixtures',fixtures,'--audio','--work',work/'guest','--timeout','360',*programs])
    print('MinUX extensions: positional/durable files, process locks, crypto, native audio, GUI/dialog/video frames passed')


if __name__=='__main__':main()
