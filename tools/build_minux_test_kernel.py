"""Build the VM change into a private test kernel using existing MinUX objects.

The normal MinUX make targets produce the deliverable OS. This helper is for
isolated compiler tests: it changes neither the user's kernel nor boot image.
"""
from pathlib import Path
import argparse
import shlex
import subprocess


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--minux-root',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--extra-source',type=Path,action='append',default=[],help='additional existing MinUX translation unit needed by the local object set')
    args=parser.parse_args()
    root,output=args.minux_root.resolve(),args.output.resolve()
    output.parent.mkdir(parents=True,exist_ok=True)
    plan=subprocess.check_output(['make','-Bn','MinUX_kernel.bin'],cwd=root,text=True)
    commands=[shlex.split(line) for line in plan.splitlines() if line.startswith(('g++ ','ld '))]
    compilation=next(command for command in commands if command[-1]=='src/kernel/process/process_virtual_memory.cpp')
    obj=output.with_suffix('.vm.o')
    compilation[compilation.index('-o')+1]=str(obj)
    subprocess.run(compilation,cwd=root,check=True)
    link=next(command for command in reversed(commands) if command[0]=='ld' and '-T' in command and 'linker.ld' in command)
    link[link.index('-o')+1]=str(output)
    link=[str(obj) if item=='obj/kernel/process/process_virtual_memory.o' else item for item in link]
    replacements={}
    for source in args.extra_source:
        original='obj/'+str(source).removeprefix('src/').removesuffix('.cpp')+'.o'
        replacements[original]=source
    for item in link:
        if item.endswith('.o') and not Path(item).is_absolute() and not (root/item).is_file():
            command=next(command for command in commands if '-o' in command and command[command.index('-o')+1]==item)
            replacements[item]=Path(command[-1])
    for original,source in replacements.items():
        extra=output.with_suffix('.'+str(source).replace('/','_').replace('\\','_')+'.o')
        command=compilation.copy();command[-1]=str(source)
        command[command.index('-o')+1]=str(extra)
        subprocess.run(command,cwd=root,check=True)
        if original in link:link=[str(extra) if item==original else item for item in link]
        else:link.append(str(extra))
    subprocess.run(link,cwd=root,check=True)
    print('Private MinUX test kernel:',output)


if __name__=='__main__':main()
