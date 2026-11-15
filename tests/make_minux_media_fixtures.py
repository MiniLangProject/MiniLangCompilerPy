"""Generate small deterministic PCM/AVI fixtures without external codecs."""
from pathlib import Path
import argparse
import math
import struct
import wave


def chunk(kind, data):
    return kind+struct.pack('<I',len(data))+data+(b'\0' if len(data)%2 else b'')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path)
    args=parser.parse_args();args.output.mkdir(parents=True,exist_ok=True)
    with wave.open(str(args.output/'tone.wav'),'wb') as wav:
        wav.setnchannels(2);wav.setsampwidth(2);wav.setframerate(8000)
        wav.writeframes(b''.join(struct.pack('<hh',int(math.sin(i*2*math.pi*440/8000)*10000),int(math.sin(i*2*math.pi*440/8000)*10000)) for i in range(8000)))
    avih=struct.pack('<14I',200000,80,0,0,5,0,1,16,2,2,0,0,0,0)
    strh=b'vidsDIB '+struct.pack('<IHH8I4h',0,0,0,0,1,5,0,5,16,0xffffffff,0,0,0,2,2)
    strf=struct.pack('<IiiHH6I',40,2,2,1,24,0,16,0,0,0,0)
    headers=chunk(b'LIST',b'hdrl'+chunk(b'avih',avih)+chunk(b'LIST',b'strl'+chunk(b'strh',strh)+chunk(b'strf',strf)))
    frames=[]
    for i in range(5):
        pixels=bytes((0,0,255-i*40))*2+b'\0\0'+bytes((255-i*40,0,0))*2+b'\0\0'
        frames.append(chunk(b'00db',pixels))
    avi=chunk(b'RIFF',b'AVI '+headers+chunk(b'LIST',b'movi'+b''.join(frames)))
    (args.output/'colors.avi').write_bytes(avi)
    wav=(args.output/'tone.wav').read_bytes()
    malformed=[b'',b'RIFF',b'RIFF\xff\xff\xff\xffWAVE',wav[:30],avi[:60],b'RIFF\x04\0\0\0MP3 ']
    for offset in (4,12+4,20,22,24,28,32,34,40):
        bad=bytearray(wav);bad[offset:offset+4]=b'\xff'*4;malformed.append(bytes(bad))
    for size in (12,24,48,100,len(avi)-1):malformed.append(avi[:size])
    for i,data in enumerate(malformed):(args.output/f'bad-{i}').write_bytes(data)


if __name__=='__main__':main()
