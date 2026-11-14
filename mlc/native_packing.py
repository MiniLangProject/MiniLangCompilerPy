"""Dependency-free x64 PE/ELF packing for compiler-generated fixed images.

The checked-in loader bytes are assembled from pack_stubs/loader.S only when
developing the compiler. Packing itself uses no external executable or library.
"""

import struct
import zlib

from . import pack_loader_bytes

MAGIC = b'MLNPACK1'
IMAGE_LIMIT = 1 << 30
FOOTER = struct.Struct('<10I8s')


class NativePackingError(ValueError):
    """Reject unsupported, corrupt, or non-shrinking packed images."""

def align(value, n=4096):
    return (value+n-1) & -n


def fnv32(data):
    """Match the loader's portable FNV-1a check of compressed code bytes."""
    value = 2166136261
    for byte in data:
        value = ((value ^ byte) * 16777619) & 0xFFFFFFFF
    return value

def lz4_encode(data):
    n=len(data)
    out=bytearray()
    if n<13:
        return bytes([n<<4])+data
    table_size=4096
    while table_size<n*4 and table_size<65536:
        table_size*=2
    table=[-1]*table_size
    mask=table_size-1
    anchor=position=0
    search=1
    limit=n-12
    def extra(length):
        while length>=255:
            out.append(255);length-=255
        out.append(length)
    while position<=limit:
        word=struct.unpack_from('<I',data,position)[0]
        slot=(((word*2654435761)&0xffffffff)>>16)&mask
        previous=table[slot]
        table[slot]=position
        if previous>=0 and position-previous<=65535 and data[previous:previous+4]==data[position:position+4]:
            literal_length=position-anchor
            matched=4
            match_limit=n-5-position
            word_limit=match_limit-3
            while matched<word_limit and data[previous+matched:previous+matched+4]==data[position+matched:position+matched+4]:
                matched+=4
            while matched<match_limit and data[previous+matched]==data[position+matched]:
                matched+=1
            match_extra=matched-4
            out.append((min(15,literal_length)<<4)|min(15,match_extra))
            if literal_length>=15:extra(literal_length-15)
            out.extend(data[anchor:position])
            offset=position-previous
            out.extend((offset&255,offset>>8))
            if match_extra>=15:extra(match_extra-15)
            position+=matched
            anchor=position
            search=1
        else:
            position+=(search>>6)+1
            search+=1
    literal_length=n-anchor
    out.append(min(15,literal_length)<<4)
    if literal_length>=15:extra(literal_length-15)
    out.extend(data[anchor:])
    return bytes(out)


def lz4_decode(block, expected_size):
    """Decode a bounded LZ4 block exactly as the embedded startup stub does."""
    if not 0 <= expected_size <= IMAGE_LIMIT:
        raise NativePackingError('invalid decoded text size')
    output=bytearray(expected_size)
    src=dst=0
    while src<len(block):
        token=block[src];src+=1
        literal=token>>4
        if literal==15:
            while True:
                if src>=len(block):raise NativePackingError('truncated literal length')
                extension=block[src];src+=1;literal+=extension
                if extension!=255:break
        if literal>len(block)-src or literal>expected_size-dst:
            raise NativePackingError('invalid literal length')
        output[dst:dst+literal]=block[src:src+literal]
        dst+=literal;src+=literal
        if src==len(block):
            if dst!=expected_size:raise NativePackingError('decoded text length mismatch')
            return bytes(output)
        if len(block)-src<2:raise NativePackingError('truncated match offset')
        offset=block[src]|block[src+1]<<8;src+=2
        if not 0<offset<=dst:raise NativePackingError('invalid match offset')
        matched=(token&15)+4
        if token&15==15:
            while True:
                if src>=len(block):raise NativePackingError('truncated match length')
                extension=block[src];src+=1;matched+=extension
                if extension!=255:break
        if matched>expected_size-dst:raise NativePackingError('invalid match length')
        for index in range(matched):output[dst+index]=output[dst+index-offset]
        dst+=matched
    raise NativePackingError('empty LZ4 block')

def pack_elf(original,stub):
    if (len(original)<4096 or original[:4]!=b'\x7fELF' or original[4:6]!=b'\x02\x01'):
        raise NativePackingError('only compiler-generated ELF64 images are supported')
    eh=list(struct.unpack_from('<HHIQQQIHHHHHH',original,16))
    if eh[0]!=2 or eh[1]!=62 or eh[4]!=64 or eh[7]!=64 or eh[8]!=56 or eh[9] not in (4,6):
        raise NativePackingError('unsupported ELF program headers')
    phoff=eh[4];phnum=eh[9]
    ph=[list(struct.unpack_from('<IIQQQQQQ',original,phoff+i*56)) for i in range(phnum)]
    text=next(row for row in ph if row[0]==1 and row[1]==5)
    header=next(row for row in ph if row[0]==1 and row[2]==0)
    if (text[2]!=4096 or text[5]<=0 or text[5]!=text[6] or
            text[2]+text[5]>len(original)):
        raise NativePackingError('invalid original ELF text')
    original_text=original[text[2]:text[2]+text[5]]
    packed=lz4_encode(original_text)
    cursor=4096
    for row in ph:
        if row is text:
            row[2]=4096;row[5]=0
        elif row[0]==1 and row is not header:
            old_off=row[2]
            new_off=align(cursor)
            cursor=new_off+row[5]
            for other in ph:
                if other[0] in (2,3) and old_off<=other[2]<old_off+row[5]:
                    other[2]=new_off+(other[2]-old_off)
            row[2]=new_off
    loader_va=align(max(row[3]+row[6] for row in ph if row[0]==1))
    loader_off=align(cursor);cursor=loader_off+len(stub)
    packed_va=align(loader_va+len(stub))
    packed_off=align(cursor);cursor=packed_off+len(packed)
    blob=bytearray(stub)
    for i,val in enumerate((packed_va,text[3],len(original_text),len(packed),eh[3],0,0,
                            align(text[6]),fnv32(packed))):
        marker=bytes([(i+1)*0x11])*8
        off=blob.find(marker)
        if off<0:
            raise NativePackingError('missing ELF loader patch marker')
        struct.pack_into('<Q',blob,off,val)
    ph.extend(([1,5,loader_off,loader_va,loader_va,len(blob),len(blob),4096],
               [1,4,packed_off,packed_va,packed_va,len(packed),len(packed),4096]))
    result=bytearray(cursor)
    result[:4096]=original[:4096]
    eh[3]=loader_va
    eh[9]=len(ph)
    struct.pack_into('<HHIQQQIHHHHHH',result,16,*eh)
    for i,row in enumerate(ph):
        struct.pack_into('<IIQQQQQQ',result,phoff+i*56,*row)
    for row in ph:
        if row[0]==1 and row is not header and row is not text and row[2] not in (loader_off,packed_off):
            old=next(x for x in struct.iter_unpack('<IIQQQQQQ',original[phoff:phoff+phnum*56]) if x[0]==1 and x[3]==row[3])
            result[row[2]:row[2]+row[5]]=original[old[2]:old[2]+old[5]]
    result[loader_off:loader_off+len(blob)]=blob
    result[packed_off:packed_off+len(packed)]=packed
    return bytes(result), text[2], len(original_text), packed_off, len(packed)

def pe_imports(original,sections,import_rva):
    def file_offset(rva):
        for section in sections:
            _,virtual_size,virtual_addr,raw_size,raw_addr,*_=section
            if virtual_addr<=rva<virtual_addr+max(virtual_size,raw_size):
                return raw_addr+rva-virtual_addr
        raise ValueError(f'unmapped RVA {rva:x}')
    found={}
    position=file_offset(import_rva)
    while True:
        original_thunk,_,_,name_rva,first_thunk=struct.unpack_from('<IIIII',original,position)
        if not name_rva:break
        dll_pos=file_offset(name_rva)
        dll=original[dll_pos:original.index(b'\0',dll_pos)].decode('ascii').lower()
        if dll=='kernel32.dll':
            index=0
            while True:
                name_entry=struct.unpack_from('<Q',original,file_offset(original_thunk)+index*8)[0]
                if name_entry==0:break
                name_pos=file_offset(name_entry)+2
                symbol=original[name_pos:original.index(b'\0',name_pos)].decode('ascii')
                found[symbol]=first_thunk+index*8
                index+=1
        position+=20
    return found

def pack_pe(original,stub):
    if len(original)<4096 or original[:2]!=b'MZ':
        raise NativePackingError('only compiler-generated PE images are supported')
    pe=struct.unpack_from('<I',original,0x3c)[0]
    if original[pe:pe+4]!=b'PE\0\0':
        raise NativePackingError('invalid PE signature')
    n=struct.unpack_from('<H',original,pe+6)[0]
    opt=pe+24
    if n!=5 or struct.unpack_from('<H',original,opt)[0]!=0x20b:
        raise NativePackingError('only compiler-generated five-section PE images can be packed')
    base=struct.unpack_from('<Q',original,opt+24)[0]
    entry=struct.unpack_from('<I',original,opt+16)[0]
    import_rva=struct.unpack_from('<I',original,opt+120)[0]
    header_size=struct.unpack_from('<I',original,opt+60)[0]
    section_align=struct.unpack_from('<I',original,opt+32)[0]
    file_align=struct.unpack_from('<I',original,opt+36)[0]
    sh=opt+0xf0
    if (file_align!=512 or section_align!=4096 or header_size>4096 or
            sh+(n+2)*40>header_size):
        raise NativePackingError('unsupported PE layout')
    sections=[]
    for i in range(n):
        pos=sh+i*40
        name=original[pos:pos+8].rstrip(b'\0').decode('ascii')
        vs,va,rs,ra=struct.unpack_from('<IIII',original,pos+8)
        char=struct.unpack_from('<I',original,pos+36)[0]
        sections.append([name,vs,va,rs,ra,char])
    text=next(row for row in sections if row[0]=='.text')
    if (text is not sections[0] or text[4]!=header_size or text[3]<=0 or
            text[4]+text[3]>len(original)):
        raise NativePackingError('invalid original PE text')
    imports=pe_imports(original,sections,import_rva)
    if 'VirtualProtect' not in imports or 'ExitProcess' not in imports:
        raise NativePackingError('rebuild with a compiler that imports VirtualProtect before native packing')
    original_text=original[text[4]:text[4]+text[3]]
    packed=lz4_encode(original_text)
    loader_va=align(max(row[2]+row[1] for row in sections),section_align)
    packed_va=align(loader_va+len(stub),section_align)
    blob=bytearray(stub)
    for i,val in enumerate((base+packed_va,base+text[2],len(original_text),len(packed),base+entry,
                            base+imports['VirtualProtect'],base+imports['ExitProcess'],
                            align(text[1],section_align),fnv32(packed))):
        marker=bytes([(i+1)*0x11])*8
        pos=blob.find(marker)
        if pos<0:
            raise NativePackingError('missing PE loader patch marker')
        struct.pack_into('<Q',blob,pos,val)
    cursor=header_size
    result=bytearray(original[:header_size])
    text[3]=text[4]=0
    for row in sections:
        if row is text:continue
        if row[3]:
            original_row=next(r for r in range(n) if original[sh+r*40:sh+r*40+8].rstrip(b'\0').decode('ascii')==row[0])
            old_pos=struct.unpack_from('<I',original,sh+original_row*40+20)[0]
            row[4]=cursor
            result.extend(original[old_pos:old_pos+row[3]])
            cursor+=row[3]
        else:
            row[4]=cursor
    stub_raw=align(len(blob),file_align)
    packed_raw=align(len(packed),file_align)
    loader_row=['.loader',len(blob),loader_va,stub_raw,cursor,0x60000020]
    result.extend(blob)
    result.extend(b'\0'*(stub_raw-len(blob)))
    cursor+=stub_raw
    packed_row=['.packed',len(packed),packed_va,packed_raw,cursor,0x40000040]
    result.extend(packed)
    result.extend(b'\0'*(packed_raw-len(packed)))
    for i,row in enumerate(sections+[loader_row,packed_row]):
        pos=sh+i*40
        name,vs,va,rs,ra,char=row
        struct.pack_into('<8sIIIIIIHHI',result,pos,name.encode().ljust(8,b'\0'),vs,va,rs,ra,0,0,0,0,char)
    struct.pack_into('<H',result,pe+6,n+2)
    struct.pack_into('<I',result,opt+16,loader_va)
    struct.pack_into('<I',result,opt+56,align(packed_va+len(packed),section_align))
    original_text_off=struct.unpack_from('<I',original,sh+20)[0]
    return bytes(result), original_text_off, len(original_text), packed_row[4], len(packed)

def _pe_sections(image):
    pe=struct.unpack_from('<I',image,0x3c)[0]
    if image[pe:pe+4]!=b'PE\0\0':raise NativePackingError('invalid PE header')
    n=struct.unpack_from('<H',image,pe+6)[0]
    start=pe+24+0xf0
    return {image[start+i*40:start+i*40+8].rstrip(b'\0').decode('ascii'):
            struct.unpack_from('<IIII',image,start+i*40+8)
            for i in range(n)}


def _elf_loads(image):
    phoff=struct.unpack_from('<Q',image,32)[0]
    count=struct.unpack_from('<H',image,56)[0]
    return {row[3]:row for row in
            (struct.unpack_from('<IIQQQQQQ',image,phoff+i*56) for i in range(count))
            if row[0]==1 and row[2]!=0}


def unpack_image(image):
    """Restore the exact original image from the checked native footer."""
    if len(image)<FOOTER.size or image[-8:]!=MAGIC:
        raise NativePackingError('not a native MiniLang packed image')
    (original_size,text_off,text_size,packed_off,packed_size,base_size,
     prefix_size,original_crc,base_crc,prefix_crc,_) = FOOTER.unpack_from(image,len(image)-FOOTER.size)
    if (not 0<original_size<=IMAGE_LIMIT or not 0<base_size<=IMAGE_LIMIT or
        not 0<prefix_size<=4096 or base_size+prefix_size+FOOTER.size!=len(image) or
        text_off!=prefix_size or text_size>original_size-text_off or
        packed_off>base_size or packed_size>base_size-packed_off):
        raise NativePackingError('invalid packed image lengths')
    base=image[:base_size]
    prefix=image[base_size:base_size+prefix_size]
    if zlib.crc32(base)!=base_crc or zlib.crc32(prefix)!=prefix_crc:
        raise NativePackingError('packed image checksum mismatch')
    result=bytearray(original_size)
    result[:prefix_size]=prefix
    result[text_off:text_off+text_size]=lz4_decode(base[packed_off:packed_off+packed_size],text_size)
    if prefix[:2]==b'MZ':
        original_sections=_pe_sections(prefix)
        packed_sections=_pe_sections(base)
        for name,(virtual_size,virtual_addr,raw_size,raw_addr) in original_sections.items():
            if name=='.text' or raw_size==0:continue
            if name not in packed_sections:raise NativePackingError('missing PE section')
            _,_,packed_raw_size,packed_raw_addr=packed_sections[name]
            if (packed_raw_size!=raw_size or raw_addr+raw_size>original_size or
                packed_raw_addr+raw_size>base_size):
                raise NativePackingError('invalid PE section')
            result[raw_addr:raw_addr+raw_size]=base[packed_raw_addr:packed_raw_addr+raw_size]
    elif prefix[:4]==b'\x7fELF':
        originals=_elf_loads(prefix)
        packed=_elf_loads(base)
        for address,row in originals.items():
            if row[1]==5:continue
            if address not in packed:raise NativePackingError('missing ELF segment')
            other=packed[address]
            if row[5]!=other[5] or row[2]+row[5]>original_size or other[2]+row[5]>base_size:
                raise NativePackingError('invalid ELF segment')
            result[row[2]:row[2]+row[5]]=base[other[2]:other[2]+row[5]]
    else:
        raise NativePackingError('invalid original image header')
    if zlib.crc32(result)!=original_crc:
        raise NativePackingError('restored image checksum mismatch')
    return bytes(result)


def pack_image(original):
    """Pack compiler-generated PE/ELF code, then prove exact restoration."""
    if not 0<len(original)<=IMAGE_LIMIT:raise NativePackingError('invalid input size')
    if original[-8:]==MAGIC:raise NativePackingError('image is already packed')
    try:
        if original[:2]==b'MZ':
            base,text_off,text_size,packed_off,packed_size=pack_pe(original,pack_loader_bytes.WINDOWS)
        elif original[:4]==b'\x7fELF':
            base,text_off,text_size,packed_off,packed_size=pack_elf(original,pack_loader_bytes.LINUX)
        else:
            raise NativePackingError('only MiniLang PE/ELF images are supported')
    except (IndexError, KeyError, StopIteration, UnicodeError, struct.error, ValueError) as exc:
        raise NativePackingError(f'unsupported compiler image: {exc}') from exc
    prefix=original[:text_off]
    if len(base)+len(prefix)+FOOTER.size>=len(original):
        raise NativePackingError('packing would not make this executable smaller')
    footer=FOOTER.pack(len(original),text_off,text_size,packed_off,packed_size,
                       len(base),len(prefix),zlib.crc32(original),zlib.crc32(base),
                       zlib.crc32(prefix),MAGIC)
    packed=base+prefix+footer
    if unpack_image(packed)!=original:
        raise NativePackingError('packed image did not roundtrip')
    return packed
