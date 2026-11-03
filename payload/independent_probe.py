import argparse,bisect,hashlib,json,re,struct
from pathlib import Path

def require(ok,message):
    if not ok:raise ValueError(message)

def cie_encoding(cie):
    """Decode only supported version-1 zR/zPLR records, with bounded reads.

    Field interpretation checked against LLVM lld ELF/EhFrame.cpp; this is an
    independently authored reader, not imported/copied implementation code.
    """
    require(cie[8] == 1, 'Unsupported CIE version')
    end = cie.find(b'\0', 9)
    require(end > 9, 'CIE augmentation string bounds')
    augmentation = cie[9:end].decode('ascii')
    require(augmentation in ('zR', 'zPLR'), 'Unsupported augmentation string')
    pos = end + 1

    def leb():
        nonlocal pos
        value = shift = 0
        for _ in range(10):
            require(pos < len(cie), 'CIE LEB bounds')
            byte = cie[pos]
            pos += 1
            value |= (byte & 127) << shift
            if not byte & 128:
                return value
            shift += 7
        raise ValueError('CIE LEB too long')

    leb()  # Code alignment, value not used to decode pointer encoding.
    leb()  # Signed data alignment: only its bounded encoded length is needed.
    require(pos < len(cie), 'CIE return register bounds')
    pos += 1  # Version 1 has a one-byte return-address register.
    length = leb()
    limit = pos + length
    require(limit <= len(cie), 'CIE augmentation data bounds')
    fields = {'augmentation': augmentation}
    for char in augmentation[1:]:
        require(pos < limit, 'CIE augmentation field bounds')
        value = cie[pos]
        pos += 1
        if char == 'P':
            require(value == 0x9b and pos + 4 <= limit, 'Unsupported personality pointer encoding')
            fields['personality_pointer_encoding'] = hex(value)
            pos += 4
        elif char == 'L':
            fields['lsda_pointer_encoding'] = hex(value)
        elif char == 'R':
            fields['fde_pointer_encoding'] = value
    require(pos == limit and fields['fde_pointer_encoding'] == 0x1b, 'FDE pointer encoding or augmentation length mismatch')
    return fields

def inspect(data, claimed, native_dir):
    require(len(data)==105896032 and hashlib.sha256(data).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301','independent target identity')
    require(data[:7]==b'\x7fELF\x02\x01\x01' and struct.unpack_from('<H',data,18)[0]==62,'independent ELF type')
    phoff,shoff=struct.unpack_from('<QQ',data,32);phsize,phcount,shsize,shcount,namesidx=struct.unpack_from('<HHHHH',data,54)
    require(phsize==56 and shsize==64 and phoff+56*phcount<=len(data) and shoff+64*shcount<=len(data),'independent header bounds')
    loads=[struct.unpack_from('<IIQQQQQQ',data,phoff+56*i) for i in range(phcount)]
    loads=[r for r in loads if r[0]==1]
    def at(va,size):
        require(size>=0,'independent VA length')
        hits=[r for r in loads if r[3]<=va and va+size<=r[3]+r[5]]
        require(len(hits)==1,'independent PT_LOAD map');r=hits[0];off=r[2]+va-r[3]
        require(off+size<=len(data),'independent file bounds');return off,data[off:off+size]
    sections=[struct.unpack_from('<IIQQQQIIQQ',data,shoff+64*i) for i in range(shcount)]
    require(namesidx<shcount,'independent name table');s=sections[namesidx];names=data[s[4]:s[4]+s[5]]
    table={}
    for r in sections:
        end=names.find(b'\0',r[0]);require(0<=r[0]<end<len(names) or r[0]==end==0,'independent section name')
        name=names[r[0]:end].decode('ascii');require(name not in table,'independent duplicate section');table[name]=r
    location=0x64b6f68;s=table['.rela.dyn'];require(s[9]==24 and s[5]%24==0,'independent RELA shape')
    selected=[]
    for off in range(s[4],s[4]+s[5],24):
        dest,info,addend=struct.unpack_from('<QQq',data,off)
        if dest==location:selected.append((off,dest,info,addend))
    require(len(selected)==1,'independent unique Location relocation');rel_off,dest,info,path_va=selected[0]
    require(info==8,'independent relative relocation kind')
    loc_off,raw=at(location,24);pointer,length,line,column=struct.unpack('<QQII',raw)
    path_off,path=at(path_va,length);require(path==b'net_utils/src/rate_limiter.rs' and (line,column)==(131,20),'independent Location path/coordinates')
    location_record=dict(va=hex(location),file_offset=hex(loc_off),raw=raw.hex(),stored_pointer=hex(pointer),
        relocation_file_offset=hex(rel_off),relocation_raw=data[rel_off:rel_off+24].hex(),info=info,
        path_va=hex(path_va),path_file_offset=hex(path_off),path=path.decode(),length=length,line=line,column=column)
    hdr,frame=table['.eh_frame_hdr'],table['.eh_frame'];pos=hdr[4]
    require(data[pos:pos+4]==bytes.fromhex('011b033b'),'independent unwind encoding')
    count=struct.unpack_from('<I',data,pos+8)[0];require(12+count*8<=hdr[5],'independent unwind length')
    entries=[tuple(hdr[3]+v for v in struct.unpack_from('<ii',data,pos+12+8*i)) for i in range(count)]
    starts=[r[0] for r in entries];require(all(a<b for a,b in zip(starts,starts[1:])),'independent unwind ordering')
    regions=[];fde_records=[];native_summaries=[]
    for ref in [0x59db91d,0x59dbbad]:
        index=bisect.bisect_right(starts,ref)-1;require(index>=0,'independent unwind lookup')
        start,fde_va=entries[index];off,fields=at(fde_va,16);size,distance,delta,extent=struct.unpack('<IIii',fields)
        require(12<=size<4096 and frame[4]<=off<off+size+4<=frame[4]+frame[5],'independent FDE bounds')
        cie_off=off+4-distance;require(frame[4]<=cie_off<off,'independent CIE back-reference')
        cie_size,cie_id=struct.unpack_from('<II',data,cie_off);require(cie_id==0 and cie_off+4+cie_size<=frame[4]+frame[5],'independent CIE bounds')
        encoding=cie_encoding(data[cie_off:cie_off+4+cie_size])
        require(fde_va+8+delta==start and start<=ref<start+extent,'independent actual FDE extent')
        body_off,body=at(start,extent);ref_off,pair=at(ref,12)
        require(pair[:3]==bytes.fromhex('488d35') and pair[7]==0xe8,'independent LEA/call opcodes')
        require(ref+7+struct.unpack_from('<i',pair,3)[0]==location,'independent LEA destination')
        callee=ref+12+struct.unpack_from('<i',pair,8)[0]
        region=dict(start_va=hex(start),end_va=hex(start+extent),extent_bytes=extent,body_sha256=hashlib.sha256(body).hexdigest(),
            reference_va=hex(ref),reference_file_offset=hex(ref_off),lea_and_call_bytes=pair.hex(),direct_call_target=hex(callee))
        text=(native_dir/('native-'+format(start,'x')+'.txt')).read_text();cursor=start;boundaries={};rows=0;continuations=0
        for textline in text.splitlines():
            if not re.match(r'^\s*[0-9a-f]+:',textline):continue
            parts=textline.split('\t');require(len(parts)>=2,'independent native columns')
            va=int(parts[0].strip().rstrip(':'),16);tokens=parts[1].split();require(tokens and all(re.fullmatch('[0-9a-f]{2}',t) for t in tokens),'independent native bytes')
            actual=bytes.fromhex(' '.join(tokens));require(va==cursor and body[va-start:va-start+len(actual)]==actual,'independent native full-range bytes')
            mnemonic=' '.join(parts[2:]).strip() if len(parts)>2 else ''
            if mnemonic:
                require('(bad)' not in mnemonic and not mnemonic.startswith('.byte'),'independent undecoded bytes')
                boundaries[va]=(actual,mnemonic);rows+=1
            else:continuations+=1
            cursor+=len(actual)
        require(cursor==start+extent,'independent native coverage end')
        require(boundaries.get(ref,(None,''))[0]==pair[:7] and boundaries[ref][1].startswith('lea'),'independent LEA boundary')
        require(boundaries.get(ref+7,(None,''))[0]==pair[7:] and boundaries[ref+7][1].startswith('call'),'independent call boundary')
        regions.append(region);fde_records.append(dict(start_va=hex(start),end_va=hex(start+extent),fde_va=hex(fde_va),
            fde_file_offset=hex(off),fde_hex=data[off:off+size+4].hex(),cie_file_offset=hex(cie_off),cie_fields=encoding))
        native_summaries.append(dict(start_va=hex(start),bytes=extent,instruction_rows=rows,continuation_rows=continuations,all_bytes_matched=True))
    observed=dict(target_sha256=hashlib.sha256(data).hexdigest(),target_size=len(data),location=location_record,regions=regions,
        counts=dict(source_locations=1,native_references=2,unwind_extents=2))
    def compare(record):
        for key in observed:require(record[key]==observed[key],'independent claimed proof mismatch: '+key)
    compare(claimed);controls=[]
    def mutant(label,edit):
        record=json.loads(json.dumps(claimed));edit(record)
        try:compare(record)
        except ValueError as error:controls.append(dict(control=label,rejection=str(error)))
        else:raise ValueError('independent proof corruption escaped')
    mutant('Location line',lambda r:r['location'].__setitem__('line',132))
    mutant('relocated path pointer',lambda r:r['location'].__setitem__('path_va','0x0'))
    mutant('relocation type',lambda r:r['location'].__setitem__('info',1))
    mutant('source path',lambda r:r['location'].__setitem__('path','other.rs'))
    for i in range(2):
        mutant('extent '+str(i),lambda r,i=i:r['regions'][i].__setitem__('end_va',hex(int(r['regions'][i]['end_va'],16)-1)))
        mutant('callee '+str(i),lambda r,i=i:r['regions'][i].__setitem__('direct_call_target','0x0'))
        mutant('body hash '+str(i),lambda r,i=i:r['regions'][i].__setitem__('body_sha256','0'*64))
        mutant('instruction bytes '+str(i),lambda r,i=i:r['regions'][i].__setitem__('lea_and_call_bytes','00'*12))
    return dict(status='INDEPENDENT_FULL_INPUT_COORDINATES_VERIFIED',observed=observed,unwind_rows_checked=count,
        fde_records=fde_records,native_coverage=native_summaries,proof_corruptions_rejected=len(controls),controls=controls,
        repository_imports=False,native_decoder_run_by_this_reader=False,captured_execution=False,
        limits='Two selected native references and actual unwind ranges only; no callee/algorithm/source-ownership/exception closure.')

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--binary',type=Path,required=True);parser.add_argument('--proof',type=Path,required=True);parser.add_argument('--native-dir',type=Path,required=True)
    args=parser.parse_args();print(json.dumps(inspect(args.binary.read_bytes(),json.loads(args.proof.read_text()),args.native_dir),indent=2))
if __name__=='__main__':main()
