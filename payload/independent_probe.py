"""Owned data-only proof reader; no repository imports or native execution."""
import argparse,bisect,hashlib,json,re,struct
from pathlib import Path
def require(value,message):
    if not value:raise ValueError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def run(data,packet,native):
    require(len(data)==105896032 and sha(data)=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301','target identity')
    require(data[:7]==b'\x7fELF\x02\x01\x01' and struct.unpack_from('<H',data,18)[0]==62,'ELF64 LE x86-64')
    phoff,shoff=struct.unpack_from('<QQ',data,32);phsize,phcount,shsize,shcount,namesidx=struct.unpack_from('<HHHHH',data,54)
    require(phsize==56 and shsize==64 and phoff+phcount*56<=len(data) and shoff+shcount*64<=len(data),'header bounds')
    loads=[struct.unpack_from('<IIQQQQQQ',data,phoff+i*56) for i in range(phcount)]
    loads=[row for row in loads if row[0]==1]
    def at(address,size):
        rows=[r for r in loads if size>=0 and r[3]<=address and address+size<=r[3]+r[5]]
        require(len(rows)==1,'PT_LOAD mapping');r=rows[0];offset=r[2]+address-r[3]
        require(offset+size<=len(data),'file bounds');return offset,data[offset:offset+size]
    table=[struct.unpack_from('<IIQQQQIIQQ',data,shoff+64*i) for i in range(shcount)]
    require(namesidx<shcount,'name table bounds');name_section=table[namesidx]
    names=data[name_section[4]:name_section[4]+name_section[5]];sections={}
    for row in table:
        require(row[0]<len(names),'name offset');end=names.find(b'\0',row[0]);require(end>=row[0],'name termination')
        name=names[row[0]:end].decode('ascii');require(name not in sections,'duplicate section');sections[name]=row
    start,end=0x5b298d0,0x5b2a121;offset,body=at(start,end-start)
    require(len(body)==2129 and sha(body)=='7e6c3dd06f3d404eabe8db3e91c5cba649c56e4bd4bcee52b35435704dba1d3a','body identity')
    records=json.loads((packet/'records.json').read_text());claimed=records['bodies'][0]
    require(len(records['bodies'])==1 and int(claimed['start'],16)==start and int(claimed['end'],16)==end and claimed['sha256']==sha(body),'claimed body')
    hdr=sections['.eh_frame_hdr'];raw=data[hdr[4]:hdr[4]+hdr[5]]
    require(raw[:4]==bytes([1,0x1b,3,0x3b]),'unwind header encoding')
    count=struct.unpack_from('<I',raw,8)[0];require(len(raw)>=12+count*8,'unwind index bounds')
    entries=[tuple(hdr[3]+v for v in struct.unpack_from('<ii',raw,12+i*8)) for i in range(count)]
    require(all(entries[i][0]<entries[i+1][0] for i in range(count-1)),'unwind index ordering')
    index=bisect.bisect_left([r[0] for r in entries],start);require(entries[index][0]==start,'unwind entry')
    fde_va=entries[index][1];fde_off,fields=at(fde_va,16);length,back,delta,extent=struct.unpack('<IIii',fields)
    frame=sections['.eh_frame'];require(frame[4]<=fde_off<fde_off+length+4<=frame[4]+frame[5],'FDE extent bounds')
    cie_off=fde_off+4-back;cie_size,cie_id=struct.unpack_from('<II',data,cie_off)
    require(frame[4]<=cie_off<fde_off and cie_id==0 and cie_off+cie_size+4<=frame[4]+frame[5],'CIE bounds')
    cie=data[cie_off:cie_off+cie_size+4];require(cie[8]==1,'selected CIE version')
    augmentation_end=cie.find(b'\0',9);require(augmentation_end>9,'CIE augmentation bounds')
    augmentation=cie[9:augmentation_end].decode('ascii');require(augmentation in ['zR','zPLR'],'selected CIE augmentation')
    position=augmentation_end+1
    def leb():
        nonlocal position
        value=shift=0
        for _ in range(10):
            require(position<len(cie),'CIE LEB bounds');byte=cie[position];position+=1
            value|=(byte&127)<<shift
            if byte<128:return value
            shift+=7
        raise ValueError('CIE LEB length')
    leb();leb();position+=1
    augmentation_size=leb();limit=position+augmentation_size;require(limit<=len(cie),'CIE augmentation data bounds')
    for field in augmentation[1:]:
        require(position<limit,'CIE field bounds');encoding=cie[position];position+=1
        if field=='P':
            require(encoding==0x9b and position+4<=limit,'CIE personality encoding');position+=4
        elif field=='R':require(encoding==0x1b,'CIE FDE pointer encoding')
    require(position==limit,'CIE augmentation length')
    require(fde_va+8+delta==start and extent==end-start and claimed['enclosing_fde']['fde']==fde_va,'actual FDE start/end')
    providers={};boundaries={}
    for provider in ['gnu','llvm']:
        alternatives=[native/('sampler.'+provider+'.stdout'),native/('sampler.'+provider+'.txt')]
        path=next((p for p in alternatives if p.exists()),None);require(path is not None,'native export present')
        cursor=start;rows=[]
        for line in path.read_text().splitlines():
            match=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}[ \t]+)+)(.*)$',line)
            if not match:continue
            va=int(match[1],16);chunk=bytes.fromhex(match[2]);asm=match[3].strip()
            require(va==cursor and va+len(chunk)<=end and body[va-start:va-start+len(chunk)]==chunk,'complete native bytes')
            if asm:
                require('(bad)' not in asm and not asm.startswith('.byte'),'decoded native row');rows.append([va,chunk,asm])
            else:
                require(bool(rows),'native continuation');rows[-1][1]+=chunk
            cursor+=len(chunk)
        require(cursor==end and len(rows)==500,'native whole-body boundary/count')
        providers[provider]=[(a,b.hex()) for a,b,_ in rows]
        if provider=='gnu':boundaries={a:(b,c) for a,b,c in rows}
    require(providers['gnu']==providers['llvm'],'independent native byte/boundary agreement')
    obligations=json.loads((packet/'obligations.json').read_text())
    ends={a+len(b) for a,(b,_) in boundaries.items()}
    for key,row in obligations.items():
        begin,stop=int(row['va'],16),int(row['end'],16);chunk=bytes.fromhex(row['bytes'])
        require(begin in boundaries and stop in ends and stop-begin==len(chunk) and at(begin,len(chunk))[1]==chunk,'instruction span '+key)
    relocation=sections['.rela.dyn'];require(relocation[5]%24==0,'RELA size');relocs={}
    for pos in range(relocation[4],relocation[4]+relocation[5],24):
        destination,info,addend=struct.unpack_from('<QQq',data,pos)
        if destination not in relocs:relocs[destination]=[]
        relocs[destination].append((info,addend,pos))
    for binding in records['relative_bindings']:
        slot=int(binding['slot'],16);values=relocs.get(slot,[])
        require(len(values)==1 and values[0][0]==8 and values[0][1]==int(binding['target'],16) and values[0][2]==int(binding['relocation_file_offset'],16),'RELATIVE binding')
    location=0x64bca88;_,raw_location=at(location,24);stored,size,line,column=struct.unpack('<QQII',raw_location)
    require((stored,size,line,column)==(0,33,169,10),'source Location')
    require(relocs[location][0][:2]==(8,0x431e32) and at(0x431e32,33)[1]==b'node/src/group_and_seq_sampler.rs','source path binding')
    calls=[(a,b,c) for a,(b,c) in boundaries.items() if re.match(r'call\s',c)]
    require(len(calls)==28==len(claimed['calls_and_tail_jumps']),'complete call count')
    for (address,chunk,asm),record in zip(calls,claimed['calls_and_tail_jumps']):
        require(int(record['site'],16)==address and record['bytes']==chunk.hex(),'call binding')
        if chunk[0]==0xe8:require(int(record['direct_target'],16)==address+5+struct.unpack_from('<i',chunk,1)[0],'direct call target')
    relations=json.loads((packet/'relations.json').read_text());parameters=relations['parameters']
    operands={'record_stride':(0x5b29b5a,4),'value_offset':(0x5b29b66,1),'group_offset':(0x5b29b89,4),
        'sequence_offset':(0x5b29ba7,4),'pair_shift':(0x5b29b0a,1),'first_count':(0x5b29bd9,1),
        'second_count':(0x5b29ce2,1),'gate':(0x5b29d21,1),'hour_multiplier':(0x5b29cf1,4),
        'hour_shift':(0x5b29cfc,1),'hour_scale':(0x5b29cff,1),'minute_multiplier':(0x5b29d01,4),
        'minute_shift':(0x5b29d0c,1),'reduce_multiplier':(0x5b29d10,4),'reduce_shift':(0x5b29d17,1),'reduce_scale':(0x5b29d1a,1)}
    observed={key:int.from_bytes(at(address,n)[1],'little') for key,(address,n) in operands.items()}
    def validate_parameters(record):require(record==observed,'all native arithmetic/layout operands')
    validate_parameters(parameters)
    interval_proofs=[]
    for divisor,multiplier,shift,maximum in [(3600,observed['hour_multiplier'],observed['hour_shift'],2**32-1),
        (60,observed['minute_multiplier'],observed['minute_shift'],2**32-1),
        (60,observed['reduce_multiplier'],observed['reduce_shift'],(2**32-1)//60)]:
        unit=2**shift;error=divisor*multiplier-unit;upper=(maximum//divisor)*error+(divisor-1)*multiplier
        require(0<=error and upper<unit and maximum*multiplier<2**64,'reciprocal interval proof')
        interval_proofs.append(dict(divisor=divisor,multiplier=multiplier,shift=shift,maximum=maximum,error=error,upper=upper))
    values=set(range(1024))|{2**32-1,2**32-2}
    for i in range(2048):values.add(int.from_bytes(hashlib.sha256(('review2200:'+str(i)).encode()).digest()[:4],'little'))
    for x in values:
        hour=(x*observed['hour_multiplier'])>>observed['hour_shift'];minute=(x*observed['minute_multiplier'])>>observed['minute_shift']
        reduce=(minute*observed['reduce_multiplier'])>>observed['reduce_shift'];result=minute-60*reduce+60*hour
        require(hour==x//3600 and minute==x//60 and reduce==minute//60 and result==x//60 and (result>=6)==(x>=360),'independent arithmetic reference')
    controls=0
    for key in operands:
        wrong=dict(parameters);wrong[key]^=1
        try:validate_parameters(wrong)
        except ValueError:controls+=1
        else:raise ValueError('corrupted operand claim survived')
    return dict(status='INDEPENDENT_SAMPLER_BYTES_AND_ARITHMETIC_VERIFIED',target_sha256=sha(data),body_sha256=sha(body),
        start=hex(start),end=hex(end),bytes=len(body),native_instruction_rows=500,calls=28,source_locations=1,
        source_line=line,source_column=column,relative_bindings=len(records['relative_bindings']),instruction_spans=len(obligations),
        actual_fde_va=hex(fde_va),cie_file_offset=hex(cie_off),unwind_index_rows=count,
        native_operands_checked=len(operands),operand_corruption_controls=controls,interval_proofs=interval_proofs,
        full_u32_reciprocal_domain=2**32,additional_arithmetic_cases=len(values),
        conclusion='Native expression equals floor(word/60); unsigned threshold >=6 is word>=360. Grouping, helpers, clock units and runtime behavior remain unproven.',
        repository_imports=False,native_execution_by_this_reader=False,captured_program_execution=False)
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--binary',type=Path,required=True);parser.add_argument('--packet',type=Path,required=True);parser.add_argument('--native-dir',type=Path,required=True)
    args=parser.parse_args();print(json.dumps(run(args.binary.read_bytes(),args.packet,args.native_dir),indent=2))
if __name__=='__main__':main()
