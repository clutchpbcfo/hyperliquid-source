#!/usr/bin/env python3
"""Read the authenticated full ELF and retained evidence; never execute captured code."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

TARGET_SHA='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START=0x15c0d90
constructor_start=0x1619820
post_start=0x15b9ce0
expected_diagnostic=b'data did not match any variant of untagged enum JsonRpcResult'
def require(condition,message):
    if not condition:raise ValueError(message)
def read_json(path):return json.loads(path.read_text())

def validate(body):
    for name,(address,expected) in sites.items():
        expected=bytes.fromhex(expected);actual=body[address-START:address-START+len(expected)]
        if actual!=expected:raise ValueError('field binding drift: '+name)
    # Independent relative-displacement arithmetic, not decoder text matching.
    for address,dest in [(0x15c104e,0x15be300),(0x15c1185,0x15b9ce0),(0x15c127d,0x1619820)]:
        if address+5+struct.unpack_from('<i',body,address-START+1)[0]!=dest:raise ValueError('call destination drift')
    for address,length,dest in [(0x15c0de2,2,0x15c0e19),(0x15c0e1c,6,0x15c1409),
        (0x15c0e35,6,0x15c1422),(0x15c0ef6,6,0x15c1273),(0x15c0f09,6,0x15c144b),
        (0x15c102b,6,0x15c148a),(0x15c105d,6,0x15c13f5)]:
        disp=struct.unpack_from('<b' if length==2 else '<i',body,address-START+(1 if length==2 else 2))[0]
        if address+length+disp!=dest or dest not in native:raise ValueError('branch destination drift')

def inspect(c,p,message):
    """Interpret only selected byte fields. No whole-excerpt digest gate here."""
    def check(condition,reason):
        if not condition:raise ValueError(reason)
    def at(body,start,va,n):return bytes(body[va-start:va-start+n])
    def call(va,destination):
        code=at(c,constructor_start,va,5)
        check(len(code)==5 and code[0]==0xe8,'direct call opcode')
        actual=va+5+struct.unpack_from('<i',code,1)[0]
        check(actual==destination,'direct helper destination')
    for va,dest in [(0x1619856,0x15b01d0),(0x16198ae,0x15a8ec0),(0x16198d6,0x15a89d0),(0x16198f8,0x1619690)]:call(va,dest)
    check(at(c,constructor_start,0x1619835,4)==bytes.fromhex('48c1e106'),'64-byte iterator stride')
    check(at(c,constructor_start,0x1619860,2)==bytes.fromhex('3c16'),'initial raw special tag')
    check(at(c,constructor_start,0x1619862,2)==bytes.fromhex('751b'),'initial special-tag branch')
    for va in [0x161986d,0x16198b3]:
        code=at(c,constructor_start,va,10)
        check(code[:2] in [b'\x48\xb8',b'\x49\xbe'] and struct.unpack_from('<Q',code,2)[0]==0x8000000000000001,'raw sentinel')
    check(at(c,constructor_start,0x16198c2,2)==bytes.fromhex('7542'),'first alternative sentinel branch')
    check(at(c,constructor_start,0x16198e0,2)==bytes.fromhex('7524'),'second alternative sentinel branch')
    pointer=at(c,constructor_start,0x16198ec,7)
    check(pointer[:3]==bytes.fromhex('488d3d') and 0x16198ec+7+struct.unpack_from('<i',pointer,3)[0]==0x26393a,'diagnostic RIP binding')
    length=at(c,constructor_start,0x16198f3,5)
    check(length[0]==0xbe and struct.unpack_from('<I',length,1)[0]==61,'diagnostic length')
    check(bytes(message)==expected_diagnostic,'diagnostic bytes/name')
    # Decode offsets/widths of every ordinary output store, rather than merely counting instructions.
    coverage=[]
    for va,size,prefix in [(0x161990e,8,'488943'),(0x1619917,16,'0f1143'),(0x1619920,16,'0f1143'),
                           (0x1619938,16,'0f115b'),(0x161993c,16,'0f1153'),(0x1619940,16,'0f114b')]:
        code=at(c,constructor_start,va,4)
        check(code[:3]==bytes.fromhex(prefix),'ordinary output store opcode')
        coverage.extend(range(code[3],code[3]+size))
    check(at(c,constructor_start,0x1619944,3)==bytes.fromhex('0f1103'),'ordinary first store')
    coverage.extend(range(16))
    check(sorted(coverage)==list(range(104)),'104-byte output coverage')
    maskcode=at(p,post_start,0x15b9cfb,10)
    check(maskcode[:2]==bytes.fromhex('48be'),'whitespace mask opcode')
    mask=struct.unpack_from('<Q',maskcode,2)[0]
    bound=at(p,post_start,0x15b9d0b,4)
    check(bound[:3]==bytes.fromhex('4983f8'),'scan bound opcode')
    whitespace=[b for b in range(256) if b<=bound[3] and (mask>>(b&63))&1]
    check(whitespace==[9,10,13,32],'local whitespace predicate')
    check(at(p,post_start,0x15b9d5b,4)==bytes.fromhex('4183f87d'),'closing brace predicate')
    check(at(p,post_start,0x15b9d5f,2)==bytes.fromhex('7510'),'closing brace branch')
    check(at(p,post_start,0x15b9d66,4)==bytes.fromhex('48894728'),'closing cursor store')
    check(at(p,post_start,0x15b9d6a,2)==bytes.fromhex('31c0'),'closing local zero return')
    for va,expected in [(0x15b9d2b,3),(0x15b9d46,0x15),(0x15b9d71,0x16)]:
        code=at(p,post_start,va,8)
        check(code[:4]==bytes.fromhex('48c70424') and struct.unpack_from('<I',code,4)[0]==expected,'raw local diagnostic code')
    return {'whitespace_domain':256,'whitespace_bytes':whitespace,'ordinary_output_bytes':len(coverage),
            'constructor_diagnostic':bytes(message).decode(),'alternative_targets':['0x15a8ec0','0x15a89d0'],
            'closing_byte':125,'explicit_local_closing_return':0,'postobject_raw_codes':[3,21,22]}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,required=True)
    parser.add_argument('--packet',type=Path,default=Path(__file__).resolve().parent)
    args=parser.parse_args();packet=args.packet
    for line in (packet/'MANIFEST.sha256').read_text().splitlines():
        digest,name=line.split('  ',1)
        require(not Path(name).is_absolute() and '..' not in Path(name).parts,'unsafe manifest path')
        require(hashlib.sha256((packet/name).read_bytes()).hexdigest()==digest,'packet file drift: '+name)
    data=args.binary.read_bytes()
    require(len(data)==91774280 and hashlib.sha256(data).hexdigest()==TARGET_SHA,'complete target identity mismatch')
    require(data[:7]==b'\x7fELF\x02\x01\x01' and struct.unpack_from('<H',data,18)[0]==62,'unsupported ELF')
    shoff=struct.unpack_from('<Q',data,40)[0]
    size,count,names_index=struct.unpack_from('<HHH',data,58)
    require(size==64 and 0<names_index<count and shoff+count*64<=len(data),'section table bounds')
    headers=[struct.unpack_from('<IIQQQQIIQQ',data,shoff+64*i) for i in range(count)]
    name_header=headers[names_index]
    table=data[name_header[4]:name_header[4]+name_header[5]]
    sections={}
    for h in headers:
        end=table.find(b'\0',h[0]);require(0<=h[0]<=end<len(table),'section name bounds')
        name=table[h[0]:end].decode('ascii');require(name not in sections,'duplicate section name')
        if h[1]!=8:require(h[4]+h[5]<=len(data),'section file bounds')
        sections[name]=h
    def at_va(va,length,executable=False,readonly=False):
        rows=[h for h in headers if h[1]!=8 and h[3]<=va and va+length<=h[3]+h[5]]
        require(len(rows)==1,'ambiguous/unmapped VA')
        h=rows[0]
        if executable:require(bool(h[2]&4),'non-executable code range')
        if readonly:require(bool(h[2]&2) and not h[2]&5,'non-readonly data range')
        off=h[4]+va-h[3]
        return data[off:off+length],off
    index=sections['.eh_frame_hdr'];frame=sections['.eh_frame'];ipos=index[4]
    require(data[ipos:ipos+4]==bytes([1,0x1b,3,0x3b]),'unsupported unwind header')
    n=struct.unpack_from('<I',data,ipos+8)[0]
    require(n==121299 and 12+n*8<=index[5],'unwind table count/bounds')
    entries=[tuple(index[3]+v for v in struct.unpack_from('<ii',data,ipos+12+8*i)) for i in range(n)]
    require(all(a[0]<b[0] for a,b in zip(entries,entries[1:])),'unwind table ordering')
    evidence=read_json(packet/'evidence.json')
    def range_binding(r,blob):
        start=int(r['start_va'],16);end=int(r['end_va'],16);fde=int(r['fde_va'],16);off=int(r['fde_file_offset'],16)
        require(entries[r['unwind_index_row']]==(start,fde),'unwind row binding')
        length,distance=struct.unpack_from('<II',blob,off)
        require(8<=length<4096 and frame[4]<=off<off+4+length<=frame[4]+frame[5],'FDE bounds')
        cie=off+4-distance
        require(cie==int(r['cie_file_offset'],16),'CIE back reference')
        delta,extent=struct.unpack_from('<ii',blob,off+8)
        require(fde+8+delta==start and start+extent==end and extent==r['bytes'],'FDE decoded range drift')
        require(blob[off:off+4+length].hex()==r['fde_hex'],'FDE bytes drift')
        clen,cid=struct.unpack_from('<II',blob,cie)
        require(cid==0 and frame[4]<=cie<cie+4+clen<=frame[4]+frame[5],'CIE bounds/id')
        require(blob[cie:cie+4+clen].hex()==r['cie_hex'],'CIE bytes drift')
        require(r['fde_pointer_encoding']=='0x1b (pcrel signed-4-byte)','declared FDE encoding')
    global native,sites
    sites=read_json(packet/'delegate-field-sites.json');native={}
    bodies={};decoded={};counts={};negative=[]
    expected_counts={'delegate':449,'caller-wrapper':99,'object-constructor':79,'post-object':47}
    for r in evidence['regions']:
        label=r['label'];require(label in expected_counts,'unexpected region')
        range_binding(r,data)
        raw,off=at_va(int(r['start_va'],16),r['bytes'],executable=True)
        require(off==int(r['file_offset'],16) and hashlib.sha256(raw).hexdigest()==r['body_sha256'],'excerpt identity')
        rows=[];address=int(r['start_va'],16)
        for line in (packet/'native'/(label+'.stdout')).read_text().splitlines():
            if not re.match(r'^\s*[0-9a-f]+:',line):continue
            parts=line.split('\t');require(len(parts)>=3,'native row syntax')
            va=int(parts[0].strip().rstrip(':'),16);tokens=parts[1].split()
            require(tokens and all(re.fullmatch('[0-9a-f]{2}',x) for x in tokens),'native row byte syntax')
            code=bytes.fromhex(' '.join(tokens));text=' '.join(parts[2:]).strip()
            require(va==address and raw[va-int(r['start_va'],16):va-int(r['start_va'],16)+len(code)]==code,'native byte coverage')
            require(text and '(bad)' not in text and not text.startswith('.byte'),'undecoded native row')
            rows.append({'va':hex(va),'bytes':code.hex(),'text':text});address+=len(code)
        require(address==int(r['end_va'],16) and len(rows)==expected_counts[label],'native extent/count')
        bodies[label]=raw;decoded[label]=rows;counts[label]=len(rows)
        if label=='delegate':native={int(row['va'],16):row for row in rows}
        changed=bytearray(data);changed[int(r['fde_file_offset'],16)+12]^=1
        try:range_binding(r,changed)
        except ValueError as error:negative.append({'control':'FDE extent: '+label,'rejection':str(error)})
        else:raise ValueError('FDE extent corruption escaped')
    require(set(bodies)==set(expected_counts),'region inventory')
    for edge in evidence['incoming_edges']:
        va=int(edge['site_va'],16);code,_=at_va(va,5,executable=True)
        require(code.hex()==edge['bytes'] and code[0]==0xe8 and va+5+struct.unpack_from('<i',code,1)[0]==int(edge['destination_va'],16),'incoming edge')
    validate(bodies['delegate'])
    for name,(va,expected) in sites.items():
        require(native[va]['bytes']==expected,'delegate native field site')
        changed=bytearray(bodies['delegate']);changed[va-START+len(bytes.fromhex(expected))-1]^=1
        try:validate(changed)
        except ValueError as error:negative.append({'control':'delegate field: '+name,'rejection':str(error)})
        else:raise ValueError('delegate field corruption escaped')
    message,_=at_va(0x26393a,61,readonly=True)
    observed=inspect(bodies['object-constructor'],bodies['post-object'],message)
    for name,region,va,xor in read_json(packet/'helper-mutations.json'):
        c=bytearray(bodies['object-constructor']);p=bytearray(bodies['post-object']);m=bytearray(message)
        if region=='constructor':c[va-constructor_start]^=xor
        elif region=='post-object':p[va-post_start]^=xor
        else:m[va]^=xor
        try:inspect(c,p,m)
        except ValueError as error:negative.append({'control':'helper field: '+name,'rejection':str(error)})
        else:raise ValueError('helper field corruption escaped')
    # Bind selected relocation records retained by the two analyses as raw ELF data.
    relocation_records=[]
    for filename in ['delegate-links.json','helper-observations.json']:
        item=read_json(packet/filename)
        for records in item['selected_relocations'].values():
            for row in records:
                off=int(row['record_file_offset'],16)
                require(data[off:off+24].hex()==row['record_bytes'],'relocation record drift')
                relocation_records.append(row['record_bytes'])
    result={'status':'COMPLETE_INPUT_STATIC_BINDINGS_REPRODUCED','target_sha256':TARGET_SHA,
        'region_count':4,'region_bytes':sum(len(x) for x in bodies.values()),'recorded_native_instructions':sum(counts.values()),
        'instruction_counts':counts,'unwind_index_rows_checked':n,'selected_relocation_records_bound':len(set(relocation_records)),
        'corruptions_rejected':len(negative),'controls':negative,'helper_observations':observed,
        'python':sys.version.split()[0],'fresh_native_decoder_run':False,'target_executed':False,'repository_imports':False,
        'limits':'Full-input authentication of retained static exports/fields and 71 evidence-binding controls; not fresh native decoding, complete schemas, runtime parser tests, helper/exception closure or whole-node equivalence.'}
    require(result['region_bytes']==3060 and result['recorded_native_instructions']==674 and len(negative)==71,'validated denominator drift')
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
