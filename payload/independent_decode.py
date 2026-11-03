"""Owned hosted-only second-provider replay. No repository imports."""
import argparse,hashlib,json,sys
from pathlib import Path
import capstone
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--binary',type=Path,required=True);parser.add_argument('--packet',type=Path,required=True)
    args=parser.parse_args();data=args.binary.read_bytes()
    assert len(data)==105896032 and hashlib.sha256(data).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
    assert capstone.__version__=='5.0.7'
    evidence=json.loads((args.packet/'evidence.json').read_text())
    sources={'constructor-candidate':'receipts/decode-result.json','delegate-candidate':'receipts/decode-result.json',
        'completion-candidate':'completion/receipts/decode-result.json','variant-candidate':'first-variant/receipts/decode-result.json',
        'value-candidate':'value-helper/receipts/decode-result.json','text-candidate':'text-decoder/receipts/decode-result.json','sequence-candidate':'sequence-helper/receipts/decode-result.json'}
    decoder=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);output=[]
    # Read file offsets from target-authenticated retained FDE records. The
    # standard-library packet verifier separately reconstructs every mapping.
    mappings={}
    for path in ['receipts/full-input-replay.json','completion/receipts/full-input-replay.json',
                 'first-variant/receipts/full-input-replay.json','value-helper/receipts/full-input-replay.json','text-decoder/receipts/full-input-replay.json','sequence-helper/receipts/full-input-replay.json']:
        record=json.loads((args.packet/path).read_text())
        assert record['target_sha256']==evidence['target_sha256']
        for entry in record.get('encoded_lea_candidates',[])+record.get('encoded_direct_call_candidates',[]):mappings[entry['fde']['start_va']]=entry['fde']
        for entry in record.get('selected_fde_candidates',{}).values():mappings[entry['start_va']]=entry
    spans=[]
    for region in evidence['regions']:
        start,end=int(region['start_va'],16),int(region['end_va'],16);record=mappings[region['start_va']]
        offset=int(record['file_offset'],16);body=data[offset:offset+end-start]
        assert len(body)==region['bytes'] and hashlib.sha256(body).hexdigest()==region['body_sha256']==record['body_sha256']
        old=json.loads((args.packet/sources[region['label']]).read_text())
        gnu=next(r for r in old['regions'] if r['label']==region['label'])
        rows=list(decoder.disasm_lite(body,start))
        assert sum(r[1] for r in rows)==len(body) and len(rows)==region['instructions']
        assert [(r[0],r[1]) for r in rows]==[(int(r['va'],16),len(bytes.fromhex(r['bytes']))) for r in gnu['instruction_rows']]
        assert all(body[address-start:address-start+size].hex()==saved['bytes'] for (address,size,_,_),saved in zip(rows,gnu['instruction_rows']))
        spans.append((start,end));output.append(dict(label=region['label'],start=hex(start),end=hex(end),bytes=len(body),rows=len(rows),all_bytes_and_boundaries_match=True))
    spans.sort();assert all(a[1]<=b[0] for a,b in zip(spans,spans[1:]))
    assert len(output)==7 and sum(r['bytes'] for r in output)==5066 and sum(r['rows'] for r in output)==1191
    print(json.dumps(dict(status='INDEPENDENT_CAPSTONE_REPLAY_PASSED',provider='capstone',version=capstone.__version__,python=sys.version.split()[0],
        regions=output,unique_ranges=7,unique_bytes=5066,unique_rows=1191,repository_imports=False,captured_execution_or_emulation=False,
        limits='Independent static byte/boundary replay only; no helper/schema/type/ABI/exception closure or runtime equivalence.'),indent=2))
if __name__=='__main__':main()
