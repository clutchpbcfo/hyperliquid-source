#!/usr/bin/env python3
"""Owned hosted-only static decoding controller; no captured-code execution."""
import csv
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import struct
import sys

PAYLOAD=Path(__file__).resolve().parent
def sha(raw):return hashlib.sha256(raw).hexdigest()
def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n')
def hashes(root):
    out={}
    for path in sorted(root.rglob('*')):
        if path.is_symlink():raise RuntimeError('linked input')
        if path.is_file():out[path.relative_to(root).as_posix()]=sha(path.read_bytes())
    return out
def readonly(root):
    path=root/'.owned-readonly-canary'
    try:path.write_text('must fail')
    except OSError as error:
        if error.errno!=errno.EROFS:raise RuntimeError('readonly control did not return EROFS') from error
    else:
        path.unlink();raise RuntimeError('readonly control unexpectedly wrote')
def prepare(fixtures,capture):
    fixtures.mkdir()
    windows=json.loads((PAYLOAD/'WINDOWS.json').read_text())
    complete=capture.read_bytes()
    if len(complete)!=windows['target_bytes'] or sha(complete)!=windows['target_sha256']:raise RuntimeError('complete target identity mismatch')
    (fixtures/'node115-full.bin').write_bytes(complete)
    for window in windows['regions']:
        raw=bytes.fromhex(window['body_hex'])
        if len(raw)!=window['bytes'] or sha(raw)!=window['body_sha256']:raise RuntimeError('excerpt input mismatch')
        (fixtures/(window['label']+'.bin')).write_bytes(raw)
    save(fixtures/'frozen-hashes.json',hashes(fixtures))
def analyze(fixtures,output,parent_namespace):
    output.mkdir(exist_ok=True)
    pre={'phase':'before_native_decoder','native_invocations_started':0,'parent_network_namespace':parent_namespace}
    save(output/'isolation-preflight.json',pre)
    try:
        status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
        caps={k:status[k].strip() for k in ['CapInh','CapPrm','CapEff','CapBnd','CapAmb']}
        dev=Path('/proc/self/net/dev').read_text()
        interfaces=sorted(line.partition(':')[0].strip() for line in dev.splitlines()[2:] if ':' in line)
        namespace=os.readlink('/proc/self/ns/net')
        pre.update(uid=os.getuid(),gid=os.getgid(),groups=os.getgroups(),capabilities=caps,
                   no_new_privileges=status['NoNewPrivs'].strip(),current_network_namespace=namespace,
                   proc_net_interfaces=interfaces,proc_net_dev=dev)
        save(output/'isolation-preflight.json',pre)
        if os.getuid()!=65534 or os.getgid()!=65534 or os.getgroups() or any(int(x,16) for x in caps.values()):raise RuntimeError('UID/group/capability qualification failed')
        if status['NoNewPrivs'].strip()!='1':raise RuntimeError('no-new-privileges qualification failed')
        def ns(value):return value.startswith('net:[') and value.endswith(']') and value[5:-1].isdigit()
        if not ns(parent_namespace) or not ns(namespace) or parent_namespace==namespace or interfaces!=['lo']:raise RuntimeError('network namespace qualification failed')
    except Exception as error:
        pre['qualification_error']=type(error).__name__+': '+str(error);save(output/'isolation-preflight.json',pre);raise
    readonly(PAYLOAD);readonly(fixtures)
    if not sys.version.startswith('3.12.3 '):raise RuntimeError('unexpected Python version')
    manifest=json.loads((PAYLOAD/'SOURCE_MANIFEST.json').read_text())
    if set(hashes(PAYLOAD))!=set(manifest['payload_files'])|{'SOURCE_MANIFEST.json'}:raise RuntimeError('payload inventory mismatch')
    for name,expected in manifest['payload_files'].items():
        if sha((PAYLOAD/name).read_bytes())!=expected:raise RuntimeError('payload hash mismatch')
    before=hashes(fixtures);frozen=json.loads((fixtures/'frozen-hashes.json').read_text())
    if {k:v for k,v in before.items() if k!='frozen-hashes.json'}!=frozen:raise RuntimeError('prepared excerpt changed')
    windows=json.loads((PAYLOAD/'WINDOWS.json').read_text())
    for row in windows['regions']:
        raw=(fixtures/(row['label']+'.bin')).read_bytes()
        if len(raw)!=row['bytes'] or sha(raw)!=row['body_sha256']:raise RuntimeError('staged excerpt mismatch')
    save(output/'qualification.json',dict(pre,payload_and_fixture_writes_rejected_EROFS=True,python=sys.version,
         captured_image_execution=False,third_party_python_packages_installed=False,
         native_program_sha256=sha(Path('/usr/bin/objdump').read_bytes())))
    complete=runpy.run_path(str(PAYLOAD/'remap_probe.py'))['probe']((fixtures/'node115-full.bin').read_bytes())
    if complete['selected_fde_candidates']!=windows['selected_fde_candidates']:raise RuntimeError('full-input FDE result drift')
    save(output/'full-input-replay.json',complete)
    observations=[]
    def command(label,argv):
        proc=subprocess.run(argv,cwd=output,capture_output=True,text=True,timeout=45)
        (output/(label+'.stdout')).write_text(proc.stdout);(output/(label+'.stderr')).write_text(proc.stderr)
        row={'label':label,'argv':argv,'exit_code':proc.returncode,'stdout':proc.stdout,'stderr':proc.stderr}
        observations.append(row);save(output/'progress.json',{'native_invocations':len(observations),'observations':observations})
        if proc.returncode or proc.stderr:raise RuntimeError('native command failed: '+label)
        return proc.stdout
    version=command('objdump-version',['/usr/bin/objdump','--version'])
    if not version.startswith('GNU objdump '):raise RuntimeError('GNU objdump is required')
    decoded=[]
    for window in windows['regions']:
        label=window['label'];binary=fixtures/(label+'.bin');raw=binary.read_bytes();start=int(window['start_va'],16)
        text=command(label,['/usr/bin/objdump','-D','-z','-b','binary','-m','i386:x86-64','-M','intel','--insn-width=16',
                            '--adjust-vma='+window['start_va'],str(binary)])
        expected=start;rows=[];branches=[]
        for line in text.splitlines():
            if not re.match(r'^\s*[0-9a-f]+:',line):continue
            parts=line.split('\t')
            if len(parts)<3:raise RuntimeError('unrecognized decoder row')
            address=int(parts[0].strip().rstrip(':'),16);tokens=parts[1].split()
            if not tokens or not all(re.fullmatch('[0-9a-f]{2}',x) for x in tokens):raise RuntimeError('unrecognized byte column')
            actual=bytes.fromhex(' '.join(tokens));mnemonic=' '.join(parts[2:]).strip()
            if address!=expected or raw[address-start:address-start+len(actual)]!=actual:raise RuntimeError('decoder byte coverage mismatch')
            if not mnemonic or '(bad)' in mnemonic or mnemonic.startswith('.byte'):raise RuntimeError('undecoded candidate bytes')
            row={'va':hex(address),'bytes':actual.hex(),'text':mnemonic};rows.append(row);expected+=len(actual)
            if re.match(r'(?:call|j\w+|loop\w*)\s',mnemonic):branches.append(row)
        if expected!=start+len(raw) or not rows:raise RuntimeError('incomplete decoder range')
        decoded.append({'label':label,'start_va':window['start_va'],'end_va':window['end_va'],
            'body_sha256':window['body_sha256'],'bytes':len(raw),'instructions':len(rows),'instruction_rows':rows,
            'control_transfer_rows_uninterpreted':branches,'all_bytes_contiguously_accounted':True})
    retained=windows['retained_dispatcher'];prior=retained['region'];fde=complete['selected_fde_candidates']['0x141e264']
    if fde!=retained['fde'] or prior['body_sha256']!=fde['body_sha256'] or prior['instructions']!=6:raise RuntimeError('retained dispatcher identity drift')
    whole=(fixtures/'node115-full.bin').read_bytes();start=int(fde['start_va'],16);off=int(fde['file_offset'],16);body=whole[off:off+fde['bytes']]
    cursor=start
    for row in prior['instruction_rows']:
        va=int(row['va'],16);raw=bytes.fromhex(row['bytes'])
        if va!=cursor or body[va-start:va-start+len(raw)]!=raw:raise RuntimeError('retained GNU boundary/full-image mismatch')
        cursor+=len(raw)
    if cursor!=int(fde['end_va'],16) or sha(body)!=fde['body_sha256']:raise RuntimeError('retained dispatcher complete coverage')
    replay=dict(prior_native_run=retained['prior_native_run'],prior_execution_commit=retained['prior_execution_commit'],prior_archive_sha256=retained['prior_archive_sha256'],
        region=prior,full_image_and_FDE_reauthenticated=True,all_prior_native_bytes_and_boundaries_replayed=True,fresh_GNU_dispatcher_decode=False)
    qualified=[]
    for kind in ['nonzero_call','zero_call']:
        candidate=windows['encoded_candidates'][kind]
        rows=[row for row in prior['instruction_rows'] if row['va']==candidate['candidate_va']]
        if len(rows)!=1 or rows[0]['bytes']!=candidate['bytes']:raise RuntimeError('retained call boundary mismatch')
        raw=bytes.fromhex(rows[0]['bytes']);site=int(candidate['candidate_va'],16);slot=site+6+struct.unpack_from('<i',raw,2)[0]
        rel_off=int(candidate['relocation_file_offset'],16);rel=whole[rel_off:rel_off+24]
        if raw[:2]!=b'\xff\x15' or hex(slot)!=candidate['slot_va'] or rel.hex()!=candidate['relocation_hex']:raise RuntimeError('indirect call/RIP/relocation mismatch')
        if struct.unpack('<QQq',rel)!=(slot,8,int(candidate['destination_va'],16)):raise RuntimeError('indirect static relocation target mismatch')
        if candidate['destination_va'] not in [r['start_va'] for r in decoded]:raise RuntimeError('callee is not a newly decoded range')
        qualified.append(dict(candidate,native_instruction_boundary_validated=True,native_boundary_source='retained GNU run41726809941 replayed against full capture',
            fresh_native_boundary_decode=False,full_capture_replay_checked=True,native_text=rows[0]['text']))
    save(output/'qualified-candidate-edges.json',qualified)
    if hashes(fixtures)!=before:raise RuntimeError('excerpt inputs changed')
    for name,expected in manifest['payload_files'].items():
        if sha((PAYLOAD/name).read_bytes())!=expected:raise RuntimeError('payload changed')
    save(output/'decode-result.json',{'status':'SELECTED_EXCERPTS_DECODED','target_sha256':windows['target_sha256'],
        'source_commit':manifest['source_commit'],'objdump_version':version.splitlines()[0],
        'native_invocations':3,'native_decode_invocations':2,'retained_dispatcher_replay':replay,'regions':decoded,'input_hashes_unchanged':True,
        'repository_source_executed':False,'captured_program_executed':False,'compiler_or_vm':False,
        'whole_elf_reauthenticated_in_job':True,'limit':'Complete-input FDE replay plus two new handler static decodes and previously qualified dispatcher boundary replay with RIP/RELATIVE binding. Does not establish complete helper semantics, complete CFG/call closure, accepted inputs, result types, reconstruction or milestone completion.'})
if __name__=='__main__':
    try:
        if len(sys.argv)==4 and sys.argv[1]=='prepare':prepare(Path(sys.argv[2]),Path(sys.argv[3]))
        elif len(sys.argv)==5 and sys.argv[1]=='analyze':analyze(Path(sys.argv[2]),Path(sys.argv[3]),sys.argv[4])
        else:raise RuntimeError('unexpected owned controller arguments')
    except Exception as error:
        print(type(error).__name__+': '+str(error),file=sys.stderr);raise
