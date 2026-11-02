#!/usr/bin/env python3
"""Owned hosted-only validation controller. Captured images are data only."""
import errno
import hashlib
import importlib.metadata
import importlib.util
import json
import os
import re
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import urllib.request

PAYLOAD=Path(__file__).resolve().parent
PACKET='research/work-items/RE-001-json-rpc-result-dispatch-94'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n')
def require(ok,message):
    if not ok:raise RuntimeError(message)
def payload_hashes():return {p.relative_to(PAYLOAD).as_posix():sha(p.read_bytes()) for p in PAYLOAD.rglob('*') if p.is_file()}
def input_hashes(source,manifest):
    result={}
    for name,expected in manifest['source_code_hashes'].items():
        raw=(source/name).read_bytes();require(sha(raw)==expected,'source code drift: '+name);result[name]=expected
    for row in manifest['artifacts']:
        path=source/row['path'];require(path.stat().st_size==row['size'] and sha(path.read_bytes())==row['sha256'],'artifact identity: '+row['path'])
        result[row['path']]=row['sha256']
    for name,expected in manifest['packet_files'].items():
        require(sha((source/PACKET/name).read_bytes())==expected,'packet drift: '+name);result[PACKET+'/'+name]=expected
    return result
def git(source,*args):
    result=subprocess.run(['/usr/bin/git','-c','safe.directory=*','-C',str(source),*args],capture_output=True,text=True,timeout=120)
    require(result.returncode==0,'Git metadata check failed: '+str(args));return result.stdout.strip()
def prepare(root,acquired):
    manifest=json.loads((PAYLOAD/'SOURCE_MANIFEST.json').read_text())
    require(payload_hashes()==dict(manifest['payload_hashes'],**{'SOURCE_MANIFEST.json':sha((PAYLOAD/'SOURCE_MANIFEST.json').read_bytes())}),'payload inventory/hash')
    tool=manifest['ripgrep']
    archive=root/'ripgrep.tar.gz'
    require(sha(archive.read_bytes())==tool['archive_sha256'],'ripgrep archive identity')
    with tarfile.open(archive,'r:gz') as package:
        member=package.getmember(tool['member'])
        require(member.isfile() and member.size==tool['binary_bytes'],'ripgrep member shape')
        binary=package.extractfile(member).read()
    require(sha(binary)==tool['binary_sha256'],'ripgrep executable identity')
    (root/'tools').mkdir()
    (root/'tools/rg').write_bytes(binary);(root/'tools/rg').chmod(0o755)
    source=root/'source';shutil.move(str(acquired),source)
    require(git(source,'rev-parse','HEAD')==manifest['source_commit'],'source commit')
    git(source,'config','--local','core.worktree',str(source))
    git(source,'config','--local','core.hooksPath','/dev/null')
    safe=[str(source)]
    for row in manifest['source_repositories']:
        path=source/row['path'];safe.append(str(path))
        git(path,'config','--local','core.worktree',str(path))
        git(path,'config','--local','core.hooksPath','/dev/null')
        require(git(path,'rev-parse','HEAD')==row['commit'],'pinned reference changed')
    # The verified setup defect was local filter configuration; do not run setup.sh.
    reference=source/'references/can1357-hl'
    for key,value in [('filter.lfs.process','git-lfs filter-process'),('filter.lfs.clean','git-lfs clean -- %f'),
                      ('filter.lfs.smudge','git-lfs smudge -- %f'),('filter.lfs.required','true')]:
        git(reference,'config','--local',key,value)
    git(reference,'lfs','pull')
    # The diagnostic proved that Git LFS clean-filter scratch must be writable.
    # Keep each clone's source/metadata read-only during analysis; cache elsewhere.
    (root/'lfs-cache').mkdir()
    for ordinal,row in enumerate(manifest['source_repositories'],1):
        cache=root/'lfs-cache'/str(ordinal);cache.mkdir();cache.chmod(0o777)
        git(source/row['path'],'config','--local','lfs.storage',str(cache))
    require(not (source/PACKET).exists(),'packet collides with selected source')
    shutil.copytree(PAYLOAD/'packet',source/PACKET)
    require(len(list((source/'tests').glob('test*.py')))==manifest['test_files'],'test inventory changed')
    inputs=input_hashes(source,manifest);save(root/'prepared-inputs.json',inputs)
    (source/'work').mkdir(exist_ok=True)
    for name in ['output','tmp','home','work','bin']:(root/name).mkdir(exist_ok=True)
    # No compiler/runtime emulator is exposed to repository code.
    names=['git','git-lfs','gpg','rg','objdump','readelf','make','sh','bash','env','uname','dirname','basename',
           'mkdir','rmdir','rm','cp','mv','ln','chmod','cat','head','tail','grep','sed','tr','cut','wc','sort','find',
           'sleep','touch','date','printf','true','false','which','mktemp','readlink','stat','tee','timeout','expr']
    for name in names:
        executable=str(root/'tools/rg') if name=='rg' else shutil.which(name,path='/usr/bin:/bin')
        if executable:(root/'bin'/name).symlink_to(executable)
    # Expose an existing static LLVM reader only; never install a compiler/toolchain.
    llvm_candidates=[shutil.which('llvm-objdump',path='/usr/bin:/bin')]
    llvm_candidates += ['/usr/bin/llvm-objdump-'+v for v in ['18','17','16']]
    llvm_candidates += ['/usr/lib/llvm-'+v+'/bin/llvm-objdump' for v in ['18','17','16']]
    llvm=next((Path(p).resolve() for p in llvm_candidates if p and Path(p).is_file()),None)
    require(llvm is not None,'required existing static LLVM decoder absent; no package installed')
    (root/'bin/llvm-objdump').symlink_to(llvm)
    save(root/'llvm-reader.json',{'path':str(llvm),'sha256':sha(llvm.read_bytes()),'installed_by_workload':False})
    for name in ['python','python3']:(root/'bin'/name).symlink_to(root/'venv/bin/python')
    for name in ['git','git-lfs','gpg','rg','objdump','readelf','make']:
        require((root/'bin'/name).exists(),'required tool missing: '+name)
    config=root/'safe-git-config';config.write_text('[core]\n\thooksPath = /dev/null\n[safe]\n'+''.join('\tdirectory = '+path+'\n' for path in safe))
    save(root/'preparation.json',{'source_commit':manifest['source_commit'],'input_files_checked':len(inputs),
         'test_files':manifest['test_files'],'packet_files':len(manifest['packet_files']),
         'capture_execution':False,'compiler_install':False,'source_setup_script_run':False})
    for name in ['output','tmp','home','work']:(root/name).chmod(0o777)
    config.chmod(0o644)

def readonly(path):
    canary=path/'.owned-write-canary'
    try:canary.write_text('must fail')
    except OSError as error:require(error.errno==errno.EROFS,'read-only write refused for wrong reason')
    else:canary.unlink();raise RuntimeError('read-only write unexpectedly succeeded')
def analyze(root,parent_namespace):
    source=root/'source';output=root/'output';manifest=json.loads((PAYLOAD/'SOURCE_MANIFEST.json').read_text())
    pre={'phase':'before_repository_execution','repository_commands_started':0,'parent_network_namespace':parent_namespace}
    save(output/'isolation-preflight.json',pre)
    status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    caps={k:status[k].strip() for k in ['CapInh','CapPrm','CapEff','CapBnd','CapAmb']}
    interfaces=sorted(line.split(':')[0].strip() for line in Path('/proc/self/net/dev').read_text().splitlines()[2:] if ':' in line)
    namespace=os.readlink('/proc/self/ns/net')
    pre.update(uid=os.getuid(),gid=os.getgid(),groups=os.getgroups(),capabilities=caps,no_new_privileges=status['NoNewPrivs'].strip(),
               current_network_namespace=namespace,interfaces=interfaces,python=sys.version,
               capstone_version=importlib.metadata.version('capstone'),unicorn_available=importlib.util.find_spec('unicorn') is not None,
               compiler_paths={name:shutil.which(name) for name in ['cargo','rustc','rustup','cc','gcc','clang']},
               captured_emulation_flags={k:v for k,v in os.environ.items() if k.startswith('HL_') and ('EMU' in k or 'ALLOW' in k)})
    save(output/'isolation-preflight.json',pre)
    require(os.getuid()==os.getgid()==65534 and not os.getgroups() and not any(int(v,16) for v in caps.values()),'uid/groups/capabilities')
    require(pre['no_new_privileges']=='1' and namespace!=parent_namespace and interfaces==['lo'],'network/privilege isolation')
    require(sys.version.startswith('3.12.3 ') and pre['capstone_version']=='5.0.7' and not pre['unicorn_available'],'Python/decoder environment')
    require(not any(pre['compiler_paths'].values()) and not pre['captured_emulation_flags'],'compiler or emulation capability exposed')
    readonly(PAYLOAD);readonly(source);readonly(root/'bin');readonly(root/'tools')
    require(sha((root/'tools/rg').read_bytes())==manifest['ripgrep']['binary_sha256'],'qualified ripgrep identity')
    pre['ripgrep_binary_sha256']=manifest['ripgrep']['binary_sha256']
    cache_records=[]
    for ordinal,row in enumerate(manifest['source_repositories'],1):
        cache=root/'lfs-cache'/str(ordinal)
        actual=subprocess.run(['git','-C',str(source/row['path']),'config','--get','lfs.storage'],capture_output=True,text=True,timeout=15)
        require(actual.returncode==0 and actual.stdout.strip()==str(cache),'private LFS cache config')
        canary=cache/'.owned-cache-canary';canary.write_text('writable scratch only');canary.unlink()
        cache_records.append({'reference':row['path'],'cache':str(cache),'writable':True,'outside_source':not cache.is_relative_to(source)})
    pre['reference_lfs_caches']=cache_records
    llvm_record=json.loads((root/'llvm-reader.json').read_text())
    require(sha(Path(llvm_record['path']).read_bytes())==llvm_record['sha256'],'LLVM reader changed')
    version=subprocess.run(['llvm-objdump','--version'],capture_output=True,text=True,timeout=15)
    require(version.returncode==0,'existing LLVM reader unusable')
    pre['llvm_objdump']=dict(llvm_record,version=version.stdout.strip())
    before=input_hashes(source,manifest);require(before==json.loads((root/'prepared-inputs.json').read_text()),'prepared inputs changed')
    pre['read_only_canaries_EROFS']=True;save(output/'qualification.json',pre)
    commands=[
      ('packet-full-input',[sys.executable,'-I','-B',PACKET+'/verify_packet.py','--binary','artifacts/node/94/hl-node'],180),
      ('doctor',['make','PYTHON='+sys.executable,'doctor'],120),
      ('verify',['make','PYTHON='+sys.executable,'verify'],240),
      ('catalogue-check',['make','PYTHON='+sys.executable,'catalogue-check'],240),
      ('reproduce',['make','PYTHON='+sys.executable,'reproduce'],360),
      ('test',['make','PYTHON='+sys.executable,'test'],9000),
    ]
    results=[]
    analysis_deadline=time.monotonic()+9600
    for label,argv,limit in commands:
        start=time.monotonic();timed_out=False
        effective_limit=min(limit,max(0,analysis_deadline-start))
        require(effective_limit>0,'analysis budget exhausted before command')
        with (output/(label+'.stdout')).open('wb') as stdout,(output/(label+'.stderr')).open('wb') as stderr:
            child=subprocess.Popen(argv,cwd=source,stdout=stdout,stderr=stderr,start_new_session=True)
            last_heartbeat=start
            while True:
                now=time.monotonic()
                remaining=effective_limit-(now-start)
                if remaining<=0:
                    if child.poll() is None:
                        timed_out=True
                        try:os.killpg(child.pid,signal.SIGKILL)
                        except ProcessLookupError:pass
                    break
                try:
                    child.wait(timeout=min(5,remaining));break
                except subprocess.TimeoutExpired:pass
                now=time.monotonic()
                if label=='test' and now-last_heartbeat>=30:
                    log=output/'test.stderr'
                    with log.open('rb') as current:
                        current.seek(max(0,log.stat().st_size-262144));tail=current.read().decode(errors='replace')
                    markers=re.findall(r'^\[(\d+)/(\d+)\] (test[^\n]+\.py)\s*$',tail,re.M)
                    print(json.dumps({'phase':'test_progress','elapsed_seconds':round(now-start,1),'latest_file':markers[-1] if markers else None}),flush=True)
                    last_heartbeat=now
            code=child.wait()
        row={'label':label,'argv':argv,'timeout_seconds':limit,'effective_timeout_seconds':effective_limit,'exit_code':code,'timed_out':timed_out,'seconds':round(time.monotonic()-start,3)}
        results.append(row);save(output/'progress.json',{'commands':results});print(json.dumps(row),flush=True)
        if timed_out or code!=0:break
    after=input_hashes(source,manifest);require(before==after,'source/artifact/packet inputs changed')
    require(sha((root/'tools/rg').read_bytes())==manifest['ripgrep']['binary_sha256'],'ripgrep changed')
    save(output/'result.json',{'status':'VALIDATION_COMMANDS_OBSERVED','source_commit':manifest['source_commit'],
        'commands':results,'all_commands_passed':len(results)==6 and all(r['exit_code']==0 for r in results),
        'inputs_unchanged':True,'test_inventory':manifest['test_files'],'private_lfs_caches':cache_records,'fail_fast':True,'analysis_deadline_seconds':9600,'captured_program_execution':False,
        'emulator_installed':False,'compiler_on_analysis_PATH':False,'native_decoding_package':'capstone==5.0.7',
        'limits':'Observed command results only. Full make test may skip unavailable optional capabilities. No Rust build, fresh original native decode, captured execution, schema equivalence, progress gate or scoring result is implied.'})
    if len(results)!=6 or any(r['exit_code'] for r in results):raise SystemExit(1)

if __name__=='__main__':
    if len(sys.argv)==4 and sys.argv[1]=='prepare':prepare(Path(sys.argv[2]),Path(sys.argv[3]))
    elif len(sys.argv)==4 and sys.argv[1]=='analyze':analyze(Path(sys.argv[2]),sys.argv[3])
    else:raise SystemExit('Unexpected owned-controller arguments')
