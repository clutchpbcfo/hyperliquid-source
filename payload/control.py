#!/usr/bin/env python3
"""Owned hosted-only validation controller. Captured images are data only."""
import errno
import hashlib
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
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
        executable=shutil.which(name,path='/usr/bin:/bin')
        if executable:(root/'bin'/name).symlink_to(executable)
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
    readonly(PAYLOAD);readonly(source);readonly(root/'bin')
    before=input_hashes(source,manifest);require(before==json.loads((root/'prepared-inputs.json').read_text()),'prepared inputs changed')
    pre['read_only_canaries_EROFS']=True;save(output/'qualification.json',pre)
    commands=[
      ('packet-full-input',[sys.executable,'-I','-B',PACKET+'/verify_packet.py','--binary','artifacts/node/94/hl-node'],180),
      ('doctor',['make','PYTHON='+sys.executable,'doctor'],120),
      ('verify',['make','PYTHON='+sys.executable,'verify'],240),
      ('catalogue-check',['make','PYTHON='+sys.executable,'catalogue-check'],240),
      ('reproduce',['make','PYTHON='+sys.executable,'reproduce'],360),
      ('test',['make','PYTHON='+sys.executable,'test'],1200),
    ]
    results=[]
    for label,argv,limit in commands:
        start=time.monotonic();timed_out=False
        with (output/(label+'.stdout')).open('wb') as stdout,(output/(label+'.stderr')).open('wb') as stderr:
            child=subprocess.Popen(argv,cwd=source,stdout=stdout,stderr=stderr,start_new_session=True)
            try:code=child.wait(timeout=limit)
            except subprocess.TimeoutExpired:
                timed_out=True;os.killpg(child.pid,signal.SIGKILL);code=child.wait()
        row={'label':label,'argv':argv,'timeout_seconds':limit,'exit_code':code,'timed_out':timed_out,'seconds':round(time.monotonic()-start,3)}
        results.append(row);save(output/'progress.json',{'commands':results});print(json.dumps(row),flush=True)
        if timed_out:break
    after=input_hashes(source,manifest);require(before==after,'source/artifact/packet inputs changed')
    save(output/'result.json',{'status':'VALIDATION_COMMANDS_OBSERVED','source_commit':manifest['source_commit'],
        'commands':results,'all_commands_passed':len(results)==6 and all(r['exit_code']==0 for r in results),
        'inputs_unchanged':True,'test_inventory':manifest['test_files'],'captured_program_execution':False,
        'emulator_installed':False,'compiler_on_analysis_PATH':False,'native_decoding_package':'capstone==5.0.7',
        'limits':'Observed command results only. Full make test may skip unavailable optional capabilities. No Rust build, fresh original native decode, captured execution, schema equivalence, progress gate or scoring result is implied.'})
    if len(results)!=6 or any(r['exit_code'] for r in results):raise SystemExit(1)

if __name__=='__main__':
    if len(sys.argv)==4 and sys.argv[1]=='prepare':prepare(Path(sys.argv[2]),Path(sys.argv[3]))
    elif len(sys.argv)==4 and sys.argv[1]=='analyze':analyze(Path(sys.argv[2]),sys.argv[3])
    else:raise SystemExit('Unexpected owned-controller arguments')
