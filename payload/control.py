#!/usr/bin/env python3
"""Owned hosted-only controller. Repository code runs only after qualification."""
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
import tarfile
import time

PAYLOAD=Path(__file__).resolve().parent
PACKET='research/work-items/RE-001-node115-jsonrpc-result-dispatch'


def require(ok,message):
    if not ok:raise RuntimeError(message)


def sha(raw):return hashlib.sha256(raw).hexdigest()
def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n')
def manifest():return json.loads((PAYLOAD/'SOURCE_MANIFEST.json').read_text())


def inputs(source,spec,overrides=None):
    expected=dict(spec['source_code_hashes'])
    expected.update(overrides or {})
    out={}
    for name,wanted in expected.items():
        got=sha((source/name).read_bytes());require(got==wanted,'source input mismatch: '+name);out[name]=got
    for row in spec['artifacts']:
        path=source/row['path'];require(path.stat().st_size==row['size'] and sha(path.read_bytes())==row['sha256'],'artifact mismatch: '+row['path']);out[row['path']]=row['sha256']
    for name,wanted in spec['packet_files'].items():
        require(sha((source/PACKET/name).read_bytes())==wanted,'packet input mismatch: '+name);out[PACKET+'/'+name]=wanted
    return out


def git(path,*args):
    result=subprocess.run(['/usr/bin/git','-c','safe.directory=*','-C',str(path),*args],capture_output=True,text=True,timeout=120)
    require(result.returncode==0,'Git preparation failed: '+str(args)+' '+result.stderr[:600])
    return result.stdout.strip()


def prepare(root,acquired):
    spec=manifest()
    actual={p.relative_to(PAYLOAD).as_posix():sha(p.read_bytes()) for p in PAYLOAD.rglob('*') if p.is_file() and p.name!='SOURCE_MANIFEST.json'}
    require(actual==spec['payload_hashes'],'payload inventory/hash')
    tool=spec['ripgrep'];archive=root/'ripgrep.tar.gz'
    require(sha(archive.read_bytes())==tool['archive_sha256'],'ripgrep archive')
    with tarfile.open(archive,'r:gz') as package:
        member=package.getmember(tool['member']);require(member.isfile() and member.size==tool['binary_bytes'],'ripgrep member')
        binary=package.extractfile(member).read()
    require(sha(binary)==tool['binary_sha256'],'ripgrep binary')
    (root/'tools').mkdir();(root/'tools/rg').write_bytes(binary);(root/'tools/rg').chmod(0o755)
    source=root/'source';shutil.move(str(acquired),source)
    require(git(source,'rev-parse','HEAD')==spec['acquisition_commit'],'acquisition commit')
    require((source/PACKET).is_dir(),'exact head packet missing')
    safe=[]
    for base in [source]:
        for path in [base,*[base/r['path'] for r in spec['source_repositories']]]:
            git(path,'config','--local','core.worktree',str(path));git(path,'config','--local','core.hooksPath','/dev/null');safe.append(str(path))
    for row in spec['source_repositories']:require(git(source/row['path'],'rev-parse','HEAD')==row['commit'],'reference pin')
    parent_spec=dict(spec,source_code_hashes=spec['parent_source_code_hashes'],packet_files={})
    inputs(source,parent_spec)
    shutil.copytree(PAYLOAD/'packet',source/PACKET,dirs_exist_ok=True)
    git(source,'add','--',PACKET)
    require(git(source,'write-tree')==spec['candidate_git_tree'],'prospective Git tree differs from published candidate object')
    raw_commit=(PAYLOAD/'CANDIDATE_COMMIT.txt').read_bytes()
    expected_oid=hashlib.sha1(b'commit '+str(len(raw_commit)).encode()+b'\0'+raw_commit).hexdigest()
    require(expected_oid==spec['source_commit'],'canonical commit payload identity')
    commit_result=subprocess.run(['/usr/bin/git','-c','safe.directory=*','-C',str(source),'hash-object','-t','commit','-w','--stdin'],
        input=raw_commit,capture_output=True,timeout=30)
    require(commit_result.returncode==0 and commit_result.stdout.decode().strip()==spec['source_commit'],'materialized exact Git commit')
    git(source,'update-ref','HEAD',spec['source_commit'],spec['acquisition_commit'])
    require(git(source,'rev-parse','HEAD')==spec['source_commit'],'candidate Git HEAD identity')
    save(root/'candidate-git-identity.json',dict(commit=spec['source_commit'],tree=spec['candidate_git_tree'],parent=spec['acquisition_commit'],
        canonical_git_commit_verified=True,staged_tree_verified=True,remote_branch_updated=False))
    base=root/'base-source';shutil.move(str(acquired.parent/'base-source'),base)
    require(git(base,'rev-parse','HEAD')==spec['base_commit'],'base commit')
    for path in [base,*[base/r['path'] for r in spec['source_repositories']]]:
        git(path,'config','--local','core.worktree',str(path));git(path,'config','--local','core.hooksPath','/dev/null');safe.append(str(path))
    for row in spec['source_repositories']:require(git(base/row['path'],'rev-parse','HEAD')==row['commit'],'base reference pin')
    base_spec=dict(spec,source_code_hashes=spec['base_source_code_hashes'],packet_files={},artifacts=spec['base_artifacts'])
    save(root/'base-sealed-inputs.json',inputs(base,base_spec))
    before=inputs(source,spec);save(root/'sealed-inputs.json',before)
    candidate=root/'candidate';shutil.copytree(source,candidate,symlinks=True)
    (root/'lfs-cache').mkdir()
    for ordinal,row in enumerate(spec['source_repositories'],1):
        path=candidate/row['path'];gitdir=Path(git(path,'rev-parse','--absolute-git-dir')).resolve()
        require(gitdir.is_relative_to((candidate/'.git').resolve()),'copied reference metadata points outside disposable copy')
        cache=root/'lfs-cache'/str(ordinal);cache.mkdir();cache.chmod(0o777)
        git(path,'config','--local','lfs.storage',str(cache))
    for path in [candidate,*[candidate/r['path'] for r in spec['source_repositories']]]:
        git(path,'config','--local','core.worktree',str(path));git(path,'config','--local','core.hooksPath','/dev/null');safe.append(str(path))
    for row in spec['artifacts']:(candidate/row['path']).chmod(0o644)
    require(inputs(candidate,spec)==before,'candidate copy drift')
    require(len(list((candidate/'tests').glob('test*.py')))==spec['test_files'],'test inventory')
    (candidate/'work').mkdir(exist_ok=True)
    for name in ['output','tmp','home','bin']:(root/name).mkdir(exist_ok=True)
    names=['git','git-lfs','gpg','rg','objdump','readelf','make','sh','bash','env','uname','dirname','basename','mkdir','rmdir','rm','cp','mv','ln','chmod','cat','head','tail','grep','sed','tr','cut','wc','sort','find','sleep','touch','date','printf','true','false','which','mktemp','readlink','stat','tee','timeout','expr']
    for name in names:
        executable=str(root/'tools/rg') if name=='rg' else shutil.which(name,path='/usr/bin:/bin')
        if executable:(root/'bin'/name).symlink_to(executable)
    llvm_options=[shutil.which('llvm-objdump',path='/usr/bin:/bin')]+['/usr/bin/llvm-objdump-'+v for v in ['18','17','16']]+['/usr/lib/llvm-'+v+'/bin/llvm-objdump' for v in ['18','17','16']]
    llvm=next((Path(p).resolve() for p in llvm_options if p and Path(p).is_file()),None)
    require(llvm is not None,'existing LLVM static reader missing; no install')
    (root/'bin/llvm-objdump').symlink_to(llvm);save(root/'llvm-reader.json',{'path':str(llvm),'sha256':sha(llvm.read_bytes()),'installed_by_workload':False})
    for name in ['python','python3']:(root/'bin'/name).symlink_to(root/'venv/bin/python')
    for name in ['git','git-lfs','gpg','rg','objdump','readelf','make']:require((root/'bin'/name).exists(),'missing tool: '+name)
    (root/'safe-git-config').write_text('[core]\n\thooksPath = /dev/null\n[safe]\n'+''.join('\tdirectory = '+p+'\n' for p in safe))
    for name in ['output','tmp','home']:(root/name).chmod(0o777)
    subprocess.run(['/usr/bin/sudo','/bin/chown','-R','--no-dereference','65534:65534',str(candidate)],check=True)
    shutil.copyfile(root/'candidate-git-identity.json',root/'output/candidate-git-identity.json')
    save(root/'preparation.json',{'source_commit':spec['source_commit'],'input_files_checked':len(before),'test_files':spec['test_files'],'packet_files':len(spec['packet_files']),
        'sealed_original_and_disposable_copy':True,'captured_execution':False,'compiler_install':False,'source_setup_script_run':False})


def readonly(path):
    test=path/'.owned-readonly-canary'
    try:test.write_text('must fail')
    except OSError as error:require(error.errno==errno.EROFS,'write rejected for wrong reason')
    else:test.unlink();raise RuntimeError('sealed input was writable')


def analyze(root,parent_namespace):
    spec=manifest();source=root/'source';candidate=root/'candidate';output=root/'output'
    pre={'phase':'before_repository_execution','repository_commands_started':0,'parent_network_namespace':parent_namespace}
    save(output/'isolation-preflight.json',pre)
    status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    caps={k:status[k].strip() for k in ['CapInh','CapPrm','CapEff','CapBnd','CapAmb']}
    interfaces=sorted(line.split(':')[0].strip() for line in Path('/proc/self/net/dev').read_text().splitlines()[2:] if ':' in line)
    namespace=os.readlink('/proc/self/ns/net')
    pre.update(uid=os.getuid(),gid=os.getgid(),groups=os.getgroups(),capabilities=caps,no_new_privileges=status['NoNewPrivs'].strip(),current_network_namespace=namespace,interfaces=interfaces,python=sys.version,
        capstone_version=importlib.metadata.version('capstone'),unicorn_available=importlib.util.find_spec('unicorn') is not None,
        compiler_paths={n:shutil.which(n) for n in ['cargo','rustc','rustup','cc','gcc','clang']},captured_emulation_flags={k:v for k,v in os.environ.items() if k.startswith('HL_') and ('EMU' in k or 'ALLOW' in k)})
    save(output/'isolation-preflight.json',pre)
    require(os.getuid()==os.getgid()==65534 and not os.getgroups() and not any(int(v,16) for v in caps.values()),'UID/group/capabilities')
    require(pre['no_new_privileges']=='1' and namespace!=parent_namespace and interfaces==['lo'],'network/privilege isolation')
    require(sys.version.startswith('3.12.3 ') and pre['capstone_version']=='5.0.7' and not pre['unicorn_available'],'Python/capstone/emulator')
    require(not any(pre['compiler_paths'].values()) and not pre['captured_emulation_flags'],'compiler/emulation capabilities')
    for path in [PAYLOAD,source,root/'bin',root/'tools']:readonly(path)
    test=candidate/'.owned-candidate-canary';test.write_text('disposable writable copy');test.unlink()
    require(inputs(source,spec)==json.loads((root/'sealed-inputs.json').read_text()),'sealed source drift')
    require(inputs(candidate,spec)==inputs(source,spec),'candidate input drift')
    for row in spec['artifacts']:require(not os.access(candidate/row['path'],os.X_OK),'data input executable mode')
    require(sha((root/'tools/rg').read_bytes())==spec['ripgrep']['binary_sha256'],'ripgrep identity')
    llvm=json.loads((root/'llvm-reader.json').read_text());require(sha(Path(llvm['path']).read_bytes())==llvm['sha256'],'LLVM identity')
    p=subprocess.run(['llvm-objdump','--version'],capture_output=True,text=True,timeout=15);require(p.returncode==0,'LLVM availability')
    caches=[]
    for ordinal,row in enumerate(spec['source_repositories'],1):
        cache=root/'lfs-cache'/str(ordinal);t=cache/'.owned-cache-canary';t.write_text('scratch');t.unlink();caches.append({'reference':row['path'],'cache':str(cache),'outside_candidate':not cache.is_relative_to(candidate),'writable':True})
    pre.update(sealed_original_read_only_EROFS=True,disposable_candidate_writable=True,temporary_marker_execution_allowed=True,
        candidate_and_temporary_directory_same_device=candidate.stat().st_dev==Path(os.environ['TMPDIR']).stat().st_dev,
        working_capture_executable_modes=False,llvm_objdump=dict(llvm,version=p.stdout.strip()),ripgrep_binary_sha256=spec['ripgrep']['binary_sha256'],reference_lfs_caches=caches)
    require(pre['candidate_and_temporary_directory_same_device'],'hard-link fixtures need shared filesystem')
    for name in ['objdump','readelf']:
        version=subprocess.run([name,'--version'],capture_output=True,text=True,timeout=15)
        require(version.returncode==0,'static reader version');pre[name+'_version']=version.stdout.splitlines()[0]
    save(output/'qualification.json',pre)
    results=[];deadline=time.monotonic()+1260
    def command(label,argv,limit,cwd=candidate):
        start=time.monotonic();effective=min(limit,max(0,deadline-start));require(effective>0,'validation budget exhausted')
        timed_out=False
        with (output/(label+'.stdout')).open('wb') as stdout,(output/(label+'.stderr')).open('wb') as stderr:
            child=subprocess.Popen(argv,cwd=cwd,stdout=stdout,stderr=stderr,start_new_session=True)
            try:child.wait(timeout=effective)
            except subprocess.TimeoutExpired:
                timed_out=True
                try:os.killpg(child.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                child.wait()
        row=dict(label=label,argv=argv,cwd=str(cwd),timeout_seconds=limit,effective_timeout_seconds=effective,
            exit_code=child.returncode,timed_out=timed_out,seconds=round(time.monotonic()-start,3))
        results.append(row);save(output/'progress.json',dict(commands=results));print(json.dumps(row),flush=True)
        return child.returncode==0 and not timed_out
    base=root/'base-source'
    base_spec=dict(spec,source_code_hashes=spec['base_source_code_hashes'],packet_files={},artifacts=spec['base_artifacts'])
    require(inputs(base,base_spec)==json.loads((root/'base-sealed-inputs.json').read_text()),'base input drift')
    readonly(base)
    checks=[('base-catalogue-check',['make','PYTHON='+sys.executable,'catalogue-check'],180,base),
        ('doctor',['make','PYTHON='+sys.executable,'doctor'],120,candidate),
        ('verify',['make','PYTHON='+sys.executable,'verify'],240,candidate),
        ('catalogue-check',['make','PYTHON='+sys.executable,'catalogue-check'],180,candidate),
        ('reproduce',['make','PYTHON='+sys.executable,'reproduce'],360,candidate),
        ('packet-full-input',[sys.executable,'-I','-B',PACKET+'/verify_packet.py','--binary','artifacts/node/115/hl-node'],180,candidate),
        ('independent-decode',[sys.executable,'-I','-B',str(PAYLOAD/'independent_decode.py'),'--binary',str(candidate/'artifacts/node/115/hl-node'),'--packet',str(source/PACKET)],180,candidate),
        ('test',['make','PYTHON='+sys.executable,'test'],1080,candidate),
        ('verify-after-test',['make','PYTHON='+sys.executable,'verify'],240,candidate),
        ('catalogue-after-test',['make','PYTHON='+sys.executable,'catalogue-check'],180,candidate)]
    okay=True
    for label,argv,limit,cwd in checks:
        if not command(label,argv,limit,cwd):okay=False;break
    require(inputs(source,spec)==json.loads((root/'sealed-inputs.json').read_text()),'sealed candidate commit inputs changed')
    require(inputs(base,base_spec)==json.loads((root/'base-sealed-inputs.json').read_text()),'sealed base inputs changed')
    require(inputs(candidate,spec)==inputs(source,spec),'disposable candidate inputs changed')
    for row in spec['artifacts']:require(not os.access(candidate/row['path'],os.X_OK),'capture became executable')
    packet_result=json.loads((output/'packet-full-input.stdout').read_text()) if any(r['label']=='packet-full-input' and r['exit_code']==0 for r in results) else None
    independent=json.loads((output/'independent-decode.stdout').read_text()) if any(r['label']=='independent-decode' and r['exit_code']==0 for r in results) else None
    final=dict(status='EXACT_CANDIDATE_VALIDATION_OBSERVED',source_commit=spec['source_commit'],candidate_git_tree=spec['candidate_git_tree'],
        acquisition_commit=spec['acquisition_commit'],base_commit=spec['base_commit'],commands=results,all_commands_passed=okay and len(results)==10,
        original_and_disposable_inputs_unchanged=True,post_run_capture_modes_checked=True,tracked_files_regenerated=False,
        packet_result=packet_result,independent_decode=independent,source_test_modules=76,packet_files=len(spec['packet_files']),
        captured_execution=False,compiler_or_emulator_installed=False,automatic_retry=False,
        limits='Actual static research and required repository checks on the exact prospective Git commit. Optional compiler/archive/platform skips remain explicit; no Rust build, complete value/schema/type/exception closure or runtime equivalence.')
    save(output/'result.json',final)
    if not final['all_commands_passed']:raise SystemExit(1)


if __name__=='__main__':
    if len(sys.argv)==4 and sys.argv[1]=='prepare':prepare(Path(sys.argv[2]),Path(sys.argv[3]))
    elif len(sys.argv)==4 and sys.argv[1]=='analyze':
        try:analyze(Path(sys.argv[2]),sys.argv[3])
        except Exception as error:
            save(Path(sys.argv[2])/'output/controller-error.json',dict(type=type(error).__name__,message=str(error),successful_end_to_end_audit=False))
            raise
    else:raise SystemExit('Unexpected owned-controller arguments')
