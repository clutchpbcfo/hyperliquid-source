"""Owned hosted-only bounded static exports; never execute the capture."""
import argparse,hashlib,json,re,subprocess
from pathlib import Path
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--binary',type=Path,required=True);parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args();raw=args.binary.read_bytes()
    assert len(raw)==105896032 and hashlib.sha256(raw).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
    args.out.mkdir(parents=True,exist_ok=False);commands=[]
    for provider,argv in [('gnu',['objdump','-d','-Mintel','--insn-width=15']),('llvm',['llvm-objdump','-d','--x86-asm-syntax=intel'])]:
        argv+=['--start-address=0x5b298d0','--stop-address=0x5b2a121',str(args.binary)]
        result=subprocess.run(argv,capture_output=True,text=True,timeout=90);assert result.returncode==0
        lines=[line for line in result.stdout.splitlines() if re.match(r'^\s*[0-9a-f]+:',line)]
        (args.out/('sampler.'+provider+'.stdout')).write_text('\n'.join(lines)+'\n')
        commands.append(dict(provider=provider,argv=argv,exit_code=result.returncode,raw_rows=len(lines)))
    result=subprocess.run(['readelf','--debug-dump=frames',str(args.binary)],capture_output=True,text=True,timeout=90);assert result.returncode==0
    selected=[chunk for chunk in result.stdout.split('\n\n') if re.search(r'FDE .*pc=0*5b298d0\.\.0*5b2a121\b',chunk)]
    assert len(selected)==1;(args.out/'sampler.readelf.stdout').write_text(selected[0]+'\n')
    print(json.dumps(dict(commands=commands,readelf_selected_fdes=1,captured_program_execution=False)))
if __name__=='__main__':main()
