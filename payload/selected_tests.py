"""Hosted-only: run a declared diagnostic subset with the unchanged project dispatch."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    plan = json.loads(args.manifest.read_text())
    root = args.root.resolve()
    raw = (root / 'tools/run_tests.py').read_bytes()
    assert hashlib.sha1(f'blob {len(raw)}\0'.encode() + raw).hexdigest() == plan['runner_blob']
    spec = importlib.util.spec_from_file_location('project_test_dispatch', root / 'tools/run_tests.py')
    dispatch = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dispatch)
    files = {p.name: p for p in dispatch.test_files(root / 'tests')}
    assert len(files) == 1130 and set(files) == set(plan['test_blobs'])
    assert len(plan['selected']) == len(set(plan['selected'])) == 16
    for name, path in files.items():
        raw = path.read_bytes()
        assert hashlib.sha1(f'blob {len(raw)}\0'.encode() + raw).hexdigest() == plan['test_blobs'][name]
    python = [sys.executable, *subprocess._args_from_interpreter_flags()]
    results = []
    for ordinal, name in enumerate(plan['selected'], 1):
        print(f'\n[{ordinal}/16] {name}', flush=True)
        started = time.monotonic()
        completed = subprocess.run(dispatch.test_command(python, root / 'tests', files[name]), cwd=root)
        results.append({'module': name, 'blob': plan['test_blobs'][name], 'exit_code': completed.returncode,
                        'seconds': round(time.monotonic() - started, 3)})
        args.out.write_text(json.dumps({'complete': len(results) == 16, 'results': results}, indent=2) + '\n')
    return int(any(row['exit_code'] for row in results))


if __name__ == '__main__':
    raise SystemExit(main())
