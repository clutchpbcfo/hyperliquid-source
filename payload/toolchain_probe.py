"""Hosted-only: identify an existing compiler without invoking rustup or installing."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def qualify(root):
    roots = [Path('/home/runner/.rustup/toolchains'), Path('/usr/share/rust/.rustup/toolchains')]
    candidates = sorted({p.resolve() for parent in roots if parent.is_dir() for p in parent.iterdir() if p.is_dir()})
    found = []
    for directory in candidates:
        if not any(directory.is_relative_to(parent.resolve()) for parent in roots if parent.is_dir()):
            continue
        paths = {name: directory / 'bin' / name for name in ('cargo', 'rustc', 'rustdoc')}
        if not all(p.is_file() and not p.is_symlink() for p in paths.values()):
            continue
        with paths['rustc'].open('rb') as stream:
            if stream.read(4) != b'\x7fELF':
                continue
        version = subprocess.check_output([str(paths['rustc']), '--version'], env={'PATH': '/usr/bin:/bin'}, text=True, timeout=10).strip()
        if not version.startswith('rustc 1.99.1 '):
            continue
        found.append((directory, paths, version))
    assert found, 'Preinstalled Rust 1.99.1 is absent; installation and fallback are forbidden'
    directory, paths, version = found[0]
    versions = {'rustc': version}
    for name in ('cargo', 'rustdoc'):
        versions[name] = subprocess.check_output([str(paths[name]), '--version'], env={'PATH': '/usr/bin:/bin'}, text=True, timeout=10).strip()
    assert versions['cargo'].startswith('cargo 1.99.1 ') and versions['rustdoc'].startswith('rustdoc 1.99.1 ')
    record = {'source': str(directory), 'versions': versions, 'installed': False, 'repo_rust_pin': '1.95.0',
              'pin_equivalent_build_claim': False, 'sha256': {}}
    for name, path in paths.items():
        with path.open('rb') as stream:
            record['sha256'][name] = hashlib.file_digest(stream, 'sha256').hexdigest()
    assert '\n' not in str(directory)
    (root / 'rust').mkdir()
    (root / 'rust-source.txt').write_text(str(directory) + '\n')
    (root / 'output/toolchain.json').write_text(json.dumps(record, indent=2) + '\n')
    for name in paths:
        (root / 'bin' / name).symlink_to(root / 'rust/bin' / name)
    return record


if __name__ == '__main__':
    qualify(Path(sys.argv[1]))
