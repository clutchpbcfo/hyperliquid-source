#!/usr/bin/env python3
"""Owned hosted Git diagnostic. Repository source and captured images are data."""
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

PAYLOAD = Path(__file__).resolve().parent


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def inputs(source, manifest):
    result = {}
    for name, expected in manifest['source_code_hashes'].items():
        require(sha(source / name) == expected, 'source changed: ' + name)
        result[name] = expected
    for row in manifest['artifacts']:
        path = source / row['path']
        require(path.stat().st_size == row['size'] and sha(path) == row['sha256'], 'artifact identity: ' + row['path'])
        result[row['path']] = row['sha256']
    return result


def root_git(source, *args):
    child = subprocess.run(['/usr/bin/git', '-c', 'safe.directory=*', '-C', str(source), *args],
                           capture_output=True, text=True, timeout=60)
    require(child.returncode == 0, 'owned preparation Git metadata failed: ' + str(args))
    return child.stdout.strip()


def prepare(root, acquired):
    manifest = json.loads((PAYLOAD / 'SOURCE_MANIFEST.json').read_text())
    actual = {p.relative_to(PAYLOAD).as_posix(): sha(p) for p in PAYLOAD.rglob('*') if p.is_file()}
    require(actual == dict(manifest['payload_hashes'], **{'SOURCE_MANIFEST.json': sha(PAYLOAD / 'SOURCE_MANIFEST.json')}), 'payload identity')
    source = root / 'source'
    shutil.move(str(acquired), source)
    require(root_git(source, 'rev-parse', 'HEAD') == manifest['source_commit'], 'source commit')
    root_git(source, 'config', '--local', 'core.worktree', str(source))
    root_git(source, 'config', '--local', 'core.hooksPath', '/dev/null')
    refs = []
    safe = [str(source)]
    for row in manifest['source_repositories']:
        path = source / row['path']
        root_git(path, 'config', '--local', 'core.worktree', str(path))
        root_git(path, 'config', '--local', 'core.hooksPath', '/dev/null')
        require(root_git(path, 'rev-parse', 'HEAD') == row['commit'], 'source pin changed: ' + row['path'])
        refs.append(dict(row, gitdir=root_git(path, 'rev-parse', '--absolute-git-dir')))
        safe.append(str(path))
    # Match the failed run's reviewed setup; do not run the repository setup script.
    reference = source / 'references/can1357-hl'
    for key, value in [('filter.lfs.process', 'git-lfs filter-process'),
                       ('filter.lfs.clean', 'git-lfs clean -- %f'),
                       ('filter.lfs.smudge', 'git-lfs smudge -- %f'),
                       ('filter.lfs.required', 'true')]:
        root_git(reference, 'config', '--local', key, value)
    root_git(reference, 'lfs', 'pull')
    authenticated = inputs(source, manifest)
    save(root / 'prepared-inputs.json', authenticated)
    save(root / 'references.json', refs)
    for name in ['output', 'tmp', 'home', 'cache', 'bin']:
        (root / name).mkdir(exist_ok=True)
    for name in ['git', 'git-lfs', 'sh', 'bash', 'env', 'uname', 'dirname', 'basename',
                 'mkdir', 'rmdir', 'rm', 'cp', 'mv', 'ln', 'chmod', 'cat', 'head', 'tail', 'grep',
                 'sed', 'tr', 'cut', 'wc', 'sort', 'find', 'sleep', 'touch', 'date', 'printf',
                 'true', 'false', 'which', 'mktemp', 'readlink', 'stat', 'tee', 'timeout', 'expr']:
        executable = shutil.which(name, path='/usr/bin:/bin')
        if executable:
            (root / 'bin' / name).symlink_to(executable)
    require(all((root / 'bin' / name).exists() for name in ['git', 'git-lfs', 'sh']), 'required Git tools missing')
    (root / 'bin/python3').symlink_to(sys.executable)
    config = root / 'safe-git-config'
    config.write_text('[core]\n\thooksPath = /dev/null\n[safe]\n' + ''.join('\tdirectory = ' + path + '\n' for path in safe))
    config.chmod(0o644)
    for name in ['output', 'tmp', 'home', 'cache']:
        (root / name).chmod(0o777)
    save(root / 'output/preparation.json', {'source_commit': manifest['source_commit'],
         'source_code_files': len(manifest['source_code_hashes']), 'authenticated_input_files': len(authenticated),
         'source_pins': refs, 'source_setup_script_run': False, 'repository_modules_imported': False,
         'captured_execution': False, 'full_test_suite': False})


def readonly(path):
    canary = path / '.owned-readonly-canary'
    try:
        canary.write_text('must fail')
    except OSError as error:
        require(error.errno == errno.EROFS, 'readonly canary refused for wrong reason')
    else:
        canary.unlink()
        raise RuntimeError('readonly canary unexpectedly succeeded')


def modes(paths):
    rows = []
    for path in paths:
        try:
            value = path.stat()
            rows.append({'path': str(path), 'mode': oct(stat.S_IMODE(value.st_mode)),
                         'uid': value.st_uid, 'gid': value.st_gid, 'directory': stat.S_ISDIR(value.st_mode)})
        except OSError as error:
            rows.append({'path': str(path), 'errno': error.errno, 'error': error.strerror})
    return rows


def analyze(root, parent_namespace):
    output = root / 'output'
    source = root / 'source'
    manifest = json.loads((PAYLOAD / 'SOURCE_MANIFEST.json').read_text())
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    caps = {key: status[key].strip() for key in ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb']}
    interfaces = sorted(line.split(':')[0].strip() for line in Path('/proc/self/net/dev').read_text().splitlines()[2:] if ':' in line)
    qualification = {'phase': 'before_git_diagnostics', 'uid': os.getuid(), 'gid': os.getgid(), 'groups': os.getgroups(),
        'capabilities': caps, 'no_new_privileges': status['NoNewPrivs'].strip(),
        'parent_network_namespace': parent_namespace, 'current_network_namespace': os.readlink('/proc/self/ns/net'),
        'interfaces': interfaces, 'python': sys.version,
        'compiler_paths': {name: shutil.which(name) for name in ['cc', 'gcc', 'clang', 'rustc', 'cargo', 'rustup']},
        'captured_emulation_flags': {k: v for k, v in os.environ.items() if k.startswith('HL_')},
        'repository_modules_imported': False, 'repository_tests_started': 0}
    save(output / 'isolation-preflight.json', qualification)
    require(qualification['uid'] == qualification['gid'] == 65534 and not qualification['groups'], 'uid/groups')
    require(not any(int(value, 16) for value in caps.values()) and qualification['no_new_privileges'] == '1', 'capabilities/privilege')
    require(qualification['current_network_namespace'] != parent_namespace and interfaces == ['lo'], 'network namespace')
    require(sys.version.startswith('3.12.3 ') and not any(qualification['compiler_paths'].values()), 'analysis tools')
    require(not qualification['captured_emulation_flags'], 'captured opt-in flags')
    for name in ['frozen', 'source', 'bin']:
        readonly(root / name)
    qualification['read_only_canaries_EROFS'] = True
    save(output / 'qualification.json', qualification)
    before = inputs(source, manifest)
    require(before == json.loads((root / 'prepared-inputs.json').read_text()), 'prepared inputs changed')
    refs = json.loads((root / 'references.json').read_text())
    results = []
    deadline = time.monotonic() + 540

    def command(label, argv, env=None):
        remaining = deadline - time.monotonic()
        require(remaining > 1, 'diagnostic analysis deadline reached')
        limit = min(60, remaining)
        start = time.monotonic()
        timed_out = False
        stdout_path = output / (label + '.stdout')
        stderr_path = output / (label + '.stderr')
        with stdout_path.open('wb') as stdout, stderr_path.open('wb') as stderr:
            child = subprocess.Popen(argv, cwd=source, env=env, stdout=stdout, stderr=stderr, start_new_session=True)
            try:
                code = child.wait(timeout=limit)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(child.pid, signal.SIGKILL)
                code = child.wait()
        row = {'label': label, 'argv': argv, 'exit_code': code, 'timed_out': timed_out,
               'seconds': round(time.monotonic() - start, 3), 'timeout_seconds': limit,
               'stdout_bytes': stdout_path.stat().st_size, 'stderr_bytes': stderr_path.stat().st_size,
               'stdout_sha256': sha(stdout_path), 'stderr_sha256': sha(stderr_path)}
        results.append(row)
        save(output / 'progress.json', {'commands': results})
        print(json.dumps(row), flush=True)
        return row, stdout_path.read_bytes()

    for label, argv in [('git-version', ['git', '--version']), ('git-lfs-version', ['git-lfs', 'version'])]:
        row, _ = command(label, argv)
        require(row['exit_code'] == 0 and not row['timed_out'], 'tool version diagnostic failed')
    matrix = []
    for number, reference in enumerate(refs, 1):
        path = source / reference['path']
        gitdir = Path(reference['gitdir'])
        require(gitdir.is_relative_to(source), 'Git metadata escapes source')
        save(output / ('ref' + str(number) + '-modes.json'), modes([
            source, path, path / '.git', gitdir.parent, gitdir, gitdir / 'config', gitdir / 'index',
            gitdir / 'lfs', gitdir / 'lfs/tmp', gitdir / 'lfs/objects', gitdir / 'lfs/logs', root / 'safe-git-config']))
        prefix = 'ref' + str(number)
        head, raw = command(prefix + '-head', ['git', '-C', str(path), 'rev-parse', 'HEAD'])
        pinned = head['exit_code'] == 0 and raw.decode().strip() == reference['commit']
        item = {'path': reference['path'], 'expected_pin': reference['commit'], 'head_matches': pinned, 'modes_receipt': prefix + '-modes.json'}
        for variant in ['baseline', 'private-cache']:
            options = []
            if variant == 'private-cache':
                cache = root / 'cache' / str(number)
                cache.mkdir()
                options = ['-c', 'lfs.storage=' + str(cache)]
            git = ['git', '-C', str(path), *options]
            ordinary, _ = command(prefix + '-' + variant + '-status', [*git, 'status', '--porcelain', '--untracked-files=all'])
            with tempfile.TemporaryDirectory(prefix=prefix + '-' + variant + '-', dir=root / 'tmp') as temporary:
                env = dict(os.environ, GIT_INDEX_FILE=str(Path(temporary) / 'index'))
                strict = [*git, '-c', 'core.ignorestat=false', '-c', 'core.splitIndex=false']
                read, _ = command(prefix + '-' + variant + '-read-tree', [*strict, 'read-tree', '--no-sparse-checkout', 'HEAD'], env)
                fresh, _ = command(prefix + '-' + variant + '-fresh-status', [*strict, 'status', '--porcelain', '--untracked-files=all'], env)
            item[variant] = {'ordinary_status_exit': ordinary['exit_code'], 'ordinary_stdout_empty': ordinary['stdout_bytes'] == 0,
                'read_tree_exit': read['exit_code'], 'fresh_status_exit': fresh['exit_code'], 'fresh_stdout_empty': fresh['stdout_bytes'] == 0,
                'timed_out': any(row['timed_out'] for row in [ordinary, read, fresh]),
                'strict_clean': all(row['exit_code'] == 0 and not row['timed_out'] for row in [ordinary, read, fresh])
                                and ordinary['stdout_bytes'] == fresh['stdout_bytes'] == 0}
        matrix.append(item)
        save(output / 'matrix-progress.json', {'references': matrix})
    after = inputs(source, manifest)
    require(before == after, 'source/artifact inputs changed')
    outcome = {'status': 'DIAGNOSTICS_COMPLETED', 'source_commit': manifest['source_commit'], 'commands': results,
        'references': matrix, 'inputs_unchanged': True, 'source_pins_match': all(row['head_matches'] for row in matrix),
        'baseline_all_strict_clean': all(row['baseline']['strict_clean'] for row in matrix),
        'private_cache_all_strict_clean': all(row['private-cache']['strict_clean'] for row in matrix),
        'repository_modules_imported': False, 'repository_test_commands': 0, 'captured_execution': False,
        'compiler_install': False, 'automatic_retry': False,
        'limits': 'Only individual Git metadata operations are observed. No repository verify/test command, full-suite result, source change, PR, progress gate or score is implied.'}
    save(output / 'result.json', outcome)
    print(json.dumps({key: value for key, value in outcome.items() if key not in ['commands', 'references']}), flush=True)


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == 'prepare':
        prepare(Path(sys.argv[2]), Path(sys.argv[3]))
    elif len(sys.argv) == 4 and sys.argv[1] == 'analyze':
        analyze(Path(sys.argv[2]), sys.argv[3])
    else:
        raise SystemExit('prepare/analyze only')
