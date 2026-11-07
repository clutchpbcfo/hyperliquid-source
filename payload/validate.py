"""Hosted-only BLST addendum integration validation."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tarfile
import time

PAYLOAD = Path(__file__).resolve().parent
BASE = "7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6"
BASE_TREE = "2334d5ee6ab20a0ccd5e81f64dd85c4a733fbc31"
PATCH_SHA = "5662905f93bdfa780a00acc1a62f9a1ef99742a313d4eeb0410835a1bb8d57f2"
PACKET = "research/work-items/RE-002-node115-cfa-frame-policy/blst-portable"

REFS = {
    "upstream/block-importer": "703f10ed0d49193161a53be7e34086c2117858e8",
    "upstream/contracts": "d7e66aa751ffbd19bfd2b90fd5d9a3d8f32d99ee",
    "upstream/historical_data": "984357d36a46c95d1426f042e30a3adf2f48e388",
    "upstream/hyper-evm-sync": "d0945c699d9d4774417f4355b10744e7cd420df8",
    "upstream/node": "405cc08b17a727ee51b0f9128918955a84439915",
    "upstream/order_book_server": "8b4f237904f683aca2dba21a07d87e831ead2a97",
}

TOOLS = ("git git-lfs gpg make sh bash env objdump readelf nm objcopy strings "
         "uname dirname basename mkdir rmdir rm cp mv ln chmod cat head tail grep "
         "sed tr cut wc sort find sleep touch date printf true false which mktemp "
         "readlink realpath stat tee timeout expr awk dd file cmp diff comm gzip "
         "tar xz unzip sha256sum xargs od cpp as").split()

def sha(path):
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()

def read(path):
    return json.loads(path.read_text())

def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")

def git(tree, *args, env=None):
    return subprocess.check_output(
        ["/usr/bin/git", "-c", f"safe.directory={tree}", "-c", "core.hooksPath=/dev/null",
         "-C", str(tree), *args], env=env, text=True, timeout=45
    ).strip()

def hashes(tree, expected):
    for relative, oid in expected.items():
        path = tree / relative
        assert path.is_file() and not path.is_symlink(), relative
        assert sha(path) == oid, relative

def artifact_hashes(tree):
    items = read(tree / "provenance/artifacts.json")["files"]
    data = {row["path"]: row["sha256"] for row in items}
    assert data["artifacts/node/115/hl-node"] == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
    assert data["artifacts/visor/captured/hl-visor"] == "89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31"
    assert all((tree / row["path"]).stat().st_size == row["size"] for row in items)
    hashes(tree, data)
    return data

def copy_source(root, source, name):
    box = root / name
    box.mkdir()
    tree = box / "tree"
    subprocess.run(["/bin/cp", "-a", "--reflink=auto", str(source), str(tree)], check=True, timeout=40)
    for work in (tree, *(tree / name for name in REFS)):
        gitdir = Path(git(work, "rev-parse", "--absolute-git-dir")).resolve()
        assert gitdir.is_relative_to((tree / ".git").resolve())
        git(work, "config", "--local", "core.worktree", str(work))
        git(work, "config", "--local", "core.hooksPath", "/dev/null")
    for name in ("home", "tmp", "logs"):
        (box / name).mkdir()
    subprocess.run(["/usr/bin/sudo", "/bin/chown", "-R", "--no-dereference", "65534:65534", str(box)],
                   check=True, timeout=40)
    return tree

def run_command(argv, tree, log, env, budget):
    if budget <= 0:
        return {"exit_code": None, "timed_out": True, "seconds": 0}
    start = time.monotonic()
    timed_out = False
    with log.open("wb") as stream:
        proc = subprocess.Popen(argv, cwd=tree, stdout=stream, stderr=subprocess.STDOUT,
                                env=env, start_new_session=True)
        try:
            proc.wait(timeout=budget)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
    return {"exit_code": proc.returncode, "timed_out": timed_out,
            "seconds": round(time.monotonic() - start, 3), "log_sha256": sha(log)}


def prepare(root, acquired):
    assert sys.version.startswith("3.12.3 ")
    assert sha(PAYLOAD / "candidate.patch") == PATCH_SHA
    source = root / "source"
    shutil.move(acquired, source)
    assert git(source, "rev-parse", "HEAD") == BASE
    assert git(source, "rev-parse", "HEAD^{tree}") == BASE_TREE
    for work in (source, *(source / name for name in REFS)):
        git(work, "config", "--local", "core.worktree", str(work))
        git(work, "config", "--local", "core.hooksPath", "/dev/null")
    assert not git(source, "status", "--porcelain", "--untracked-files=no")
    assert all(git(source / p, "rev-parse", "HEAD") == oid for p, oid in REFS.items())
    manifest = artifact_hashes(source)
    assert all(not (source / name).stat().st_mode & 0o111 for name in manifest)
    (root / "output").chmod(0o777)
    (root / "bin").mkdir()
    (root / "tools").mkdir()
    with tarfile.open(root / "ripgrep.tar.gz") as tar:
        member = tar.getmember("ripgrep-14.1.1-x86_64-unknown-linux-musl/rg")
        assert member.isfile() and member.size < 10_000_000
        rg = root / "tools/rg"
        rg.write_bytes(tar.extractfile(member).read())
        rg.chmod(0o755)
    for name in TOOLS:
        path = shutil.which(name, path="/usr/bin:/bin")
        if path:
            (root / "bin" / name).symlink_to(path)
    for name in ("python3", "python"):
        (root / "bin" / name).symlink_to(sys.executable)
    (root / "bin/rg").symlink_to(rg)
    llvm = next((p for name in ("llvm-objdump", "llvm-objdump-18", "llvm-objdump-17")
                 if (p := shutil.which(name, path="/usr/bin:/bin"))), None)
    assert llvm
    (root / "bin/llvm-objdump").symlink_to(llvm)
    assert shutil.disk_usage(root).free > 1_000_000_000
    copy_source(root, source, "work")
    save(root / "output/prepared.json", {"base": BASE, "base_tree": BASE_TREE,
         "artifacts": manifest, "reference_pins": REFS, "patch_sha256": PATCH_SHA})


def analyze(root, parent_namespace, shard):
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    namespace = os.readlink("/proc/self/ns/net")
    interfaces = [l.split(":", 1)[0].strip() for l in Path("/proc/self/net/dev").read_text().splitlines()[2:] if ":" in l]
    capabilities = {name: status[name].strip() for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")}
    assert os.getuid() == os.getgid() == 65534 and os.getgroups() == []
    assert all(int(v, 16) == 0 for v in capabilities.values()) and status["NoNewPrivs"].strip() == "1"
    assert namespace != parent_namespace and interfaces == ["lo"]
    assert all(shutil.which(name) is None for name in ("rustc", "cargo", "cc", "gcc", "clang", "qemu-x86_64"))
    out = root / "output"
    source = root / "source"
    tree = root / "work/tree"
    assert all(os.statvfs(p).f_flag & os.ST_RDONLY for p in (source, tree / "artifacts", tree / "upstream"))
    prepared = read(out / "prepared.json")
    hashes(tree, prepared["artifacts"])
    assert all(not os.access(tree / name, os.X_OK) for name in prepared["artifacts"])
    save(out / "qualification.json", {"uid": os.getuid(), "gid": os.getgid(), "groups": [],
         "capabilities": capabilities, "no_new_privs": 1, "parent_namespace": parent_namespace,
         "network_namespace": namespace, "interfaces": interfaces,
         "source_readonly": True, "captures_readonly_and_nonexecutable": True})
    assert git(tree, "write-tree") == BASE_TREE
    assert not git(tree, "status", "--porcelain", "--untracked-files=no")
    assert shard in ("0", "1")
    expected = read(PAYLOAD / "CANDIDATE.json")
    changed = expected["changed_files"]
    assert len(changed) == 31
    patch = str(PAYLOAD / "candidate.patch")
    git(tree, "apply", "--check", "--whitespace=nowarn", patch)
    git(tree, "apply", "--whitespace=nowarn", patch)
    git(tree, "add", "--", *sorted(changed))
    candidate_tree = git(tree, "write-tree")
    assert candidate_tree == expected["tree"]
    assert set(git(tree, "diff", "--cached", "--name-only").splitlines()) == set(changed)
    git(tree, "diff", "--cached", "--check")
    hashes(tree, changed)

    commit_env = dict(os.environ, GIT_AUTHOR_NAME="clutchpbcfo", GIT_COMMITTER_NAME="clutchpbcfo",
                      GIT_AUTHOR_EMAIL="205850674+clutchpbcfo@users.noreply.github.com",
                      GIT_COMMITTER_EMAIL="205850674+clutchpbcfo@users.noreply.github.com",
                      GIT_AUTHOR_DATE=expected["commit_date"], GIT_COMMITTER_DATE=expected["commit_date"])
    commit = git(tree, "-c", "commit.gpgsign=false", "commit-tree", candidate_tree,
                 "-p", BASE, "-m", expected["commit_message"], env=commit_env)
    assert commit == expected["commit"]
    git(tree, "update-ref", "HEAD", commit, BASE)
    assert git(tree, "rev-parse", "HEAD^{tree}") == candidate_tree
    assert not git(tree, "status", "--porcelain", "--untracked-files=no")
    modules = list((tree / "tests").glob("test*.py"))
    test_map = read(PAYLOAD / "SUITE.json")["test_blobs"]
    assert len(modules) == len(test_map) == 1052
    assert {p.name for p in modules} == set(test_map)
    for path in modules:
        raw = path.read_bytes()
        assert hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest() == test_map[path.name]

    save(out / "candidate-identity.json", {"base": BASE, "base_tree": BASE_TREE,
         "candidate_commit": commit, "candidate_tree": candidate_tree,
         "patch_sha256": PATCH_SHA, "changed_files": changed, "test_files": len(modules),
         "shard": shard, "suite_manifest_sha256": sha(PAYLOAD / "SUITE.json"),
         "runner_blob": hashlib.sha1(f"blob {(tree / 'tools/run_tests.py').stat().st_size}\0".encode()
                                     + (tree / "tools/run_tests.py").read_bytes()).hexdigest()})
    checks = {}
    deadline = time.monotonic() + 13800

    def execute(label, argv, cap):
        entry = run_command(argv, tree, out / (label + ".log"), os.environ,
                            min(cap, deadline - time.monotonic()))
        checks[label] = dict(entry, argv=argv)
        save(out / "commands.json", checks)
        print(json.dumps({"command": label, **entry}), flush=True)
        return entry["exit_code"] == 0 and not entry["timed_out"]

    make = ["make", "PYTHON=" + sys.executable]
    commands = [
        ("doctor", make + ["doctor"], 120),
        ("verify", make + ["verify"], 180),
        ("catalogue-check", make + ["catalogue-check"], 120),
        ("suite", [sys.executable, "-B", str(PAYLOAD / "suite_shard.py"), "--root", str(tree),
                   "--manifest", str(PAYLOAD / "SUITE.json"), "--shard", shard,
                   "--out", str(out / "shard-results.json")], 13500),
        ("catalogue-after-test", make + ["catalogue-check"], 120),
    ]
    passed = True
    for label, argv, cap in commands:
        if not execute(label, argv, cap):
            passed = False
            break
    assert git(tree, "rev-parse", "HEAD") == commit
    assert git(tree, "write-tree") == candidate_tree
    assert not git(tree, "status", "--porcelain", "--untracked-files=no")
    assert git(source, "rev-parse", "HEAD^{tree}") == BASE_TREE
    hashes(tree, changed)
    hashes(tree, prepared["artifacts"])
    assert all(not os.access(tree / p, os.X_OK) for p in prepared["artifacts"])
    assert all(git(tree / name, "rev-parse", "HEAD") == oid for name, oid in REFS.items())
    save(out / "result.json", {"base": BASE, "candidate_commit": commit, "candidate_tree": candidate_tree,
         "all_required_commands_passed": passed, "commands": checks, "known_test_modules": len(modules), "test_modules_executed": len(read(out / "shard-results.json")["results"]) if (out / "shard-results.json").exists() else 0, "shard": shard,
         "source_tree_readonly": True, "tracked_candidate_unchanged": True,
         "capture_digests_and_modes_unchanged": True, "serial_make_test": False})
    if not passed:
        raise SystemExit(1)

if __name__ == "__main__":
    mode, location, argument, *extra = sys.argv[1:]
    root = Path(location)
    try:
        if mode == "prepare":
            assert not extra
            prepare(root, Path(argument))
        else:
            assert mode == "analyze" and len(extra) == 1
            analyze(root, argument, extra[0])
    except Exception as error:
        save(root / "output/controller-error.json",
             {"phase": mode, "type": type(error).__name__, "detail": str(error)[:800]})
        raise
