"""Hosted-only generator and focused verification controller."""
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
BASE = "05bc2de303c05525b71e7e257426e741bc66a390"
BASE_TREE = "8ebaa903bb38e89dabeb402a83d7bd6770b3ff67"
ADDENDUM_PATCH = "e6561c5e3be9e68000c9c5632e4b83d556c7687e3955d54d114bcdc50553b742"
GENERATED = ("README.md", "docs/assets/research-progress.svg")
PACKET = "research/work-items/RE-001-node115-jsonrpc-result-dispatch"

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
         "tar xz unzip sha256sum xargs").split()

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
    assert sha(PAYLOAD / "addendum.patch") == ADDENDUM_PATCH
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
         "artifacts": manifest, "reference_pins": REFS, "addendum_sha256": ADDENDUM_PATCH})


def analyze(root, parent_namespace):
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
    commands = {}
    deadline = time.monotonic() + 530

    def execute(label, *argv, expected=0):
        entry = run_command(argv, tree, out / (label + ".log"), os.environ,
                            min(150, deadline - time.monotonic()))
        commands[label] = dict(entry, argv=argv)
        save(out / "commands.json", commands)
        assert entry["exit_code"] == expected and not entry["timed_out"], label

    def make(label, target, expected=0):
        execute(label, "make", "PYTHON=" + sys.executable, target, expected=expected)

    make("before-catalogue-check", "catalogue-check", expected=2)
    assert "Stale catalogue: README.md; run make catalogue" in (out / "before-catalogue-check.log").read_text()
    make("regenerate-catalogue", "catalogue")
    touched = git(tree, "diff", "--name-only").splitlines()
    assert set(touched) == set(GENERATED), touched
    changed = {}
    for name, old, new in (
        (GENERATED[0], b"559 #115 research work items.", b"560 #115 research work items."),
        (GENERATED[1], b">559</text>", b">560</text>"),
    ):
        raw = (source / name).read_bytes()
        assert raw.count(old) == 1 and (tree / name).read_bytes() == raw.replace(old, new)
        changed[name] = sha(tree / name)
    git(tree, "diff", "--check")
    diff = subprocess.check_output(["git", "-C", str(tree), "diff", "--binary", "--", *GENERATED])
    (out / "catalogue-repair.patch").write_bytes(diff)
    git(tree, "add", "--", *GENERATED)
    corrected_tree = git(tree, "write-tree")
    make("repaired-catalogue-check", "catalogue-check")

    git(tree, "apply", "--index", "--whitespace=error-all", str(PAYLOAD / "addendum.patch"))
    status = read(PAYLOAD / "DRAFT_STATUS.json")
    changed.update({name: record["sha256"] for name, record in status["changed_paths"].items()})
    assert set(git(tree, "diff", "--cached", "--name-only").splitlines()) == set(changed)
    hashes(tree, changed)
    candidate_tree = git(tree, "write-tree")
    make("candidate-catalogue-check", "catalogue-check")
    make("doctor", "doctor")
    make("verify", "verify")
    make("reproduce", "reproduce")
    execute("packet", sys.executable, "-I", "-B", PACKET + "/verify_packet.py",
            "--binary", "artifacts/node/115/hl-node")
    assert git(tree, "write-tree") == candidate_tree
    assert not git(tree, "diff", "--name-only")
    assert git(source, "rev-parse", "HEAD^{tree}") == BASE_TREE
    hashes(tree, changed)
    hashes(tree, prepared["artifacts"])
    assert all(git(tree / name, "rev-parse", "HEAD") == oid for name, oid in REFS.items())
    result = {"base": BASE, "base_tree": BASE_TREE, "corrected_tree": corrected_tree,
              "combined_candidate_tree": candidate_tree, "catalogue_changed_files": list(GENERATED),
              "combined_changed_files": changed, "all_focused_checks_passed": True,
              "full_suite_run": False, "baseline_stale_catalogue_reproduced": True,
              "catalogue_patch_sha256": sha(out / "catalogue-repair.patch"), "commands": commands}
    save(out / "result.json", result)
    print(json.dumps({k: v for k, v in result.items() if k != "commands"}))


if __name__ == "__main__":
    mode, location, argument = sys.argv[1:]
    root = Path(location)
    try:
        if mode == "prepare":
            prepare(root, Path(argument))
        else:
            assert mode == "analyze"
            analyze(root, argument)
    except Exception as error:
        save(root / "output/controller-error.json",
             {"phase": mode, "type": type(error).__name__, "detail": str(error)[:800]})
        raise
