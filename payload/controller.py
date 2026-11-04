"""Owned hosted controller. Repository execution begins only in analyze."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import time

PAYLOAD = Path(__file__).resolve().parent
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


def check_tree(tree, plan, commit):
    assert git(tree, "rev-parse", "HEAD") == commit
    assert git(tree, "rev-parse", "HEAD^{tree}") == plan["candidate_tree"]
    assert git(tree, "write-tree") == plan["candidate_tree"]
    assert not git(tree, "status", "--porcelain", "--untracked-files=no")
    for relative, pin in REFS.items():
        assert git(tree / relative, "rev-parse", "HEAD") == pin


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


def prepare(root, shard, acquired, plan, job):
    assert sys.version.startswith("3.12.3 ")
    assert sha(PAYLOAD / "candidate.patch") == plan["patch_sha256"]
    source = root / "source"
    shutil.move(acquired, source)
    assert git(source, "rev-parse", "HEAD") == plan["base_commit"]
    assert git(source, "rev-parse", "HEAD^{tree}") == plan["base_tree"]
    for work in (source, *(source / name for name in REFS)):
        git(work, "config", "--local", "core.worktree", str(work))
        git(work, "config", "--local", "core.hooksPath", "/dev/null")
    assert not git(source, "status", "--porcelain", "--untracked-files=no")
    assert len(REFS) == 6 and all(git(source / p, "rev-parse", "HEAD") == sha for p, sha in REFS.items())
    manifest = artifact_hashes(source)
    for name in manifest:
        assert not stat.S_IMODE((source / name).stat().st_mode) & 0o111
    git(source, "apply", "--index", "--whitespace=error-all", str(PAYLOAD / "candidate.patch"))
    assert git(source, "write-tree") == plan["candidate_tree"]
    commit_env = dict(os.environ, GIT_AUTHOR_NAME="clutchpbcfo", GIT_COMMITTER_NAME="clutchpbcfo",
                      GIT_AUTHOR_EMAIL="205850674+clutchpbcfo@users.noreply.github.com",
                      GIT_COMMITTER_EMAIL="205850674+clutchpbcfo@users.noreply.github.com",
                      GIT_AUTHOR_DATE="2026-11-04T04:54:00Z", GIT_COMMITTER_DATE="2026-11-04T04:54:00Z")
    commit = git(source, "-c", "commit.gpgsign=false", "commit-tree", plan["candidate_tree"],
                 "-p", plan["base_commit"], "-m",
                 "RE-001: trace node115 failure paths to Rust runtime endpoints [skip ci]", env=commit_env)
    git(source, "update-ref", "HEAD", commit, plan["base_commit"])
    check_tree(source, plan, commit)
    hashes(source, read(PAYLOAD / "DRAFT_STATUS.json")["changed_content_hashes"])
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
    for name in ("output", "tmp", "home"):
        (root / name).mkdir(exist_ok=True)
        (root / name).chmod(0o777)
    size = int(subprocess.check_output(["/usr/bin/du", "-sb", str(source)], text=True).split()[0])
    assert shutil.disk_usage(root).free > size * (5 if shard == "long" else 4) + 1_000_000_000
    for worker in job["workers"]:
        copy_source(root, source, "worker-" + str(worker["worker"]))
    if shard == "long":
        copy_source(root, source, "checks")
    save(root / "output/prepared.json", {
        "shard": shard, "commit": commit, "tree": plan["candidate_tree"], "base": plan["base_commit"],
        "refs": REFS, "artifacts": manifest, "patch_sha256": plan["patch_sha256"],
    })


def module_inventory(tree, plan, runner, expected_styles):
    files = runner.test_files(tree / "tests")
    assert len(files) == 583
    assert {p.name for p in files} == set(plan["test_module_git_blobs"])
    for path in files:
        raw = path.read_bytes()
        digest = hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()
        assert digest == plan["test_module_git_blobs"][path.name]
        command = runner.test_command([sys.executable], tree / "tests", path)
        style = command[2] if command[1] == "-m" else "script"
        assert style == expected_styles["tests/" + path.name]


def import_runner(source, plan):
    path = source / "tools/run_tests.py"
    raw = path.read_bytes()
    assert hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest() == plan["repository_test_runner_git_blob"]
    spec = importlib.util.spec_from_file_location("upstream_test_dispatch", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


def summarize_log(path):
    tail_size = 32768
    with path.open("rb") as log:
        log.seek(max(0, path.stat().st_size - tail_size))
        return log.read().decode(errors="replace")[-3500:]


def analyze(root, shard, parent_namespace, plan, job):
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    current_ns = os.readlink("/proc/self/ns/net")
    interfaces = sorted(l.split(":", 1)[0].strip() for l in Path("/proc/self/net/dev").read_text().splitlines()[2:] if ":" in l)
    caps = {key: status[key].strip() for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")}
    assert os.getuid() == os.getgid() == 65534 and os.getgroups() == []
    assert all(int(v, 16) == 0 for v in caps.values()) and status["NoNewPrivs"].strip() == "1"
    assert current_ns != parent_namespace and interfaces == ["lo"]
    assert all(shutil.which(name) is None for name in ("cargo", "rustc", "rustup", "cc", "gcc", "clang", "qemu-x86_64"))
    output = root / "output"
    source = root / "source"
    pre = read(output / "prepared.json")
    save(output / "qualification.json", {"uid": os.getuid(), "gid": os.getgid(), "groups": [],
         "caps": caps, "no_new_privs": 1, "parent_namespace": parent_namespace,
         "current_namespace": current_ns, "interfaces": interfaces,
         "parallel_workers": 4, "tool_paths": {n: shutil.which(n) for n in ("make", "llvm-objdump", "objdump", "gpg")},
         "source_tree_sealed_readonly": bool(os.statvfs(source).f_flag & os.ST_RDONLY)})
    assert os.statvfs(source).f_flag & os.ST_RDONLY
    runner = import_runner(source, plan)
    expected_styles = read(PAYLOAD / "SPLIT_INPUT_CHECK.json")["test_dispatch"]
    module_inventory(source, plan, runner, expected_styles)
    prep_end = time.monotonic()
    budget = 555 if shard == "short" else 1080
    deadline = prep_end + budget
    changed = read(PAYLOAD / "DRAFT_STATUS.json")["changed_content_hashes"]

    def worker(job_row):
        number = job_row["worker"]
        box = root / ("worker-" + str(number))
        tree = box / "tree"
        assert os.statvfs(tree / "artifacts").f_flag & os.ST_RDONLY
        assert not any(os.access(tree / name, os.X_OK) for name in pre["artifacts"])
        env = dict(os.environ, HOME=str(box / "home"), TMPDIR=str(box / "tmp"))
        rows = []
        for module in job_row["modules"]:
            command = runner.test_command([sys.executable], tree / "tests", tree / "tests" / module)
            log = box / "logs" / (module + ".log")
            result = run_command(command, tree, log, env, deadline - time.monotonic())
            row = dict(result, module=module, argv=command)
            if log.exists():
                row["tail"] = summarize_log(log)
            rows.append(row)
            save(output / f"worker-{number}.json", rows)
            if result["timed_out"]:
                break
        check_tree(tree, plan, pre["commit"])
        hashes(tree, changed)
        hashes(tree, pre["artifacts"])
        assert not any(os.access(tree / name, os.X_OK) for name in pre["artifacts"])
        return rows

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = [row for batch in pool.map(worker, job["workers"]) for row in batch]
    wanted = [name for entry in job["workers"] for name in entry["modules"]]
    okay = len(results) == len(wanted) and [r["module"] for r in results] == wanted
    okay = okay and all(r["exit_code"] == 0 and not r["timed_out"] for r in results)
    checks = {}
    if shard == "long" and okay:
        box = root / "checks"
        env = dict(os.environ, HOME=str(box / "home"), TMPDIR=str(box / "tmp"))
        for label in ("doctor", "verify", "catalogue-check", "reproduce", "packet"):
            argv = (["make", "PYTHON=" + sys.executable, label] if label != "packet" else
                    [sys.executable, "-I", "-B", PACKET + "/verify_packet.py",
                     "--binary", "artifacts/node/115/hl-node"])
            row = run_command(argv, box / "tree", output / (label + ".log"), env, 105)
            checks[label] = dict(row, argv=argv)
            save(output / "checks.json", checks)
            if row["exit_code"] != 0 or row["timed_out"]:
                okay = False
                break
        check_tree(box / "tree", plan, pre["commit"])
        hashes(box / "tree", changed)
        hashes(box / "tree", pre["artifacts"])
    save(output / "result.json", {
        "shard": shard, "candidate_commit": pre["commit"], "candidate_tree": pre["tree"],
        "modules_completed": len(results), "expected_modules": len(wanted),
        "coverage_matches_assignment": len(results) == len(wanted) and [r["module"] for r in results] == wanted,
        "all_passed": okay, "checks": checks, "tests_executed_by_upstream_dispatch": True,
        "test_cap_seconds": budget, "sealed_source_unchanged": True,
        "no_compiler_or_emulator_installed": True,
    })
    if not okay:
        raise SystemExit(1)


if __name__ == "__main__":
    mode, root_arg, shard, *args = sys.argv[1:]
    root = Path(root_arg)
    plan = read(PAYLOAD / "SPLIT_PLAN.json")
    job = next(row for row in plan["jobs"] if row["name"] == shard)
    try:
        if mode == "prepare":
            prepare(root, shard, Path(args[0]), plan, job)
        elif mode == "analyze":
            analyze(root, shard, args[0], plan, job)
        else:
            raise ValueError(mode)
    except Exception as error:
        save(root / "output/controller-error.json",
             {"phase": mode, "type": type(error).__name__, "detail": str(error)[:800]})
        raise
