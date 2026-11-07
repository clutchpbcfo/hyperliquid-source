"""Run a declared subset using the project's unchanged per-file test dispatch."""
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
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--shard", required=True, choices=("0", "1"))
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    plan = json.loads(args.manifest.read_text())
    selected = plan["shards"][args.shard]
    assert len(selected) == 526 and len(set(selected)) == 526
    assert set(plan["shards"]["0"]).isdisjoint(plan["shards"]["1"])
    assert set(plan["shards"]["0"]) | set(plan["shards"]["1"]) == set(plan["test_blobs"])
    spec = importlib.util.spec_from_file_location("project_test_runner", root / "tools/run_tests.py")
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    files = {path.name: path for path in runner.test_files(root / "tests")}
    assert set(files) == set(plan["test_blobs"]) and len(files) == 1052
    for name, path in files.items():
        raw = path.read_bytes()
        assert hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest() == plan["test_blobs"][name]
    python = [sys.executable, *subprocess._args_from_interpreter_flags()]
    results = []
    for ordinal, name in enumerate(selected, 1):
        command = runner.test_command(python, root / "tests", files[name])
        print(f"\n[{ordinal}/{len(selected)}] {name}", flush=True)
        started = time.monotonic()
        completed = subprocess.run(command, cwd=root)
        results.append({"module": name, "blob": plan["test_blobs"][name], "exit_code": completed.returncode, "seconds": round(time.monotonic() - started, 3)})
        args.out.write_text(json.dumps({"shard": args.shard, "results": results,
                                       "complete": len(results) == len(selected)}, indent=2) + "\n")
    failed = [row["module"] for row in results if row["exit_code"]]
    print(f"Shard {args.shard}: {len(results)} modules attempted, {len(failed)} failed.", flush=True)
    return bool(failed)


if __name__ == "__main__":
    raise SystemExit(main())
