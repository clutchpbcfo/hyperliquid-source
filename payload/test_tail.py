"""Run the remaining files using the unchanged repository runner on hosted Linux."""
import argparse
import importlib.util
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--selection", required=True, type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    assert Path.cwd() == root
    selected = json.loads(args.selection.read_text())
    runner_path = root / "tools/run_tests.py"
    spec = importlib.util.spec_from_file_location("project_test_runner", runner_path)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)

    test_dir = root / "tests"
    files = runner.test_files(test_dir)
    expected = json.loads((args.selection.parent / "TESTS.json").read_text())
    assert [path.name for path in files] == sorted(expected)
    remaining = files[selected["prefix_completed"]:]
    assert {path.name: expected[path.name] for path in remaining} == selected["remaining_modules"]
    assert len(remaining) == 163

    def select_remaining(start):
        assert start.resolve() == test_dir
        return remaining

    runner.test_files = select_remaining
    return runner.run(test_dir)


if __name__ == "__main__":
    raise SystemExit(main())
