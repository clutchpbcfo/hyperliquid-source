# Validation remaining before submission

Draft base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. Refresh it and ownership immediately before publication. The current Makefile routes required checks through `tools/doctor.py`, `tools/artifacts.py`, `tools/verify_imports.py`, `tools/run_tests.py`, `tools/catalogue.py` and `tools/reproduce.py`.

1. Review those actual scripts, their reachable modules/hooks, current manifests/locks and test inventory as data. Identify native builds, model calls, network access and captured-code execution before choosing a workload. Do not assume that a command called `test` is confined to static reading.
2. Prepare one isolated hosted Linux validation specification with an exact source/packet inventory, pinned public input acquisition and full hashes, networked acquisition separated from rootless offline checking, fixed commands, time/resource bounds, output receipts and no automatic retry. Preserve captured-program execution as prohibited.
3. Include the packet's full-input verifier and required `make doctor`, `make verify test catalogue-check`, and `make reproduce` checks where compatible with the authorized scope. A required check that needs a prohibited capability must be reported as a gap, not silently bypassed or counted green.
4. Freeze that concrete job before execution under the operator's authorization. The existing two native jobs are completed evidence and must not be rerun. No new job is launched by assembling this draft.
5. Verify observed artifact digests and all results. Attach exact commands, base/head, tool versions, actual failures/skips and limits to one focused PR. Generate honest attribution and record the Slop opened event after the PR exists. Do not infer the current served model/client version or inspect secrets/usage traces to manufacture them.

The local verifier has passed against the complete captured input. This does not qualify hosted full-input acquisition, normal repository CI, a Rust build, target execution or schema equivalence. No completion gate is requested.
