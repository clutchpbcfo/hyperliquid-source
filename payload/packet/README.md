# RE-001: node #94 JsonRpcResult dispatch and object closure

This bounded static packet extends the accepted [JSON trailing-admission wrapper packet](https://github.com/lalalune/hyperliquid-source/tree/cec50f68e01c967d21538d48c49683ddeea52767/research/work-items/RE-001-json-trailing-admission-94). Its unresolved initial delegate contains an object-entry loop and calls a constructor whose captured diagnostic names **JsonRpcResult**. The constructor tries two alternative helpers. A separate helper consumes the closing brace before the caller's existing trailing-input check.

The result is a map of local operations and evidence boundaries, not a recovered complete JSON schema or a Rust implementation. Both alternative helpers' exact field requirements remain unresolved. No progress gate is requested.

## What is new

- Delegate **0x15c0d90**: local object/key/value delimiter path, state-byte guards, 64-byte append records and caller-visible 104-byte/sentinel store arms.
- Constructor **0x1619820**: ordered calls to **0x15a8ec0** and **0x15a89d0**, sentinel selection, read-only diagnostic naming JsonRpcResult, and a matching 104-byte ordinary copy.
- Closing helper **0x15b9ce0**: local whitespace scan, closing-brace cursor advance and explicit zero return on that arm, with distinct raw-code paths for exhaustion, comma and other bytes.

The accepted caller's 99 instructions and trailing-whitespace findings are supporting prior work, not a new discovery. [Delegate findings](delegate-observations.md) and [helper findings](helper-observations.md) give exact addresses, raw values, inferences and unknowns.

## Reproduce without executing a captured program

Use Python 3.12+ standard library only, an authenticated complete node #94 capture, and this packet. The verifier launches no subprocess, native tool, model, network request, repository module or captured function. It reads the full file as bytes, verifies its complete SHA256, then authenticates retained static exports, actual CIE/FDE fields, executable mappings, selected transfer/data/relocation bindings and deliberate evidence corruptions.

From the repository root:

```sh
python3 -I -B research/work-items/RE-001-json-rpc-result-dispatch-94/verify_packet.py \
  --binary artifacts/node/94/hl-node
```

An immutable public acquisition source is the node #94 recovery URL in `provenance/artifacts.json`:

`https://media.githubusercontent.com/media/can1357/hl/999556f6e0a474b8312db96ec3149e1c44e97c23/bin/hl-node-mainnet-new`

It is data input only. Expected size **91,774,280 bytes**; SHA256 **3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f**. A cached complete capture is sufficient for offline replay. An LFS pointer is rejected. The verifier does not fetch or run the binary.

Expected result: **4 regions, 3,060 bytes, 674 retained instruction rows, 71 rejected evidence corruptions**. The four instruction counts are caller 99, delegate 449, constructor 79 and closing helper 47. These are denominators for this declared evidence, not a function census, byte-equivalence rate or completion percentage. The controls comprise 48 delegate instruction bindings, 19 selected helper/data field controls and four FDE-extent mutations; they are not executed parser inputs.

## Actual validation and original native runs

[Local full-input replay](validation/local-full-input.json) passed with Python 3.14.7 using the owned standard-library data reader. It validates every retained instruction byte against the complete input, all 121,299 ordered unwind-header rows, selected actual FDE/CIE records, 12 unique retained relocation records, selected local predicates and all 71 corruption controls. No new native decoder or repository program ran in this replay.

The two original isolated Ubuntu 24.04 native runs passed on their first attempt:

- [Delegate and caller](https://github.com/clutchpbcfo/hyperliquid-source/actions/runs/41285258547), GNU objdump 2.42, 449 + 99 instructions.
- [Constructor and closing helper](https://github.com/clutchpbcfo/hyperliquid-source/actions/runs/41287064801), GNU objdump 2.42, 79 + 47 instructions.

Each run used exactly one version query and two static decodes. Options: `-D -z -b binary -m i386:x86-64 -M intel --insn-width=16 --adjust-vma=<linked-VA>`. Complete stdout exports are retained under `native/`. Before native decoding, receipts qualified UID/GID 65534, empty groups, zero capabilities, no-new-privileges, a distinct loopback-only network namespace, read-only/noexec payload/excerpts, EROFS controls and unchanged hashes. Each downloaded archive matched GitHub's SHA256 digest. See `qualification/` and [evidence.json](evidence.json).

Those original native jobs authenticated excerpts, not a separately acquired whole ELF. The separately approved [hosted validation](https://github.com/clutchpbcfo/hyperliquid-source/actions/runs/41371054867), at execution commit `5ce47c05b0ccc4b5bf1f9ca50cc25fa06f0fab17` against source `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`, now authenticates the complete input with Python 3.12.3. Its [full-input result](validation/hosted-full-input.json) matches the local replay except the Python version. `make doctor`, `make catalogue-check` and `make reproduce` passed. `make verify` passed artifact hashes and signatures, then failed to read a pinned reference through Git under the isolated runner. `make test` hit its 20-minute cap: 175 of 971 files completed with 2,779 reported tests, including 27 skips; file 176 had started. The completed prefix records no assertion failure, but the suite is incomplete. [Command results](validation/hosted-result.json), [receipt audit](validation/hosted-audit.json), [artifact identity](validation/hosted-artifact.json), [isolation qualification](qualification/hosted-validation.json) and [remaining plan](VALIDATION_PLAN.md) retain these gaps. The hosted run checked the frozen 25-file packet; this working draft adds only evidence receipts and updates status/prose afterward. The data reader and research observations are unchanged. No full-suite pass is implied.

A later [diagnostic-only run](https://github.com/clutchpbcfo/hyperliquid-source/actions/runs/41374009882) reproduced that verification failure: Git LFS could not create its clean-filter temporary file inside read-only reference metadata. Supplying a separate writable cache made all seven exact pins, ordinary status and fresh-index status checks pass. The 51 Git-operation receipts were audited and source/artifact hashes remained unchanged. This proves the cache correction for the isolated Git checks; it does not claim a successful full `make verify` or complete test suite. [Diagnostic audit](validation/git-pin-diagnostic.json), [artifact identity](validation/git-pin-artifact.json), [original error](validation/git-pin-baseline.stderr), [qualification](qualification/git-pin-diagnostic.json).

The next full validation is pinned to current main `e5c9b6436876b2a4a39daef813171f9879317699`. The four-commit refresh changes accounting documentation and four Python files; the captured artifact identities, seven reference pins and 971-file test inventory are unchanged. Previous hosted results above remain evidence for their explicitly named source revisions. No new result is inferred from the refresh.

## Coordinates, authorship and limits

Addresses are linked ELF VAs; file offsets are separately retained in `evidence.json`. Bounds come from actual FDE initial-location/range fields, not next unwind starts. No normalization mask or compiled Rust candidate is used. No compiled-code comparison or byte-coverage registration is claimed.

New analysis prose and the owned data reader are independently authored. Original captured bytes/exports retain their upstream rights; they are evidence, not transplanted implementation. No source from the unlicensed inferred can1357 tree was copied. Its pinned revision is cited solely for target/reference provenance. Original negative results and earlier scopes remain preserved.

Open boundaries include **0x15b01d0**, both alternative decoders, conversion/cleanup helpers, reachable data/type ownership beyond the recorded associations, LSDA/exception closure, all callers, complete accepted schemas and whole-node identity. A diagnostic name is not a fully qualified source type. A non-sentinel local result is not proof of a valid complete input. The source-type/layout hypotheses are distinguished from observed byte operations.

This is a **local draft**. No upstream PR, model-backed inference, captured execution, wallet/chain action, scoring request, payment or progress change occurred. The next question is whether the two alternative decoders establish concrete result variants and field requirements; that research can follow separately from this bounded dispatch/closure packet.
