# RE-001: node #115 JsonRpcResult local dispatch and constructor

**Local research draft; required repository checks remain pending.** Task RE-001. Component allocation `foundation` is tentative, not proven source/type ownership. The bounded gap was whether #115 contains the diagnostic-associated alternative constructor and how one local caller handles its result. This packet newly binds two #115 FDE ranges, their native instruction rows and selected local operations. No #94 acceptance credit or generic type schema is transferred.

Target: node #115, 105,896,032 bytes, SHA256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Source `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. Bounds and file offsets are retained in `candidates.json`; VAs differ from body file offsets by 0x1000 here. No inferred reference source is copied or required.

## Actual observations

The constructor is `[0x1751380,0x17514d6)`, 342 bytes / 79 instructions. The caller is `[0x1707010,0x17077b2)`, 1,954 bytes / 410 instructions. These 489 rows over 2,296 bytes are declared evidence denominators, not a function census or reconstruction percentage. [Local operations and explicit unknowns](observations.md), [machine-readable evidence](evidence.json).

The diagnostic occurs once at readonly ELF VA/file offset `0x480c41`. Native decoding confirms its LEA at `0x175144c` and the direct incoming call at `0x17074ee`. The constructor's ordered calls target `0x16fdba0` then, conditionally on the raw sentinel, `0x16fdf90`. Its ordinary arm copies 104 local bytes. The caller retains object/delimiter and tagged-output paths. Both alternative helpers' schemas, opaque post-object semantics and source ownership remain unresolved.

## Reproduce without native or captured execution

With Python 3.12+ standard library and the authenticated complete #115 capture, from repository root:

```sh
python3 -I -B research/work-items/RE-001-node115-jsonrpc-result-dispatch/verify_packet.py \
  --binary artifacts/node/115/hl-node
```

The owned reader authenticates the complete file, all 135,313 ordered unwind-header rows, actual supported CIE/FDE fields, all 489 retained instruction-byte rows and selected field evidence controls. The controls corrupt evidence bytes and FDE extents; they are not runtime parser inputs. No subprocess, repository import, native decoder, network request or captured program is launched. The extended verifier was added after the hosted job. Its local Python 3.14.7 replay passed and rejected 40 evidence corruptions (38 selected field changes and two FDE-extent changes); hosted reproduction remains pending.

## Actual hosted evidence

[Run 41499013810](https://github.com/clutchpbcfo/hyperliquid-source/actions/runs/41499013810), execution `a50750f0da242beda28002f1662c7eab735ae02e`, succeeded on attempt 1 as one job with a 12-minute ceiling. It acquired the pinned complete capture through Git LFS and reproduced the complete-input candidate reader under Python 3.12.3. The two selected ranges were decoded using one GNU objdump 2.42 version query and exactly two static decodes: `-D -z -b binary -m i386:x86-64 -M intel --insn-width=16 --adjust-vma=<ELF-VA>`. The actual executable hash and complete command stdout/stderr are retained in `receipts/`.

Before native analysis, receipts qualified UID/GID 65534, no supplementary groups, zero capabilities, no-new-privileges, a distinct loopback-only network namespace, read-only/noexec payload/input mounts and EROFS write controls. Complete capture, excerpt and payload hashes matched afterward. The independently downloaded archive was 26,181 bytes, SHA256 `e794a70b0ad64ca50968a3b6230a64a1255213e4c2254c12253431080f6dd402`; it matches GitHub's digest. [Artifact and per-file audit](artifact-audit.json).

This proves full-input binding and selected static instruction observations. It is not a `make verify/test/catalogue-check/reproduce` pass, Rust build, runtime parser test or whole-ELF identity result. No new native tool or repository program ran on the Mac. New code/prose is independently authored; captured evidence retains upstream rights. All incomplete gates remain false. No upstream PR, accepted-work Points or payment is claimed.

Next batch: reproduce the extended packet verifier in the hosted environment and run the applicable current repository checks before considering one scoped #115 research PR. The current test inventory has 76 files; the retired 971-file results do not apply to it.
