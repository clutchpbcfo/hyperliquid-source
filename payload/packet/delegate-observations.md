# Node #94 initial JSON delegate: bounded static observations

The decoded region at **0x15c0d90** contains a local object-handling path, state/cursor guards, a 64-byte append loop and two caller-visible return-store layouts. The concrete result type and complete accepted input format remain unresolved. These are observations of captured machine-code bytes and their local control flow; the captured parser was never executed or emulated.

## Identity and evidence

- Full capture: node #94, 91,774,280 bytes, SHA256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`, authenticated locally by owned standard-library data readers.
- Delegate: linked ELF VA **[0x15c0d90, 0x15c15c3)**, file offset **0x15bfd90**, 2,099 bytes, SHA256 `11b6ac618f848362971f5e10e4f2cf4e89f070a5ba2eb9ca3be4596bc17eecc2`.
- Supporting caller: **[0x15ba010, 0x15ba1c8)**, 440 bytes, SHA256 `86f9090343566d5391ce8e80a4c12f4e785f9ba61543e2e37b1cfafaf6548ba9`; direct call **0x15ba05b -> 0x15c0d90**, bytes `e8306d0000`.
- [Hosted run](https://github.com/clutchpbcfo/hyperliquid-source/actions/runs/41285258547): GNU objdump 2.42 decoded 449 delegate instructions and 99 caller instructions. Both decodes cover their frozen excerpts contiguously and exactly, without undecoded rows.
- [Raw native output](native/delegate.stdout), [native instruction records](evidence.json), [annotated sites](delegate-observations.json), [artifact verification](qualification/41285258547-verified.json).

The region boundaries come from actual CIE/FDE fields, not the next unwind-index start. They establish unwind-described PC regions, not complete source-function ownership. The hosted job checked excerpt hashes; it did not reacquire or authenticate the complete ELF. [Range extraction](evidence.json) and [full-input identity](evidence.json) retain the local binding.

The [accepted wrapper packet](https://github.com/lalalune/hyperliquid-source/blob/cec50f68e01c967d21538d48c49683ddeea52767/research/work-items/RE-001-json-trailing-admission-94/README.md) already establishes the caller's trailing-whitespace checks and call ordering. This analysis advances its explicitly unresolved delegate question. The whitespace mask is credited context, not a new wrapper discovery.

## Observed local path

| Observation | Instruction anchors | Bound on the claim |
| --- | --- | --- |
| The incoming output pointer is retained in RBX; the incoming state pointer in R14. State +0x18 supplies input bytes, +0x20 a length-like bound, and +0x28 a cursor. | 0x15c0da1, 0x15c0da4, 0x15c0db1, 0x15c0db5, 0x15c0dc2 | Offset roles follow local addressing/comparisons. No complete Rust state layout is recovered. |
| The leading scan advances the cursor for bytes 9, 10, 13 and 32. The next local comparison is with `{` (0x7b). | 0x15c0dcf, 0x15c0dde, 0x15c0de4, 0x15c0dea, 0x15c0e19 | The mask `0x100002600` plus the unsigned bound 32 selects exactly these four values across the 256-byte domain. They match [RFC 8259 section 2](https://datatracker.ietf.org/doc/html/rfc8259#section-2). This is a local scan predicate, not whole-parser compliance. |
| A non-`{` byte takes a separate helper path rather than the local object loop. | 0x15c0e1c -> 0x15c1409; call 0x15c1418 -> 0x15b9910; then 0x160f1c0 | The helpers are opaque. No complete-input rejection or recovered error name is claimed. |
| State byte +0x48 is checked for zero, decremented and stored. A zero result selects raw code 0x18. The buffer-cleanup path later guards against 0xff, increments this byte and stores it. | 0x15c0e22, 0x15c0e29, 0x15c0e2f, 0x15c0e31, 0x15c0e35, 0x15c1422; 0x15c116f through 0x15c117e | A depth-like budget is a plausible interpretation. Reachable state values, maximum nesting and helper behavior are not proved. |
| The entry scan distinguishes an initial entry from subsequent entries, consumes commas on the subsequent-entry path, recognizes `}`, and otherwise requires a quoted key. | 0x15c0e6c, 0x15c0ea2, 0x15c0ea8, 0x15c0ef2, 0x15c0efc, 0x15c0f05, 0x15c1103 | Key escapes, Unicode, duplicate-key handling and accepted key names are delegated or unresolved. |
| A key helper is called indirectly; the next local delimiter scan requires `:` before a direct value-helper call. | 0x15c0f31; 0x15c1027, 0x15c102b; 0x15c104e -> 0x15be300 | The value helper's result byte is compared with raw tag 0x16 at 0x15c105b. Neither the concrete enum nor the helper's complete grammar is established. |
| The append loop shifts the count left six bits, performs four 16-byte stores and increments the count. | 0x15c10c8; 0x15c10e0, 0x15c10e5, 0x15c10ea, 0x15c10ef; 0x15c10f3 | This establishes 64-byte local append records. A key/value pairing is an inference from data flow, not a recovered record type. Capacity behavior remains inside a helper. |
| The close-brace path calls 0x1619820 with stack output storage and the local buffer header. Cleanup and a later call to 0x15b9ce0 precede the final output selection. | 0x15c1273, 0x15c1278, 0x15c127d; 0x15c12fe; 0x15c1185 | Calling the constructor/visitor helper does not prove that `{}` or any particular object is accepted. These two helpers are the next result-shape blockers. |

## Caller-visible local stores

R13 is initialized to **0x8000000000000001** and reloaded on paths that reuse it. At 0x15c11f8 the intermediate first word is compared against that raw sentinel. The equal branch goes to 0x15c1323. Otherwise, the return value of helper 0x15b9ce0 is tested: nonzero goes to 0x15c134d; zero reaches the ordinary copy.

| Return arm | Local stores through the retained output pointer | Meaning established |
| --- | --- | --- |
| Ordinary copy, 0x15c1217 through 0x15c125a | Qwords at +0 and +8; five 16-byte stores at +0x10, +0x20, +0x30, +0x40, +0x50; qword at +0x60. Together: offsets 0 through 103. | A **104-byte store layout** on this local arm. Concrete fields, Rust type and accepted schema are unknown. |
| Common sentinel arm, 0x15c1394 and 0x15c1398 | RAX at +8 and the sentinel in R13 at +0. | A **16-byte local store layout**. No assertion about prior initialization, external helper side effects or the remaining caller storage. |
| Shared return, 0x15c125e through 0x15c1272 | RAX receives RBX, then the epilogue returns. | Both local arms return the output pointer. This does not establish behavior of non-returning or unwinding paths. |

The caller already uses the same raw sentinel. This strengthens the byte-level connection between the accepted wrapper and its delegate without assigning a Rust enum name or calling every non-sentinel form a validated success type.

## Raw local diagnostic codes

These are immediates stored before calls to 0x15b8e90. Names below describe local branch conditions, not reconstructed dependency enum variants or executed error messages.

| Local condition | Code store VA | Raw code |
| --- | --- | --- |
| Initial cursor exhausted, including after leading whitespace | 0x15c0dfe | 0x05 |
| Decremented state byte becomes zero | 0x15c1422 | 0x18 |
| Input exhausted while scanning entries | 0x15c1124 | 0x03 |
| Input exhausted after a comma | 0x15c1308 | 0x05 |
| Subsequent entry lacks comma or close brace | 0x15c1430 | 0x08 |
| Close brace encountered where a quoted key is required after a comma | 0x15c1454 | 0x15 |
| Other locally invalid key start, including a first-entry comma | 0x15c146f | 0x11 |
| Input exhausted in the scan following a key | 0x15c13a0 | 0x03 |
| The required colon is absent | 0x15c148a | 0x06 |

## Selected links and dependency anchors

The owned full-image data reader retained exact relocation records and descriptor bytes in [SELECTED_LINKS.json](delegate-links.json).

- Slot **0x576eca0 -> 0x4ebf970**, loaded into R9 before the key call at 0x15c0f31.
- Slot **0x576e768 -> 0x13eda70**, loaded before the capacity-dependent call at 0x15c10be.
- Slot **0x576dfe0** binds external dynamic symbol **memcpy**. Other local targets remain identified by their addresses.
- Descriptor **0x5676908** references the captured diagnostic path ending `serde_json-1.0.120/src/de.rs`; **0x5676878** references `serde_json-1.0.120/src/read.rs`. These support a dependency association. They do not identify the concrete node result type, a unique historical build producer or exact source equivalence.
- Descriptor **0x5676920** contains raw qwords `[0, 0, 1, 0]`, with a relocation at +0x18 to **0x1615490**. A visitor/vtable interpretation remains a hypothesis.

## Verification and open boundaries

All **78 direct branch sites** in the selected region target recorded instruction starts. There are **26 direct call sites**, **14 distinct direct destinations**, and **18 indirect call sites**. One RET appears at 0x15c1272 and a UD2 at 0x15c1509. The code following the UD2 contains apparent cleanup/unwind paths. LSDA and exception edges, all callers, and callee behavior are not closed. The branch inventory is not a complete CFG.

[LOCAL_BINDING_CONTROLS.json](delegate-binding-controls.json) records 48 selected native instruction-byte bindings and 48 rejected single-byte mutations, below the global digest gate. Three relative calls and seven conditional branches were recalculated. The local leading-whitespace predicate was checked over all 256 byte values. The output-store coverage calculation checks the observed offsets and widths. Mutation rejection tests evidence bindings; it does not execute parser behavior, establish accepted examples or qualify opaque helpers.

No repository modules, target program, compiler, VM or tests ran on the Mac. The only native analysis ran in the single isolated hosted job. Full repository CI, make doctor/verify/test/catalogue-check/reproduce, independent complete-input hosted reproduction, a Rust implementation, runtime equivalence, milestone completion, Points and payment are outside this result. No upstream PR was opened.
