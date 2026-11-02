# RE-001: JsonRpcResult dispatch and object closure in node #94

The two formerly opaque helpers now have bounded static descriptions. The 342-byte constructor tries two alternative decoding helpers, and its captured failure message names **JsonRpcResult**. The 179-byte post-object helper scans whitespace, checks for a closing brace, advances the cursor past it and explicitly returns zero on that arm. The two alternative helpers' field requirements remain unresolved.

These observations advance the [earlier delegate analysis](delegate-observations.md), without executing the captured parser, claiming a complete accepted schema or reconstructing a Rust type.

## Target and native evidence

Node #94, 91,774,280 bytes, SHA256 **3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f**. Source snapshot **6d727b9ea2ca4dc497c96a2de35cfba064e14dcc**. Linked ELF VAs and file-backed executable section mappings are retained in [FUNCTION_RANGE_RECORDS.json](evidence.json), including actual FDE/CIE fields and incoming call bytes.

| Region | Linked ELF interval | File offset | Bytes | Instructions |
| --- | --- | --- | ---: | ---: |
| Constructor/visitor, descriptive role | [0x1619820, 0x1619976) | 0x1618820 | 342 | 79 |
| Post-object check | [0x15b9ce0, 0x15b9d93) | 0x15b8ce0 | 179 | 47 |

The [single hosted run](https://github.com/clutchpbcfo/hyperliquid-source/actions/runs/41287064801) used GNU objdump 2.42. Both instruction sequences cover their frozen excerpts exactly and contiguously. [Constructor stdout](native/object-constructor.stdout), [post-object stdout](native/post-object.stdout), [native records](evidence.json), [artifact verification](qualification/41287064801-verified.json).

## Constructor: observed sequence and result paths

The incoming output pointer is retained in RBX. Input header +8 supplies a pointer and +0x10 a count. At **0x1619835**, the count is shifted left six bits; **0x1619839** adds the pointer. The helper builds a three-word local state containing start pointer, end pointer and zero, then calls **0x15b01d0** at **0x1619856**. This is consistent with an iterator over the delegate's 64-byte records; the exact intermediate source type remains unknown.

The returned first byte is compared with raw tag **0x16** at **0x1619860**. Equality selects a two-qword local output: payload at +8 and raw sentinel **0x8000000000000001** at +0, then the shared return. The helper's error/tag enum name is not established.

The other arm builds a 32-byte intermediate from the returned byte/payload and calls **0x15a8ec0** at **0x16198ae**. At **0x16198bd**, the resulting first word is compared with the sentinel. A non-sentinel result branches directly to the ordinary result copy. A sentinel result calls **0x1617010**, then calls the second alternative **0x15a89d0** at **0x16198d6** using the same intermediate storage address. Preservation of that storage's content by the first helper is not established.

The second alternative's result word is also compared with the sentinel at **0x16198db**. A non-sentinel result reaches the same result copy. A sentinel result calls **0x1617010** again, then supplies a captured diagnostic pointer and length to **0x1619690**. The meaning of the intervening helper is unresolved; cleanup is a role inference, not a decoded contract.

At **0x16198ec**, the RIP-relative LEA resolves to **0x26393a**; **0x16198f3** supplies length **61**. Those exact read-only bytes say:

`data did not match any variant of untagged enum JsonRpcResult`

The pointer, length, file mapping, raw bytes and string are checked in [HELPER_OBSERVATIONS.json](helper-observations.json) and [CONSTRUCTOR_DIAGNOSTIC.json](helper-diagnostic.json). This is a diagnostic in the captured target, not a quotation from inferred reference source. Its placement on the both-sentinel path supports association with an untagged result named JsonRpcResult. It does not establish a fully qualified source type, accepted field names, the two variant names, generic parameters or exact source-level equivalence.

The ordinary result copy consists of six 16-byte stores at output offsets **0, 0x10, 0x20, 0x30, 0x40, 0x50** and one qword at **0x60**. These cover **104 bytes** with no overlap or gap, matching the delegate's previously observed ordinary output width. Sentinel paths locally write only +0 and +8. The shared epilogue returns the output pointer at **0x161994f**. Calls to **0x16177e0** and the apparent unwind tail remain opaque; local stores do not describe external helper side effects or unwinding behavior.

## Post-object helper: the missing close-brace operation

The helper reads input pointer, bound and cursor from state **+0x18, +0x20, +0x28**. The cursor is compared with the bound before reading input. The local scan uses mask **0x100002600** and an unsigned bound comparison against **0x2c**, then a separate comma comparison. Across all 256 byte values the whitespace path selects exactly **9, 10, 13, 32**, matching [RFC 8259 section 2](https://datatracker.ietf.org/doc/html/rfc8259#section-2).

| Local path | Instruction anchors | Observed operation |
| --- | --- | --- |
| Cursor exhausted initially or after scanning whitespace | 0x15b9cef, 0x15b9d29, 0x15b9d2b, 0x15b9d36 | Supply raw code **3** to 0x15b8e90 and return its value. |
| Whitespace | 0x15b9cfb, 0x15b9d0b, 0x15b9d11, 0x15b9d17 | Advance state cursor one byte and continue scanning. |
| Comma | 0x15b9d40, 0x15b9d46, 0x15b9d51 | Supply raw code **0x15** to 0x15b8e90 and return its value. |
| Closing brace | 0x15b9d5b, 0x15b9d5f, 0x15b9d66, 0x15b9d6a | After the local nonzero guard, store cursor one past `}` and explicitly return **0**. |
| Other non-whitespace byte | 0x15b9d71, 0x15b9d7c | Supply raw code **0x16** to 0x15b8e90 and return its value. |
| Guarded zero-cursor arm | 0x15b9d64, 0x15b9d86, 0x15b9d8d | Call through slot 0x576e118 using descriptor 0x5676878. No returning contract is asserted. |

Only the closing-brace arm has a locally explicit zero return. The code-to-error mapping, allocation behavior and nonzero return convention of 0x15b8e90 remain external to this helper's decode. No complete-input success/rejection experiment was run.

The previously decoded delegate sees `}` at **0x15c0ef2**, branches to the constructor call **0x15c127d**, cleans the entry buffer and restores its state byte, then calls this post-object helper at **0x15c1185**. It has not locally consumed that brace before construction. This new decode supplies the missing explicit cursor advance. The prior accepted caller wrapper still owns admission of trailing bytes after the complete object; this post-object scan must not be relabeled as a duplicate of its trailing-whitespace check.

The earlier delegate then compares its intermediate word with the same sentinel and tests this helper's return. A constructor non-sentinel plus a post-object zero reaches the 104-byte output copy. Other local arms retain their previously documented conversion/cleanup gaps.

## Verification and limits

The owned local analyzer reauthenticated the full capture, matched every retained native row to the executable file bytes, recalculated direct branch/call destinations, checked local branch targets as recorded instruction starts and checked external direct destinations for executable-section membership. Selected dynamic relocation slots and the read-guard diagnostic descriptor were read as data; the descriptor points to the captured `serde_json-1.0.120/src/read.rs` path. Relative slot targets do not establish callee behavior.

Nineteen targeted corruptions were rejected **below the global digest gate**, covering iterator stride, raw tag/sentinel, both alternative calls/branches, diagnostic address/length/type-name bytes, output-store coverage, whitespace mask, closing byte/branch/cursor/zero-return and three raw diagnostic codes. These validate evidence bindings and local byte predicates, not parser behavior or a reimplemented model's equivalence. The full 256-byte whitespace domain is the explicit denominator for that local predicate alone.

No additional helper was natively decoded. The alternative decoders **0x15a8ec0** and **0x15a89d0**, intermediate builder **0x15b01d0**, conversion/cleanup helpers, LSDA/exception edges, full source-function ownership and complete accepted schema remain open. No Rust implementation, runtime equivalence, whole-node progress gate, Points or payment is claimed. Full repository checks and independent complete-input hosted reproduction have not run. The hosted job itself checked the excerpts, while full-input authentication was local.

This supports one bounded static research contribution extending the accepted wrapper packet. It does not yet support a complete JsonRpcResult parser implementation.
