"""Hosted static comparison. No target or reference-object execution."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

BASE = "05bc2de303c05525b71e7e257426e741bc66a390"
TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
SOURCE_SHA = "25b7d54b248a1ccb910d4abb8a45ea82d7bdc78e48162b80e492dd5f2100a03c"
BODY_SHA = "d2076f9aebaf3b248e7c260b85fca54fbb7195d158f836c5e5089418a5527bc9"
START, END = 0x5D20100, 0x5D21214
SYMBOL = "blst_sha256_block_data_order"
TOOLS = ("as", "cpp", "objdump", "readelf", "git")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def sections(data):
    # Adapted from this contributor's earlier bounded ELF provenance reader.
    require(len(data) >= 64 and data[:6] == b"\x7fELF\x02\x01", "ELF64 little endian required")
    kind, machine = struct.unpack_from("<HH", data, 16)
    require(machine == 62, "x86-64 required")
    offset = struct.unpack_from("<Q", data, 40)[0]
    stride, count, names = struct.unpack_from("<HHH", data, 58)
    require(stride == 64 and 0 < count < 1000 and names < count, "unsupported section table")
    require(offset + count * stride <= len(data), "section table exceeds input")
    rows = []
    for index in range(count):
        n, t, flags, va, off, size, link, info, align, step = struct.unpack_from(
            "<IIQQQQIIQQ", data, offset + index * stride)
        require(t == 8 or off + size <= len(data), "section exceeds input")
        rows.append(dict(index=index, name_offset=n, type=t, flags=flags, va=va,
                         offset=off, size=size, link=link, info=info, align=align, step=step))
    names_section = rows[names]
    require(names_section["type"] == 3, "section names require STRTAB")
    strings = payload(data, names_section)
    for row in rows:
        row["name"] = string_at(strings, row["name_offset"])
    return kind, rows


def payload(data, section):
    require(section["type"] != 8, "NOBITS has no file bytes")
    return data[section["offset"]:section["offset"] + section["size"]]


def string_at(data, offset):
    end = data.find(b"\0", offset)
    require(0 <= offset < len(data) and end >= offset, "invalid ELF string")
    return data[offset:end].decode("ascii")


def object_record(data):
    kind, rows = sections(data)
    require(kind == 1, "relocatable reference object required")
    tables = {}
    for section in rows:
        if section["type"] != 2:
            continue
        require(section["step"] == 24 and section["size"] % 24 == 0, "invalid symbol table")
        require(section["link"] < len(rows), "symbol string table link")
        strings = payload(data, rows[section["link"]])
        table = []
        for at in range(section["offset"], section["offset"] + section["size"], 24):
            n, info, other, owner, value, size = struct.unpack_from("<IBBHQQ", data, at)
            table.append(dict(name=string_at(strings, n), type=info & 15,
                              binding=info >> 4, section=owner, value=value, size=size))
        tables[section["index"]] = table
    functions = [s for table in tables.values() for s in table if s["name"] == SYMBOL]
    require(len(functions) == 1, "reference function is ambiguous")
    function = functions[0]
    require(function["type"] == 2 and 0 < function["section"] < len(rows), "invalid function symbol")
    owner = rows[function["section"]]
    require(owner["flags"] & 4 and function["value"] + function["size"] <= owner["size"], "function bounds")
    code = payload(data, owner)[function["value"]:function["value"] + function["size"]]
    relocations = []
    for section in rows:
        if section["type"] not in (4, 9):
            continue
        require(section["type"] == 4 and section["step"] == 24 and section["size"] % 24 == 0,
                "RELA64 required")
        require(section["link"] in tables and section["info"] < len(rows), "relocation links")
        for at in range(section["offset"], section["offset"] + section["size"], 24):
            place, info, addend = struct.unpack_from("<QQq", data, at)
            require(info >> 32 < len(tables[section["link"]]), "relocation symbol index")
            symbol = tables[section["link"]][info >> 32]
            relocation = dict(section=rows[section["info"]]["name"], offset=place,
                              type=info & 0xFFFFFFFF, addend=addend, symbol=symbol)
            if section["info"] == function["section"] and function["value"] <= place < function["value"] + len(code):
                relocation["body_offset"] = place - function["value"]
            relocations.append(relocation)
    return function, code, relocations


def comparison(reference, target, relocations):
    require(len(reference) == len(target) == END - START, "body lengths differ")
    wanted = {"__blst_platform_cap": (10, -8, b"\xf7\x05"),
              ".Lblst_sha256_block_data_order$2": (20, -4, b"\x0f\x85"),
              "K256": (101, -4, b"\x48\x8d\x2d")}
    require(len(relocations) == 3 and {r["symbol"]["name"] for r in relocations} == set(wanted),
            "unexpected reference relocation set")
    masks = set()
    bindings = []
    for row in relocations:
        require(row["type"] in (2, 4), "unsupported PC-relative relocation")
        at = row["body_offset"]
        expected_offset, expected_addend, prefix = wanted[row["symbol"]["name"]]
        require(at == expected_offset and row["addend"] == expected_addend, "relocation field changed")
        require(reference[at - len(prefix):at] == prefix, "relocation opcode changed")
        require(reference[at:at + 4] == b"\0" * 4, "reference relocation is not unresolved")
        require(0 <= at and at + 4 <= len(reference), "relocation exceeds body")
        fields = set(range(at, at + 4))
        require(not masks & fields, "overlapping relocation fields")
        require(row["symbol"]["section"] in (0, 0xFFF2), "reference symbol unexpectedly defined")
        masks.update(fields)
        encoded = struct.unpack_from("<i", target, at)[0]
        bindings.append(dict(symbol=row["symbol"]["name"], body_offset=at,
                             type=row["type"], addend=row["addend"], bytes=4,
                             linked_address=hex(START + at + encoded - row["addend"])))
    mismatches = [i for i, pair in enumerate(zip(reference, target)) if pair[0] != pair[1] and i not in masks]
    return dict(matched=not mismatches, reference_bytes=len(reference), target_bytes=len(target),
                masked_bytes=len(masks), compared_bytes=len(reference) - len(masks),
                mismatch_offsets=mismatches, raw_equal=reference == target, bindings=bindings)


def run(root, label, argv):
    result = subprocess.run(argv, cwd=root / "work", stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=75)
    require(len(result.stdout) < 2_000_000 and len(result.stderr) < 100_000, "tool output exceeds bound")
    (root / "output" / (label + ".log")).write_bytes(result.stdout)
    (root / "output" / (label + ".stderr.log")).write_bytes(result.stderr)
    records = json.loads((root / "output/commands.json").read_text())
    records[label] = dict(argv=argv, exit_code=result.returncode,
                          stdout_sha256=digest(result.stdout), stderr_sha256=digest(result.stderr))
    save(root / "output/commands.json", records)
    require(result.returncode == 0, "tool failed: " + label)
    return result.stdout


def native_rows(raw, start, end):
    rows = []
    for line in raw.decode().splitlines():
        match = re.match(r"^\s*([0-9a-f]+):[ \t]+((?:[0-9a-f]{2}[ \t]+)+)(\S.*)$", line)
        if match and start <= int(match[1], 16) < end:
            rows.append((int(match[1], 16), bytes.fromhex(match[2]), match[3]))
    pc = start
    for address, code, _ in rows:
        require(address == pc, "native rows do not cover the body")
        pc += len(code)
    require(pc == end, "native coverage is incomplete")
    return rows


def authenticate(data):
    require(len(data) == 105896032 and digest(data) == TARGET_SHA, "target identity mismatch")


def prepare(root, checkout):
    require(subprocess.check_output(["/usr/bin/git", "-C", str(checkout), "rev-parse", "HEAD"], text=True).strip() == BASE,
            "checkout base mismatch")
    source = root / "frozen/reference-source.s"
    require(source.stat().st_size == 26196 and file_digest(source) == SOURCE_SHA, "source identity mismatch")
    require(not re.search(r"(?m)^\s*\.(?:include|incbin)\b|^\s*#\s*include\b", source.read_text()), "source includes another file")
    target = checkout / "artifacts/node/115/hl-node"
    require(not target.stat().st_mode & 0o111, "capture must be nonexecutable")
    authenticate(target.read_bytes())
    shutil.copy2(target, root / "target/hl-node")
    (root / "target/hl-node").chmod(0o444)
    for name in TOOLS:
        found = shutil.which(name, path="/usr/bin:/bin")
        require(found is not None, "missing system tool: " + name)
        (root / "bin" / name).symlink_to(found)
    llvm = next((path for name in ("llvm-objdump", "llvm-objdump-18", "llvm-objdump-17")
                 if (path := shutil.which(name, path="/usr/bin:/bin"))), None)
    require(llvm is not None, "missing LLVM objdump")
    (root / "bin/llvm-objdump").symlink_to(llvm)
    (root / "bin/python3").symlink_to(sys.executable)
    save(root / "output/prepared.json", dict(base=BASE, target_sha256=TARGET_SHA,
         source_sha256=SOURCE_SHA, tools={p.name: str(p.resolve()) for p in (root / "bin").iterdir()}))


def analyze(root, parent_namespace):
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    caps = {name: status[name].strip() for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")}
    interfaces = [line.split(":", 1)[0].strip() for line in Path("/proc/net/dev").read_text().splitlines()[2:]]
    require(os.getuid() == os.getgid() == 65534 and os.getgroups() == [], "identity isolation")
    require(all(int(v, 16) == 0 for v in caps.values()) and status["NoNewPrivs"].strip() == "1", "privilege isolation")
    require(os.readlink("/proc/self/ns/net") != parent_namespace and interfaces == ["lo"], "network isolation")
    for name in ("target", "frozen"):
        require(os.statvfs(root / name).f_flag & os.ST_RDONLY, "input mount is writable")
    require(os.statvfs(root / "work").f_flag & os.ST_NOEXEC, "work mount permits execution")
    target_path = root / "target/hl-node"
    require(not os.access(target_path, os.X_OK), "capture execution permitted")
    data = target_path.read_bytes()
    authenticate(data)
    source = root / "frozen/reference-source.s"
    require(file_digest(source) == SOURCE_SHA, "source changed")
    save(root / "output/qualification.json", dict(uid=os.getuid(), gid=os.getgid(), groups=os.getgroups(),
         capabilities=caps, no_new_privs=1, interfaces=interfaces, source_readonly=True,
         target_readonly=True, target_nonexecutable=True, work_noexec=True, network_isolated=True))
    save(root / "output/commands.json", {})
    versions = {name: run(root, "version-" + name, [name, "--version"]).decode().splitlines()[0]
                for name in ("cpp", "as", "objdump", "readelf", "llvm-objdump")}
    save(root / "output/versions.json", versions)
    preprocessed = root / "work/reference.s"
    run(root, "preprocess", ["cpp", "-P", "-undef", "-nostdinc", "-D__BLST_PORTABLE__=1",
                             "-x", "assembler-with-cpp", str(source), "-o", str(preprocessed)])
    object_path = root / "work/reference.o"
    run(root, "assemble", ["as", "--64", "-o", str(object_path), str(preprocessed)])
    object_path.chmod(0o444)
    reference_data = object_path.read_bytes()
    require(len(reference_data) < 100_000, "reference object exceeds bound")
    (root / "output/reference-object.hex").write_text(reference_data.hex() + "\n")
    function, reference, all_relocations = object_record(reference_data)
    relocations = [r for r in all_relocations if "body_offset" in r]
    save(root / "output/reference-object.json", dict(function=function, object_sha256=digest(reference_data),
         object_bytes=len(reference_data), body_sha256=digest(reference), body_bytes=len(reference),
         relocations=all_relocations, preprocessed_sha256=file_digest(preprocessed)))
    _, target_sections = sections(data)
    owner = [s for s in target_sections if s["flags"] & 4 and s["va"] <= START and END <= s["va"] + s["size"]]
    require(len(owner) == 1, "target extent has no unique executable owner")
    offset = owner[0]["offset"] + START - owner[0]["va"]
    target = data[offset:offset + END - START]
    require(digest(target) == BODY_SHA, "selected target body changed")
    object_gnu = run(root, "object-gnu", ["objdump", "-d", "-z", "--insn-width=16", str(object_path)])
    object_llvm = run(root, "object-llvm", ["llvm-objdump", "-d", "--disassemble-zeroes", str(object_path)])
    run(root, "object-readelf", ["readelf", "-Wr", "-Ws", str(object_path)])
    target_gnu = run(root, "target-gnu", ["objdump", "-d", "-z", "--insn-width=16",
        "--start-address=" + hex(START), "--stop-address=" + hex(END), str(target_path)])
    target_llvm = run(root, "target-llvm", ["llvm-objdump", "-d", "--disassemble-zeroes",
        "--start-address=" + hex(START), "--stop-address=" + hex(END), str(target_path)])
    target_rows = [native_rows(raw, START, END) for raw in (target_gnu, target_llvm)]
    require(len(target_rows[0]) == len(target_rows[1]) == 1295, "target instruction count changed")
    require([(a, b) for a, b, _ in target_rows[0]] == [(a, b) for a, b, _ in target_rows[1]], "target native disagreement")
    require(b"".join(b for _, b, _ in target_rows[0]) == target, "target native byte mismatch")
    for raw in (object_gnu, object_llvm):
        rows = native_rows(raw, function["value"], function["value"] + len(reference))
        require(b"".join(b for _, b, _ in rows) == reference, "reference native byte mismatch")
    result = comparison(reference, target, relocations)
    save(root / "output/comparison.json", result)
    require(result["matched"], "unmasked body mismatch")
    controls = {}
    mutated = bytearray(target)
    mutated[0] ^= 1
    controls["unmasked_instruction_mutation_rejected"] = not comparison(reference, mutated, relocations)["matched"]
    for label, changed in (("removed_relocation_rejected", relocations[:-1]),
                           ("altered_relocation_rejected", [{**relocations[0], "addend": relocations[0]["addend"] + 1}, *relocations[1:]])):
        try:
            comparison(reference, target, changed)
        except ValueError:
            controls[label] = True
        else:
            controls[label] = False
    wrong = bytearray(data)
    wrong[-1] ^= 1
    try:
        authenticate(wrong)
    except ValueError:
        controls["wrong_target_digest_rejected"] = True
    else:
        controls["wrong_target_digest_rejected"] = False
    require(all(controls.values()), "corruption control accepted")
    save(root / "output/controls.json", controls)
    require(file_digest(source) == SOURCE_SHA and file_digest(target_path) == TARGET_SHA, "inputs changed during analysis")
    save(root / "output/result.json", dict(passed=True, base=BASE, target_sha256=TARGET_SHA,
         source_sha256=SOURCE_SHA, target_start=hex(START), target_end=hex(END),
         body_sha256=BODY_SHA, target_bytes=len(target), native_instruction_rows=1295,
         comparison=result, controls=controls, target_or_reference_executed=False,
         claim="Relocation-masked body comparison to the pinned BLST portable assembly; unique release and outside target identities unresolved"))


if __name__ == "__main__":
    mode, where, extra = sys.argv[1:]
    root = Path(where)
    try:
        if mode == "prepare":
            prepare(root, Path(extra))
        else:
            require(mode == "analyze", "unknown mode")
            analyze(root, extra)
    except Exception as error:
        save(root / "output/error.json", dict(phase=mode, type=type(error).__name__, detail=str(error)[:800]))
        raise
