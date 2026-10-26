#!/usr/bin/env python3
"""python tools/find_functions.py VERSION: add the functions config/VERSION/functions.json does not list, found in the
code itself, unnamed and without a source.

The code of a CodeWarrior x86 executable holds no data (switch tables are in .data), so it decodes linearly. From the
start of every listed function and of every run of code after padding, instructions are decoded up to the next listed
function; the target of each call is a function start, and so is an address of the code that the base relocation table
holds (a function pointer) when it is not an entry of a switch table (jmp [reg*4 + table]) nor inside code decoded from a function start before it. This repeats until no new
start is found; padding counts as such only after a return or jump. A found function runs to the next function, less the padding (zeros or int3) before it."""
import json
import struct
import sys
from bisect import bisect_right
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pe import PEFile
from split import base_relocations, instructions

PADDING = (0x00, 0xCC)
# (ret, ret n, jmp rel32, jmp rel8, jmp r/m)
TERMINATORS = (0xC3, 0xC2, 0xE9, 0xEB, 0xFF)


def main():
    version = sys.argv[1]
    path = Path(f"config/{version}/functions.json")
    config = json.loads(Path(f"config/{version}/config.json").read_text())
    pe = PEFile(Path(config["original"]))
    text = next(s for s in pe.sections if s.name == ".text")
    low, high = text.virtual_address, text.virtual_address + text.virtual_size
    code = pe.read(low, text.virtual_size)
    functions = json.loads(path.read_text())
    listed = {int(f["address"], 16): f for f in functions}
    fixups = base_relocations(pe)
    fixed = set(fixups)
    # (the entries of switch tables: case labels, not functions)
    cases = set()
    operands = set()
    for at in fixups:
        operands.update(range(at, at + 4))
    pointers = {struct.unpack_from("<I", pe.data, pe.address_to_offset(at))[0] for at in fixups}
    pointers = {p for p in pointers if low <= p < high}

    extents = sorted((a, a + f["size"]) for a, f in listed.items())
    firsts_listed = [a for a, _ in extents]

    def inside(address):
        """Whether ADDRESS is in a listed function, past its start (a jump target of its own code)."""
        k = bisect_right(firsts_listed, address) - 1
        return k >= 0 and extents[k][0] < address < extents[k][1]

    found = set(listed) | {low}
    starts = set(found)
    for _ in range(50):
        ordered = sorted(starts)
        calls, reached = set(), []
        for k, start in enumerate(ordered):
            end = ordered[k + 1] if k + 1 < len(ordered) else high
            if start in listed and start + listed[start]["size"] < end:
                # (a listed function is its size: what follows it up to the next start is code of its own)
                after = start + listed[start]["size"]
                while after < end and code[after - low] in PADDING and after not in operands:
                    after += 1
                if after < end:
                    calls.add(after)
                end = start + listed[start]["size"]
            at, last = start, None
            while at < end:
                # (padding after a return or jump, between functions: the next code is a start of its own)
                if last in TERMINATORS and code[at - low] in PADDING and at not in operands:
                    run = at
                    while run < end and code[run - low] in PADDING and run not in operands:
                        run += 1
                    if run < end:
                        calls.add(run)
                    break
                try:
                    offset, length, opcode, target, _ = next(instructions(code[at - low:end - low + 16], at))
                except (KeyError, IndexError, StopIteration):
                    break
                if opcode == 0xE8 and target is not None and low <= target < high:
                    calls.add(target)
                if opcode == 0xFF and code[at - low + offset + 1:at - low + offset + 3] == bytes([0x24, 0x85]):
                    # (jmp [reg*4 + table]: the table's entries are this function's)
                    entry = struct.unpack_from("<I", code, at - low + offset + 3)[0]
                    while entry in fixed:
                        value = struct.unpack_from("<I", pe.data, pe.address_to_offset(entry))[0]
                        # (the cases follow the jump in its function)
                        if not at < value < at + 0x4000:
                            break
                        cases.add(value)
                        entry += 4
                last = opcode if opcode != 0xFF or (code[at - low + offset + 1] >> 3) & 7 == 4 else None
                at += length
            reached.append((start, at))
        # (a pointer into code decoded from a start before it is a jump target inside that function)
        firsts = [s for s, _ in reached]
        pointed = set()
        for pointer in pointers - cases:
            k = bisect_right(firsts, pointer) - 1
            if k < 0 or not reached[k][0] <= pointer < reached[k][1]:
                pointed.add(pointer)
        # (a start found as a call target stays one; one that only a pointer gives is found again each time, as a
        # switch table found later may claim it)
        found |= calls - cases
        new = {s for s in found | pointed if s in listed or not inside(s)}
        if new == starts:
            break
        starts = new

    ordered = sorted(starts)
    added = []
    names = {f["name"] for f in functions}
    for k, start in enumerate(ordered):
        if start in listed:
            continue
        end = ordered[k + 1] if k + 1 < len(ordered) else high
        while end > start and code[end - 1 - low] in PADDING and end - 1 not in operands:
            end -= 1
        if end > start:
            # (a listed function can be named by its address in another executable: this one's is then auto_fn_)
            name = f"fn_{start:08x}" if f"fn_{start:08x}" not in names else f"auto_fn_{start:08x}"
            added.append({"name": name, "address": f"0x{start:08x}", "size": end - start})
    # (a listed function the starts found cut into: the code it reaches is its own)
    out = sorted(functions + added, key=lambda f: int(f["address"], 16))
    path.write_text(json.dumps(out, indent=2) + "\n")
    print(f"{len(added)} functions added to the {len(functions)} listed ({sum(f['size'] for f in added)} bytes)")


if __name__ == "__main__":
    main()
