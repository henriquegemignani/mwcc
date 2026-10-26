#!/usr/bin/env python3
"""python tools/crossmatch.py TO FROM...: find the functions of one executable's function list in another executable built
with the same tools (the compiler's driver, C library and runtime in the linker of the same release).

TO and FROM are config folders (config/FROM/functions.json and bindings.json are read, config/TO/config.json names the
executable searched). With several FROM, the first places a function and names it, and the others place the functions
it does not have and name (and give the source of) those it leaves unnamed. A function of FROM is searched for in all of TO's code by its bytes, the relocated operands
wildcarded (as tools/remap.py does). The two programs are not laid out alike, so the search is not windowed: a function
found once is placed there, and one found in several places goes where its neighbours in FROM (the nearest placed
functions of the same source, or of any source for the only function of its source) put it. A function with fewer than MIN_FIXED bytes that are not wildcarded is placed only
next to such a neighbour.

config/TO/functions.json and bindings.json are written: the placed functions, each with its FROM source, and the data
the placed functions relocate, named as FROM binds it."""
import json
import re
import sys
from bisect import bisect_left
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pe import PEFile
from remap import data_pairs, pattern, wildcards
from split import base_relocations

MIN_FIXED = 16
# (how far from where its neighbours put it a function found in several places may be)
NEAR = 0x400


def search(blob, start, code, wild):
    return [start + m.start() for m in pattern(code, wild).finditer(blob)]


def place(source, pe_b, text, blob):
    """({address in FROM: address in TO}, FROM's functions, its executable and fixups) of one function list."""
    pe_a = PEFile(Path(json.loads((source / "config.json").read_text())["original"]))
    fix_a = base_relocations(pe_a)
    functions = sorted(json.loads((source / "functions.json").read_text()), key=lambda f: int(f["address"], 16))
    candidates = []
    for f in functions:
        address, size = int(f["address"], 16), f["size"]
        code, wild = wildcards(pe_a, fix_a, address, size)
        fixed = size - len(wild)
        hits = search(blob, text.virtual_address, code, wild) if fixed >= 4 else []
        candidates.append((f, address, size, fixed, hits))

    placed = {}
    # (first the functions found once with enough bytes to be sure of, then the others by their neighbours)
    for f, address, size, fixed, hits in candidates:
        if len(hits) == 1 and fixed >= MIN_FIXED:
            placed[address] = hits[0]
    taken = set(placed.values())
    order = [address for _, address, *_ in candidates]
    by_source = {}
    for f, address, *_ in candidates:
        by_source.setdefault(f.get("source"), []).append(address)
    for f, address, size, fixed, hits in candidates:
        if address in placed or not hits:
            continue
        group = by_source[f.get("source")]
        k = group.index(address)
        neighbours = [a for a in group[k - 1::-1] if a in placed][:1] + [a for a in group[k + 1:] if a in placed][:1]
        if not neighbours:
            # (the only function of its source: its neighbours in the code, whatever their source)
            k = order.index(address)
            neighbours = [a for a in order[k - 1::-1] if a in placed][:1] + [a for a in order[k + 1:] if a in placed][:1]
        guesses = [placed[a] + address - a for a in neighbours]
        best = None
        for hit in hits:
            if hit in taken:
                continue
            distance = min((abs(hit - g) for g in guesses), default=None)
            if distance is not None and distance <= NEAR and (best is None or distance < best[0]):
                best = (distance, hit)
        if best:
            placed[address] = best[1]
            taken.add(best[1])
    return placed, functions, pe_a, fix_a


def unnamed(f):
    return re.fullmatch(r"fn_[0-9a-f]{8}", f["name"]) is not None


def main():
    to_folder, *from_folders = sys.argv[1:]
    target = Path(f"config/{to_folder}")
    pe_b = PEFile(Path(json.loads((target / "config.json").read_text())["original"]))
    text = next(s for s in pe_b.sections if s.name == ".text")
    blob = pe_b.read(text.virtual_address, text.virtual_size)

    result, names, total = {}, {}, 0
    for from_folder in from_folders:
        source = Path(f"config/{from_folder}")
        placed, functions, pe_a, fix_a = place(source, pe_b, text, blob)
        total = max(total, len(functions))
        for f in functions:
            address = int(f["address"], 16)
            if address not in placed:
                continue
            at = placed[address]
            known = result.get(at)
            if known is None:
                result[at] = {**f, "address": f"0x{at:08x}"}
            elif known["size"] == f["size"]:
                # (a list further on names a function, or gives its source, where the first does not)
                if unnamed(known) and not unnamed(f):
                    known["name"] = f["name"]
                if not known.get("source") and f.get("source"):
                    known["source"] = f["source"]
        pairs = data_pairs(functions, placed, pe_a, fix_a, pe_b)
        for name, address in json.loads((source / "bindings.json").read_text()).items():
            moved = pairs.get(int(address, 16))
            if moved is not None and not text.virtual_address <= moved < text.virtual_address + text.virtual_size:
                names.setdefault(name, f"0x{moved:08x}")

    out = sorted(result.values(), key=lambda f: int(f["address"], 16))
    # (two functions placed over each other: keep the larger)
    kept = []
    for f in out:
        start = int(f["address"], 16)
        if kept and int(kept[-1]["address"], 16) + kept[-1]["size"] > start:
            if f["size"] > kept[-1]["size"]:
                kept[-1] = f
            continue
        kept.append(f)
    (target / "functions.json").write_text(json.dumps(kept, indent=2) + "\n")
    # (one address bound by two names: the first list's)
    seen, bindings = set(), {}
    for name, address in names.items():
        if address not in seen:
            seen.add(address)
            bindings[name] = address
    (target / "bindings.json").write_text(json.dumps(bindings, indent=2) + "\n")
    found = sum(f["size"] for f in kept)
    print(f"{len(kept)} functions placed in {to_folder} ({found} of {len(blob)} bytes of code); "
          f"{len(bindings)} bindings carried")


if __name__ == "__main__":
    main()
