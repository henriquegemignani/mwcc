#!/usr/bin/env python3
"""python tools/probe_units.py VERSION [UNIT...]: link the original from its split units with one unit at a time linked
from its compiled object, and say which give the original (by default the units with a source, after `ninja
all_source build/VERSION/obj/ok`).

A unit that does is Matching on its own; config/VERSION/config.json "matching" lists those that also do together (the
build checks that). A unit that does not either fails to link (a symbol the split units name otherwise) or differs at the
address shown."""
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from split import read_splits

# (as configure.py links them)
LIBRARY_OBJECTS = {"cexc.obj": "lib/runtime/cexc.obj", "ccinit.obj": "lib/runtime/ccinit.obj"}


def main():
    version, *chosen = sys.argv[1:]
    config = json.loads(Path(f"config/{version}/config.json").read_text())
    sections, split_units = read_splits(f"config/{version}/splits.txt")
    units = [unit for unit, _ in split_units]
    # (the resources are a .res file of their own, after the sections object)
    resources = [f"build/{version}/obj/resources.res"] if ".rsrc" in sections else []
    chosen = chosen or [u for u in units if Path(f"build/{version}/compiled/{u}.obj").exists()]
    imports = [f"build/{Path(library).stem}.lib" if library.endswith(".def") else library
               for library in config.get("imports", ["lib/win32sdk/KERNEL32.LIB"])] + ["build/lmgr326b.lib"]
    # (the matching units from their compiled objects, as the exact build links them: a split unit's data alone may
    # not give the original's layout)
    matching = set(config.get("matching", []))
    good = []
    for unit in chosen:
        inputs = [f"build/{version}/obj/sections.obj", *resources]
        for u in units:
            if u in LIBRARY_OBJECTS:
                inputs.append(LIBRARY_OBJECTS[u])
            else:
                inputs.append(f"build/{version}/{'compiled' if u == unit or u in matching else 'obj'}/{u}.obj")
        run = subprocess.run([sys.executable, "tools/link.py", version, f"build/{version}/probe.exe", *inputs, *imports],
                             capture_output=True, text=True)
        if run.returncode == 0:
            good.append(unit)
            print(f"OK   {unit}", flush=True)
        else:
            lines = run.stderr.strip().splitlines()
            reason = next((line.strip() for line in lines if "differs at" in line), "does not link")
            print(f"BAD  {unit}: {reason}", flush=True)
    Path(f"build/{version}/ok").unlink(missing_ok=True)
    print(f"{len(good)} of {len(chosen)} give the original:", json.dumps(good))


if __name__ == "__main__":
    main()
