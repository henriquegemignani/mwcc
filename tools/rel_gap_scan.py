#!/usr/bin/env python3
"""python tools/rel_gap_scan.py: list, for each section the replica does not carry through partial links (`.mwcats.text`,
`extab`, `extabindex`, debug sections) and a few it handles specially (`.init`, `.ctors$10`, `.dtors$10`, `.dtors$15`),
the modules of the Echoes build whose objects have it. Edit the two paths below for another project. Run from anywhere."""
import re, struct, collections, os
os.chdir('F:/programming/decomp/echoes')  # (the project directory)
BS = chr(92)
def secs(path):
    d = open(path, 'rb').read()
    shoff, = struct.unpack('>I', d[32:36]); n, si = struct.unpack('>HH', d[48:52])
    S = [struct.unpack('>10I', d[shoff + i * 40:shoff + i * 40 + 40]) for i in range(n)]
    st = S[si]
    return [d[st[4] + s[0]:d.index(b'\0', st[4] + s[0])].decode() for s in S]
t = re.sub(r' ?\$\r?\n\s*', ' ', open('build.ninja', encoding='utf-8').read())
want = {'.mwcats.text', 'extab', 'extabindex', '.debug', '.line', '.ctors$10', '.dtors$10', '.dtors$15', '.init'}
hits = collections.defaultdict(set)
pat = r'^build (build' + re.escape(BS) + r'G2ME01' + re.escape(BS) + r'([^' + re.escape(BS) + r' ]+)' + re.escape(BS) + r'[^' + re.escape(BS) + r' ]+\.plf):(.*?)ldflags'
for m in re.finditer(pat, t, re.M | re.S):
    for o in re.findall(r'build[^ ]*\.o', m.group(3)):
        try: s = set(secs(o.replace(BS, '/')))
        except Exception: continue
        for w in want & s: hits[w].add(m.group(2))
for w, ms in hits.items(): print(w, len(ms), sorted(ms)[:6])
