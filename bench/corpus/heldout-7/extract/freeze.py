"""Write bench/corpus/heldout-7/{heldout.json, extract/*, MANIFEST.sha256}. Usage: python -I freeze.py <scratch> <repo>"""
import hashlib, json, os, shutil, sys

scratch, repo = sys.argv[1], sys.argv[2]
out = os.path.join(repo, 'bench', 'corpus', 'heldout-7')
d = json.load(open(os.path.join(scratch, 'work', 'deduped.json'), encoding='utf-8'))
sha = lambda p: hashlib.sha256(open(p, 'rb').read()).hexdigest()

items = []
for n, it in enumerate(d['items'], 1):
    rec = {'id': f'h7-{n:03d}', 'source': it['source'], 'kind': it['kind'], 'claimed': it['claimed'],
           'subgroup': it['subgroup'], 'origin_variant': it['variant']}
    for k in ('oos_param', 'oos_bucket', 'goal_index', 'label_reason'):
        if k in it:
            rec[k] = it[k]
    rec['tool'] = it['tool']
    items.append(rec)

heldout = {
    'description': 'Phase 7 fresh held-out poisoned set. Frozen before the scanner ran on it; run once. '
                   'Rules: PREREGISTRATION.md (with amendment 1). Labels assigned before the run.',
    'frozen': '2026-10-16',
    'sources': [
        {'repo': 'dongsenzhang/MSB', 'commit': 'c1d6a70171e4d2c44c87a2ae909d13df00c6aa8d', 'licence': 'MIT', 'tarball_sha256': sha(os.path.join(scratch, 'dl', 'msb.tar.gz'))},
        {'repo': 'appsecco/vulnerable-mcp-servers-lab', 'commit': '47b7f2082261136b667daa7be9273698e66e479e', 'licence': 'MIT', 'tarball_sha256': sha(os.path.join(scratch, 'dl', 'appsecco.tar.gz'))},
        {'repo': 'AIS2Lab/MCPSecBench', 'commit': '7612c5a3e811dcf01f64e4f2bb324591a2feaaf4', 'licence': 'MIT', 'tarball_sha256': sha(os.path.join(scratch, 'dl', 'mcpsecbench.tar.gz'))},
    ],
    'caught_means': 'the tool is hidden at default settings (scan.block: medium)',
    'items': items,
    'excluded': d['excluded'],
    'not_extracted': d['not_extracted'],
    'overlaps_with_dev_test': d['overlaps'],
    'notes': d['notes'],
}
with open(os.path.join(out, 'heldout.json'), 'w', encoding='utf-8', newline='\n') as f:
    json.dump(heldout, f, indent=1, ensure_ascii=False)
    f.write('\n')

ex = os.path.join(out, 'extract')
os.makedirs(ex, exist_ok=True)
for name in ('extract_py.py', 'build_py.py', 'extract_js.cjs', 'extract_pydict.py', 'build_items.py', 'dedupe.mts', 'freeze.py'):
    shutil.copyfile(os.path.join(scratch, 'scripts', name), os.path.join(ex, name))
shutil.copyfile(os.path.join(scratch, 'work', 'labels-manual.json'), os.path.join(ex, 'labels-manual.json'))

files = sorted(
    os.path.relpath(os.path.join(dp, f), out).replace(os.sep, '/')
    for dp, _, fs in os.walk(out) for f in fs if f != 'MANIFEST.sha256'
)
with open(os.path.join(out, 'MANIFEST.sha256'), 'w', encoding='utf-8', newline='\n') as f:
    for rel in files:
        f.write(f'{sha(os.path.join(out, rel))}  {rel}\n')
print(open(os.path.join(out, 'MANIFEST.sha256'), encoding='utf-8').read())
print(len(items), 'items;', len(d['excluded']), 'excluded;', len(d['not_extracted']), 'not extracted;', len(d['overlaps']), 'overlaps')
