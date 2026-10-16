"""Assemble held-out candidates per PREREGISTRATION.md (+ amendment 1). Parse-only; nothing third-party runs.

Usage: python -I build_items.py <dl-root> <work-dir>
Reads work/{py-defs,js-defs,pydict-defs,labels-manual}.json; writes work/candidates.json.
"""
import ast, json, os, re, sys

dl, work = sys.argv[1], sys.argv[2]
J = lambda f: json.load(open(os.path.join(work, f), encoding='utf-8'))
py, js, pd, manual = J('py-defs.json'), J('js-defs.json'), J('pydict-defs.json'), J('labels-manual.json')
buckets = manual.get('msb_oos_buckets', {})

COMMITS = {'msb': ('dongsenzhang/MSB', 'c1d6a70171e4d2c44c87a2ae909d13df00c6aa8d'),
           'appsecco': ('appsecco/vulnerable-mcp-servers-lab', '47b7f2082261136b667daa7be9273698e66e479e'),
           'mcpsecbench': ('AIS2Lab/MCPSecBench', '7612c5a3e811dcf01f64e4f2bb324591a2feaaf4')}


def src_ref(file, line):
    top, rest = file.split('/', 1)
    repo, commit = COMMITS[top]
    return f'{repo}@{commit[:7]}:{rest}#L{line}'


items, excluded, not_extracted, notes = [], [], [], []
MSB = 'msb/data/tools/attack_tools/'
by_file = {}
for d in py:
    by_file.setdefault(d['file'], []).append(d)

# ---- MSB file-based kinds -------------------------------------------------------------------------
VARIANTS = ['name_overlap', 'out_of_scope_parameter', 'preference_manipulation',
            'preference_manipulation-out_of_scope_parameter', 'tool_transfer']
servers = {}  # server dir -> base file (tool-bearing file without a variant suffix), path order
for f in sorted(by_file):
    if not f.startswith(MSB):
        continue
    sdir, base = f.rsplit('/', 1)
    stem = base[:-3]
    if not any(stem.endswith('-' + v) for v in VARIANTS):
        servers.setdefault(sdir, f)
for sdir, basef in servers.items():
    base_tools = {d['tool']['name']: d for d in by_file[basef]}
    base_params = {p for d in by_file[basef] for p in d['tool']['inputSchema']['properties']}
    stem = basef.rsplit('/', 1)[1][:-3]
    for v in VARIANTS:
        vf = f'{sdir}/{stem}-{v}.py'
        if vf not in by_file:
            continue
        for d in by_file[vf]:
            t = d['tool']
            b = base_tools.get(t['name'])
            if b is not None and b['tool'] == t:
                notes.append(f'MSB {vf}: `{t["name"]}` identical to the base definition, not an item (rule as written)')
                continue
            ref = src_ref(vf, d['lineno'])
            if v == 'tool_transfer':
                excluded.append({'source': ref, 'name': t['name'], 'why': 'tool transfer (response-stage; runtime benchmark)'})
                continue
            item = {'source': ref, 'origin': 'msb-file', 'variant': v, 'tool': t}
            if 'out_of_scope_parameter' in v:
                extra = [p for p in t['inputSchema']['properties'] if p not in base_params]
                item['oos_param'] = extra
                item['oos_bucket'] = [buckets.get(p) for p in extra]
            items.append(item)

# ---- MSB prompt injection (amendment 1) -------------------------------------------------------------
tmpl_src = open(os.path.join(dl, 'msb/data/prompt_template.py'), encoding='utf-8').read()
TEMPLATE = None
for node in ast.parse(tmpl_src).body:
    if isinstance(node, ast.Assign) and getattr(node.targets[0], 'id', '') == 'PROMPT_INJECTION_TEMPLATE':
        TEMPLATE = ast.literal_eval(node.value)
goals = [json.loads(l)['implementation'] for l in open(os.path.join(dl, 'msb/data/attack_task.jsonl'), encoding='utf-8') if l.strip()]
hosts = list(servers.items())  # path order
for i, goal in enumerate(goals):
    sdir, basef = hosts[i]
    host = by_file[basef][0]  # first tool in file order
    content = TEMPLATE.replace('{goal}', goal)
    desc = host['tool']['description']
    parts = desc.split('Args:', 1)
    args_part = f'Args:{parts[1]}' if len(parts) > 1 else ''
    # prompt_injection: MSB's disabled code — rstrip().endswith('\n') is never true, so plain concatenation.
    t = json.loads(json.dumps(host['tool']))
    t['description'] = parts[0] + content + args_part
    items.append({'source': src_ref(basef, host['lineno']) + f' + attack_task.jsonl[{i}] via PROMPT_INJECTION_TEMPLATE',
                  'origin': 'msb-pi', 'variant': 'prompt_injection', 'goal_index': i, 'tool': t})
    lines = args_part.split('\n')
    if args_part and len(lines) > 1:
        lines[1] += f' {content}'
        t2 = json.loads(json.dumps(host['tool']))
        t2['description'] = parts[0] + '\n'.join(lines)
        items.append({'source': src_ref(basef, host['lineno']) + f' + attack_task.jsonl[{i}] via PROMPT_INJECTION_TEMPLATE',
                      'origin': 'msb-pi', 'variant': 'prompt_injection-parameter_description', 'goal_index': i, 'tool': t2})
    else:
        excluded.append({'source': src_ref(basef, host['lineno']), 'name': host['tool']['name'],
                         'why': f'parameter-description PI, goal {i}: host tool has no `Args:` line to inject into (MSB injects nothing)'})
notes.append('MSB PI hosts (servers in path order, base files): ' + ', '.join(f'goal {i} -> {hosts[i][0].split("/")[-1]}:{by_file[hosts[i][1]][0]["tool"]["name"]}' for i in range(len(goals))))
if len(hosts) > len(goals):
    notes.append('MSB servers without a PI goal (only 5 goals): ' + ', '.join(h[0].split('/')[-1] for h in hosts[len(goals):]))

# ---- appsecco / MCPSecBench (manual labels) -----------------------------------------------------------
others = [(d['file'], d['lineno'], d['tool']) for d in py if not d['file'].startswith('msb/')]
for d in js + pd:
    f = d['file'].replace('\\', '/').split('/dl/')[-1]
    if 'tool' in d:
        others.append((f, d['line'], d['tool']))
    else:
        not_extracted.append({'source': src_ref(f, d['line']), 'why': d['not_extractable']})
for f, line, t in others:
    lab = manual.get(f, {})
    l = lab.get(t['name']) or lab.get('*')
    if l is None:
        raise SystemExit(f'UNLABELLED: {f} {t["name"]}')
    if 'excluded' in l:
        excluded.append({'source': src_ref(f, line), 'name': t['name'], 'why': f"{l['excluded']}: {l['reason']}"})
        continue
    item = {'source': src_ref(f, line), 'origin': f.split('/')[0], 'variant': l['kind'], 'tool': t, 'label_reason': l['reason']}
    if l['kind'] == 'oos':
        item['oos_param'] = [l['oos_param']]
        item['oos_bucket'] = [buckets.get(l['oos_param'])]
    items.append(item)

# ---- kind + claim ------------------------------------------------------------------------------------
def classify(it):
    v = it['variant']
    if v in ('prompt_injection', 'pi-description'):
        return 'prompt injection in tool description', True
    if v == 'prompt_injection-parameter_description':
        return 'prompt injection in parameter description', True
    if v in ('name_overlap', 'name-collision'):
        return 'name collision / overlap / squatting', False
    if v == 'preference_manipulation':
        return 'preference manipulation', False
    if 'oos' in v or 'out_of_scope' in v:
        bs = set(it.get('oos_bucket') or [None])
        if None in bs or len(bs) != 1:
            return 'UNASSIGNED out-of-scope bucket', None
        b = bs.pop()
        prefix = 'preference manipulation + ' if v.startswith('preference') else ''
        return prefix + ('out-of-scope parameter: credentials/history' if b == 'credentials' else 'out-of-scope parameter: other data'), b == 'credentials'
    raise SystemExit(f'unknown variant {v}')


for n, it in enumerate(items):
    it['kind'], it['claimed'] = classify(it)
    it['subgroup'] = 'msb-pi-reconstructed' if it['origin'] == 'msb-pi' else 'main'
for d in [d for d in py if d['file'].startswith(MSB)]:
    pass
json.dump({'items': items, 'excluded': excluded, 'not_extracted': not_extracted, 'notes': notes},
          open(os.path.join(work, 'candidates.json'), 'w', encoding='utf-8'), indent=1, ensure_ascii=False)

from collections import Counter
print('items', len(items), 'excluded', len(excluded), 'not_extracted', len(not_extracted))
for k, v in sorted(Counter((i['subgroup'], i['kind'], i['claimed']) for i in items).items()):
    print('  ', v, k)
for n in notes:
    print('NOTE', n)
oos = {}
for it in items:
    for p in it.get('oos_param') or []:
        if buckets.get(p) is None:
            m = re.search(rf'^\s*{re.escape(p)}\b.*$', it['tool']['description'], re.M)
            oos.setdefault(p, set()).add(m.group(0).strip() if m else '(no line in description)')
for p, lines in oos.items():
    print('OOS param needing a bucket:', p)
    for l in sorted(lines):
        print('     ', l[:200])
