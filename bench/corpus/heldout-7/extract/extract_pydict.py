"""Parse-only: dict literals with name/description/inputSchema keys (hand-rolled JSON-RPC servers)."""
import ast, json, sys
path, out = sys.argv[1], sys.argv[2]
res = []
for n in ast.walk(ast.parse(open(path, encoding='utf-8').read())):
    if isinstance(n, ast.Dict):
        keys = [k.value for k in n.keys if isinstance(k, ast.Constant)]
        if {'name', 'description', 'inputSchema'} <= set(keys):
            try:
                d = ast.literal_eval(n)
                res.append({'file': path, 'line': n.lineno, 'tool': {k: d[k] for k in ('name', 'description', 'inputSchema')}})
            except ValueError as e:
                res.append({'file': path, 'line': n.lineno, 'not_extractable': str(e)})
json.dump(res, open(out, 'w', encoding='utf-8'), indent=1, ensure_ascii=False)
for r in res: print(r['line'], r.get('tool', {}).get('name') or r['not_extractable'])
