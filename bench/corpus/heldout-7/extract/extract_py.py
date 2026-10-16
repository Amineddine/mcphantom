"""Parse-only extraction of @mcp.tool() definitions (nothing is imported or executed).

Usage: python -I extract_py.py <dl-root> <out.json>

For each Python file of the three sources, records every tool-decorated function that the file actually
registers: module-level decorated functions, plus (for files that define `register_tools*()` functions)
only the functions inside the register function the module calls at top level. Raw facts only: name,
decorator kwargs, raw docstring, parameters (name, annotation source, default source).
"""
import ast, json, os, sys, glob

root, out_path = sys.argv[1], sys.argv[2]
FILES = sorted(
    glob.glob(os.path.join(root, 'msb/data/tools/attack_tools/*/*/*.py'))
    + glob.glob(os.path.join(root, 'appsecco/*/*.py'))
    + glob.glob(os.path.join(root, 'mcpsecbench/code/*.py'))
)


def is_tool_dec(dec):
    f = dec.func if isinstance(dec, ast.Call) else dec
    return isinstance(f, ast.Attribute) and f.attr == 'tool'


def dec_kwargs(dec):
    if not isinstance(dec, ast.Call):
        return {}
    out = {}
    for kw in dec.keywords:
        out[kw.arg] = ast.literal_eval(kw.value) if isinstance(kw.value, ast.Constant) else {'unparsed': ast.unparse(kw.value)}
    if dec.args:
        out['_positional'] = [ast.unparse(a) for a in dec.args]
    return out


def tool_from(fn, dec):
    a = fn.args
    params = []
    pos = a.posonlyargs + a.args
    defaults = [None] * (len(pos) - len(a.defaults)) + list(a.defaults)
    for arg, d in zip(pos, defaults):
        params.append({'name': arg.arg, 'annotation': ast.unparse(arg.annotation) if arg.annotation else None,
                       'default': ast.unparse(d) if d is not None else None, 'has_default': d is not None})
    for arg, d in zip(a.kwonlyargs, a.kw_defaults):
        params.append({'name': arg.arg, 'annotation': ast.unparse(arg.annotation) if arg.annotation else None,
                       'default': ast.unparse(d) if d is not None else None, 'has_default': d is not None})
    if a.vararg or a.kwarg:
        params.append({'name': '*varargs', 'unsupported': True})
    return {'function': fn.name, 'lineno': fn.lineno, 'decorator': dec_kwargs(dec),
            'docstring_raw': ast.get_docstring(fn, clean=False), 'params': params,
            'async': isinstance(fn, ast.AsyncFunctionDef)}


def decorated_in(body):
    out = []
    for node in body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                if is_tool_dec(dec):
                    out.append(tool_from(node, dec))
    return out


records = []
for path in FILES:
    rel = os.path.relpath(path, root).replace(os.sep, '/')
    src = open(path, encoding='utf-8').read()
    tree = ast.parse(src)
    flavour = 'fastmcp2' if 'from fastmcp import FastMCP' in src else ('mcp-fastmcp' if 'mcp.server.fastmcp' in src else None)
    top = decorated_in(tree.body)
    # Register functions and which ones the module calls (top level or under `if __name__ == ...`).
    regs = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef) and decorated_in(n.body)}
    called = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in regs:
            called.append(node.func.id)
    nested = []
    for name in called:
        nested += [dict(t, register_fn=name) for t in decorated_in(regs[name].body)]
    # Decorated functions anywhere else (e.g. in a class or an uncalled function) are reported, not used.
    all_dec = sum(1 for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(is_tool_dec(d) for d in n.decorator_list))
    records.append({'file': rel, 'flavour': flavour, 'tools': top + nested, 'register_called': called,
                    'decorated_total': all_dec, 'unused_decorated': all_dec - len(top) - len(nested)})

json.dump(records, open(out_path, 'w', encoding='utf-8'), indent=1, ensure_ascii=False)
ann = {}
for r in records:
    for t in r['tools']:
        for p in t['params']:
            ann[(p.get('annotation'), p.get('default') is not None)] = ann.get((p.get('annotation'), p.get('default') is not None), 0) + 1
for r in records:
    if r['tools'] or r['decorated_total']:
        print(f"{r['file']}: flavour={r['flavour']} tools={len(r['tools'])} register={r['register_called']} unused_decorated={r['unused_decorated']}")
print('annotation shapes (annotation, has_default): count')
for k, v in sorted(ann.items(), key=lambda kv: str(kv[0])):
    print('  ', k, v)
print('defaults seen:', sorted({p.get('default') for r in records for t in r['tools'] for p in t['params'] if p.get('default')}))
print('decorator kwargs seen:', sorted({k for r in records for t in r['tools'] for k in t['decorator']}))
