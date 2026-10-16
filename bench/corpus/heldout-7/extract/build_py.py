"""Turn py-raw.json into MCP tool definitions, reproducing FastMCP's rules statically.

Usage: python -I build_py.py <py-raw.json> <out.json>

mcp.server.fastmcp (mcp 1.13.1, pydantic 2.11.7): description = fn.__doc__ (raw); inputSchema =
<fn>Arguments model JSON schema: per field {"title": Name.Title, ...}, model title "<fn>Arguments",
"required" = params without a default; `Context` params are omitted; an unannotated param gets
{"title": <raw name>, "type": "string"} (mcp's WithJsonSchema).
fastmcp 2.12.2: description = inspect.getdoc(fn); same schema with every "title" pruned.
Python 3.13+ (MCPSecBench requires it): __doc__ is dedented by the compiler; reproduced by compiling a
synthetic function holding only the docstring constant (no third-party code runs).
"""
import inspect, json, sys

raw_path, out_path = sys.argv[1], sys.argv[2]
records = json.load(open(raw_path, encoding='utf-8'))

TYPE = {
    'str': {'type': 'string'}, 'int': {'type': 'integer'}, 'float': {'type': 'number'},
    'bool': {'type': 'boolean'}, 'list': {'items': {}, 'type': 'array'},
    'Optional[str]': {'anyOf': [{'type': 'string'}, {'type': 'null'}]},
    'Union[str, int]': {'anyOf': [{'type': 'string'}, {'type': 'integer'}]},
}
DEFAULT = {'None': None, '1': 1, '5': 5, '10': 10, '30': 30}


def py313_doc(doc):
    ns = {}
    exec(compile('def f():\n    ' + repr(doc) + '\n', '<doc>', 'exec'), {}, ns)  # noqa: S102 — our own literal
    return ns['f'].__doc__


def pyd_title(name):
    return name.title().replace('_', ' ')


def build(rec, t):
    flavour = rec['flavour']
    doc = t['docstring_raw']
    if flavour == 'fastmcp2':
        desc = inspect.cleandoc(doc) if doc else ''
    elif rec['file'].startswith('mcpsecbench/'):
        desc = py313_doc(doc) if doc else ''
    else:
        desc = doc or ''
    props, required, problems = {}, [], []
    for p in t['params']:
        if p.get('unsupported'):
            problems.append('varargs')
            continue
        if p['annotation'] == 'Context':
            continue
        if p['annotation'] is None:
            s = {'title': p['name'], 'type': 'string'}
        elif p['annotation'] in TYPE:
            s = dict(TYPE[p['annotation']])
            s['title'] = pyd_title(p['name'])
        else:
            problems.append(f"annotation {p['annotation']}")
            continue
        if p['has_default']:
            if p['default'] not in DEFAULT:
                problems.append(f"default {p['default']}")
                continue
            s['default'] = DEFAULT[p['default']]
        else:
            required.append(p['name'])
        # pydantic key order: anyOf/items/type first as in TYPE, then default, title.
        order = [k for k in ('anyOf', 'default', 'items', 'title', 'type') if k in s]
        props[p['name']] = {k: s[k] for k in order}
    schema = {'properties': props, 'title': f"{t['function']}Arguments", 'type': 'object'}
    if required:
        schema = {'properties': props, 'required': required, 'title': f"{t['function']}Arguments", 'type': 'object'}
    if flavour == 'fastmcp2':
        for v in props.values():
            v.pop('title', None)
        schema.pop('title', None)
    name = t['decorator'].get('name', t['function'])
    return {'name': name, 'description': desc, 'inputSchema': schema}, problems


out = []
for rec in records:
    for t in rec['tools']:
        tool, problems = build(rec, t)
        out.append({'file': rec['file'], 'function': t['function'], 'lineno': t['lineno'],
                    'register_fn': t.get('register_fn'), 'flavour': rec['flavour'], 'tool': tool,
                    'extract_problems': problems})
json.dump(out, open(out_path, 'w', encoding='utf-8'), indent=1, ensure_ascii=False)
print(len(out), 'definitions;', sum(1 for o in out if o['extract_problems']), 'with extraction problems')
for o in out:
    if o['extract_problems']:
        print('  ', o['file'], o['function'], o['extract_problems'])
