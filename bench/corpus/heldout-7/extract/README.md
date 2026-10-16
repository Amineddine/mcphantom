# How `heldout.json` was built

Parse-only: no third-party code is imported or executed. Run in this order, with the three pinned
tarballs (`heldout.json` → `sources`, SHA-256 included) unpacked into `<dl>/msb`, `<dl>/appsecco` and
`<dl>/mcpsecbench`, and the scripts kept outside `<dl>`:

```sh
python -I extract_py.py     <dl> <work>/py-raw.json        # @mcp.tool() functions (ast)
python -I build_py.py       <work>/py-raw.json <work>/py-defs.json   # FastMCP's name/description/inputSchema rules
node extract_js.cjs <repo>/node_modules/typescript <work>/js-defs.json <dl>/appsecco/*/index.js <dl>/appsecco/*/local-test.js <dl>/appsecco/*/test.js <dl>/mcpsecbench/code/index.js
python -I extract_pydict.py <dl>/appsecco/vulnerable-mcp-server-filesystem-workspace-actions/vulnerable-mcp-server-filesystem-workspace-actions-mcp.py <work>/pydict-defs.json
cp labels-manual.json <work>/
python -I build_items.py    <dl> <work>                    # labels per PREREGISTRATION.md (+ amendment 1)
npx tsx dedupe.mts          <repo> <work>                  # against bench/corpus/*.json, scanner's normalize()
python -I freeze.py         <scratch> <repo>               # heldout.json, this folder, MANIFEST.sha256
```

`labels-manual.json` holds every judgement made by reading a definition (appsecco and MCPSecBench
kinds and exclusions, out-of-scope buckets), each with its reason, written before the run.

FastMCP rules reproduced: `mcp.server.fastmcp` (mcp 1.13.1, pydantic 2.11.7, MSB's lock file) uses the
raw `__doc__` and pydantic titles; `fastmcp` 2.12.2 (MSB's Word server) uses `inspect.getdoc` and prunes
titles. MSB pins Python 3.10 (raw docstrings); MCPSecBench requires Python ≥ 3.13, whose compiler
dedents docstrings (reproduced by compiling a function that holds only the docstring constant); the
appsecco Python server has no version pin and is excluded anyway.
