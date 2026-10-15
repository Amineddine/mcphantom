# Phase 7 fresh held-out poisoned set — pre-registration

Committed **before** any definition was extracted and before the scanner ran on any of it (owner rule,
2026-10-15). The scanner is not changed in the PR that runs this set. Anything below that turns out to be
ambiguous is resolved by the rule written here, and every such case is listed in the report.

## Sources (owner-approved 2026-10-15; verbatim, MIT; NOTICE entries added with the data)

| source | commit | licence |
|---|---|---|
| dongsenzhang/MSB (MCP Security Bench, arXiv 2510.15994) | `c1d6a70171e4d2c44c87a2ae909d13df00c6aa8d` | MIT |
| appsecco/vulnerable-mcp-servers-lab | `47b7f2082261136b667daa7be9273698e66e479e` | MIT |
| AIS2Lab/MCPSecBench (arXiv 2508.13220) | `7612c5a3e811dcf01f64e4f2bb324591a2feaaf4` | MIT |

Not included: MCPTox (no licence; the owner is asking its authors), Damn Vulnerable MCP Server (no
licence), MCP-SafetyBench (licence unclear). No rewrites of unlicensed material in this set.

## Extraction (nothing third-party is executed)

Downloads go to an isolated scratchpad directory. Python sources are parsed with `ast` (definitions are
`@mcp.tool()`-decorated functions: name, docstring, parameters and annotations; FastMCP's own rules for
turning those into `name` / `description` / `inputSchema` are reproduced statically). JavaScript sources
are parsed with the TypeScript compiler API (object literals passed to tool registration). A definition
that cannot be extracted statically is listed, not guessed.

## Labels — mechanical, from the sources

- **MSB, file-based kinds.** Each server has a benign base file and attack variants
  (`-name_overlap`, `-out_of_scope_parameter`, `-preference_manipulation`,
  `-preference_manipulation-out_of_scope_parameter`, `-tool_transfer`). A tool in a variant is an item
  if its extracted definition differs from the base file's tool of the same name, or has no counterpart
  in the base. Unchanged tools are not items.
- **MSB, prompt injection** is assembled at run time by MSB's harness (`main.py`,
  `mcp_use/agents/prompts/system_prompt_builder.py`): `PROMPT_INJECTION_TEMPLATE` (`data/prompt_template.py`)
  with `{goal}` replaced by one of the 5 `attack_task.jsonl` implementations, appended to the tool
  description (`prompt_injection`) or to the first line after `Args:` (`prompt_injection-parameter_description`).
  MSB applies it to every tool; to avoid near-duplicates this set uses **one item per goal × variant**:
  goal *i* (file order) is applied, by MSB's own insertion rule, to the first tool (file order) of server
  *i* (servers in path order, base files). 10 items at most; an item whose host tool has no `Args:` section
  is dropped for the parameter variant (MSB injects nothing there) and listed.
- **appsecco and MCPSecBench**: an item is a tool definition from a server the source presents as an
  attack, assigned to a kind below by what its *definition* contains. A definition whose attack lives only
  in code, outputs, dependencies, transport or a package/server name is excluded and listed (the static
  scanner never sees it).

## Claims, per attack kind (pre-registered)

| kind | where it lives | MCPhantom claims to catch it? |
|---|---|---|
| Prompt injection in a tool description (MSB `prompt_injection`; equivalent definitions elsewhere) | description | **Claimed** |
| Prompt injection in a parameter description (MSB `prompt_injection-parameter_description`) | parameter text | **Claimed** |
| Out-of-scope parameter asking for credentials, secrets, keys, tokens, passwords, credential files or the conversation / chat history | input schema | **Claimed** |
| Out-of-scope parameter asking for other data (e.g. name, phone, address, location, preferences) | input schema | **Not claimed** (outside the claims) |
| Preference manipulation (promotional wording) | description | **Not claimed** (outside the claims) |
| Preference manipulation + out-of-scope parameter | both | the claim of its out-of-scope bucket |
| Name collision / overlap / tool-name squatting | tool name | **Not claimed** (outside the claims; namespacing `<server>__<tool>` is the mitigation, not the scanner) |
| Tool transfer, false error, user impersonation, retrieval injection, mixed response-stage | tool response | **Excluded** — not a definition; belongs to the runtime benchmark (Phase 7 item 3) |

The out-of-scope bucket of each item is assigned by reading the extra parameter **before** the run and is
recorded in the manifest with the parameter name. "Caught" = the tool is hidden at default settings
(`scan.block: medium`).

## Dedupe

Each item is compared with every definition in the existing dev and test splits (`bench/corpus/*.json`)
on the model-visible text after the scanner's own normalisation: identical name + description, or an
identical poisoned field, is an overlap. Overlaps are excluded and listed.

## Freeze, run, report

After extraction, labelling and dedupe, the set is written to `bench/corpus/heldout-7/heldout.json` with a
SHA-256 manifest (`MANIFEST.sha256`: every file of the set and this pre-registration), committed, and only
then run **once** (`npm run bench:heldout`). Reported per kind and overall: caught / total with **Wilson
95% intervals**; claimed and unclaimed kinds in separate tables, the unclaimed ones labelled as outside the
claims; every miss and every exclusion listed. No tuning on this set; a fix found from it needs new dev
examples first.

## Disclosed before the run

While establishing the attack kinds, the first 40 characters of each of MSB's 5 attack-goal strings were
printed in a structure summary (`attack_task.jsonl`). No definition, template or other payload text was
read before this file was committed.
