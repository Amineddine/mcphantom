/**
 * Regressions for defects found in the Opus-5.5 audit of Phases 2–5 (docs/reviews/audit-2026-10.md).
 * Each test was written to FAIL against the pre-audit code and pass after the fix.
 */
import fs from 'node:fs';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { ElicitRequestSchema, type Prompt, type Tool } from '@modelcontextprotocol/sdk/types.js';
import { RugpullChecker, pinsFrom } from '../src/rugpull/checker.js';
import { ensureKey } from '../src/rugpull/lockfile.js';
import { scanTool } from '../src/scanner/scan.js';
import { compile } from '../src/policy/cel.js';
import { connectDirect, fixtureServer, startGateway, tempDir, textOf, type GatewayHarness } from './helpers.js';

const harnesses: GatewayHarness[] = [];
const dirs: string[] = [];
afterEach(async () => {
  await Promise.all(harnesses.splice(0).map((h) => h.close()));
  for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
});
async function gw(...a: Parameters<typeof startGateway>): Promise<GatewayHarness> {
  const h = await startGateway(...a);
  harnesses.push(h);
  return h;
}
function customServer(tools: Tool[], extra: Record<string, unknown> = {}): Record<string, unknown> {
  const f = path.join(tempDir('mcphantom-audit-'), 'tools.json');
  dirs.push(path.dirname(f));
  fs.writeFileSync(f, JSON.stringify(tools));
  return { ...fixtureServer('custom', { env: { CUSTOM_TOOLS_FILE: f } }), ...extra };
}
const noScan = { scan: { enabled: false, block: 'medium', mode: 'hide' } };

describe('AUD-1: pinned prompts must match by their original name', () => {
  it('a prompt approved via pinsFrom is served, not hidden as "new"', async () => {
    const direct = await connectDirect('everything');
    const prompts: Prompt[] = (await direct.listPrompts()).prompts;
    const tools: Tool[] = (await direct.listTools()).tools;
    await direct.close();
    const pins = pinsFrom({ fx: tools }, { fx: prompts }, {});
    const h = await gw({ fx: fixtureServer('everything') }, { config: noScan, rugpull: new RugpullChecker(pins, true) });
    expect((await h.client.listPrompts()).prompts.map((p) => p.name)).toEqual(['fx__greet']);
    expect(h.store.events({ kind: 'rugpull' }).filter((e) => e.method === 'prompt')).toHaveLength(0);
  });
});

describe('AUD-2: a policy `ask` must never silently allow', () => {
  const send: Tool = { name: 'send', description: 'send', inputSchema: { type: 'object', properties: { to: { type: 'string' } } } };
  const askServer = () => customServer([send], { tools: { send: { effect: 'egress', integrity: 'trusted', rules: [{ ask: 'arg.to != ""' }] } } });

  it('denies when the client cannot be asked (no elicitation capability)', async () => {
    const h = await gw({ s: askServer() });
    const r = await h.client.callTool({ name: 's__send', arguments: { to: 'x@y.example' } });
    expect((r as { isError?: boolean }).isError).toBe(true);
    expect(textOf(r)).toMatch(/confirmation/i);
  });

  it('forwards only after the user explicitly approves via elicitation', async () => {
    let asked = 0;
    const h = await gw({ s: askServer() }, {
      clientCapabilities: { elicitation: {} },
      setupClient: (c) => {
        c.setRequestHandler(ElicitRequestSchema, () => {
          asked++;
          return { action: 'accept', content: { approve: true } };
        });
      },
    });
    const r = await h.client.callTool({ name: 's__send', arguments: { to: 'x@y.example' } });
    expect(asked).toBe(1);
    expect(textOf(r)).toBe('called send');
  });

  it('denies when the user declines', async () => {
    const h = await gw({ s: askServer() }, {
      clientCapabilities: { elicitation: {} },
      setupClient: (c) => {
        c.setRequestHandler(ElicitRequestSchema, () => ({ action: 'decline' }));
      },
    });
    expect((await h.client.callTool({ name: 's__send', arguments: { to: 'x@y.example' } }) as { isError?: boolean }).isError).toBe(true);
  });
});

describe('AUD-3: renamed argument, rug-pull in OBSERVE mode (owner note #1, the real scenario)', () => {
  it('server renames `to`→`recipient` after approval; observe keeps the tool; the policy fails closed', async () => {
    const before: Tool = { name: 'send', description: 'send', inputSchema: { type: 'object', properties: { to: { type: 'string' } } } };
    const after: Tool = { name: 'send', description: 'send', inputSchema: { type: 'object', properties: { recipient: { type: 'string' } } } };
    const pins = pinsFrom({ s: [before] }, {}, {});
    const h = await gw(
      { s: customServer([after], { tools: { send: { effect: 'egress', integrity: 'trusted', rules: [{ allow: 'arg.to == "ok@corp.example"' }] } } }) },
      { config: { ...noScan, rugpull: { mode: 'observe', on_bad_signature: 'refuse' } }, rugpull: new RugpullChecker(pins, true) },
    );
    expect((await h.client.listTools()).tools.map((t) => t.name)).toContain('s__send'); // observe: kept
    expect(h.store.events({ kind: 'rugpull' }).some((e) => e.outcome === 'flagged')).toBe(true);
    const r = await h.client.callTool({ name: 's__send', arguments: { recipient: 'ok@corp.example' } });
    expect((r as { isError?: boolean }).isError).toBe(true);
    expect(textOf(r)).toMatch(/policy/i);
  });
});

describe('AUD-4: `has(arg.x)` is an explicit optional-argument check, not a required reference', () => {
  it('compile does not count a has() test as a required argument', () => {
    // cc is guarded by has(): optional, not required; still visible to the linter via allArgRefs.
    const guarded = compile('has(arg.cc) && arg.cc == "x"');
    expect([...guarded.argRefs]).toEqual([]);
    expect([...guarded.allArgRefs]).toEqual(['cc']);
    expect([...compile('!has(arg.cc) || arg.to == "x"').argRefs]).toEqual(['to']);
  });
});

describe('AUD-5: HMAC key creation never overwrites an existing key', () => {
  it('a second ensureKey returns the first key', () => {
    const d = tempDir('mcphantom-key-');
    dirs.push(d);
    const a = ensureKey(d).toString('hex');
    const b = ensureKey(d).toString('hex');
    expect(b).toBe(a);
  });
});

describe('AUD-6: an ordinary HTTP/webhook tool description must not be hidden by the scanner', () => {
  it.each([
    'Send a POST request to https://api.example.com/v1/items and return the response.',
    'Post a message to a Slack webhook such as https://hooks.slack.com/services/...',
    'Loads configuration from .env files in the project directory.',
  ])('%s', (description) => {
    expect(scanTool({ name: 't', description, inputSchema: { type: 'object' } }).flagged).toBe(false);
  });
});
