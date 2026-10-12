import { describe, expect, it } from 'vitest';
import { ConfigSchema } from '../src/config/schema.js';
import { PolicyEngine } from '../src/policy/engine.js';
import { TaintEngine } from '../src/taint/engine.js';
import { lintPolicy, schemaArgNames } from '../src/policy/lint.js';
import { compile } from '../src/policy/cel.js';
import { globMatch } from '../src/policy/glob.js';

function cfg(servers: Record<string, unknown>, extra: Record<string, unknown> = {}) {
  return ConfigSchema.parse({ version: 1, servers, ...extra });
}

const mailServer = {
  command: 'x',
  tools: {
    send_email: {
      effect: 'egress',
      integrity: 'trusted',
      rules: [
        { deny: 'containsSecret(arg.body)' },
        { ask: 'context.integrity == "untrusted"' },
        { allow: 'arg.to in ["me@corp.example"]' },
      ],
    },
  },
};

function engine(servers: Record<string, unknown>, extra: Record<string, unknown> = {}): TaintEngine {
  const c = cfg(servers, extra);
  return new TaintEngine(c, new PolicyEngine(c));
}

const CANARY = 'AKIAPOLICYCANARY0001'.slice(0, 20);
const text = (t: string) => ({ content: [{ type: 'text', text: t }] });

describe('glob', () => {
  it.each([
    ['/home/u/.env.local', '**/.env*', true],
    ['/a/b/readme.md', '**/.env*', false],
    ['config/app.yaml', 'config/*.yaml', true],
    ['config/sub/app.yaml', 'config/*.yaml', false],
    ['config/sub/app.yaml', 'config/**', true],
  ])('%s vs %s', (v, p, expected) => {
    expect(globMatch(v, p)).toBe(expected);
  });
  it('has no catastrophic backtracking on adversarial input', () => {
    const t0 = performance.now();
    globMatch('a'.repeat(100000) + '/x', '**/*b*c*d');
    expect(performance.now() - t0).toBeLessThan(500);
  });
});

describe('PolicyEngine: deny > ask > allow', () => {
  it('denies when a secret is present regardless of other allows', () => {
    const d = engine({ mail: mailServer }).decide('mail', 'send_email', 'mail__send_email', { to: 'me@corp.example', body: 'key ' + CANARY });
    expect(d).toMatchObject({ verdict: 'deny', rule: 'policy' });
  });

  it('allows an explicitly allowed recipient with no secret', () => {
    expect(engine({ mail: mailServer }).decide('mail', 'send_email', 'mail__send_email', { to: 'me@corp.example', body: 'hello' }).verdict).toBe('allow');
  });

  it('asks when the context is untrusted (ask beats allow)', () => {
    const e = engine({ web: { command: 'x', tools: { fetch: { effect: 'read', integrity: 'untrusted' } } }, mail: mailServer });
    e.ingest('tool', 'web', 'web__fetch', 'fetch', text('some page'));
    const d = e.decide('mail', 'send_email', 'mail__send_email', { to: 'me@corp.example', body: 'hi' });
    expect(d).toMatchObject({ verdict: 'ask', rule: 'policy', enforced: true });
    expect(d.reason).toContain('confirmation');
  });
});

describe('PolicyEngine: fail-closed on missing argument (owner note #1)', () => {
  it('denies and records when a rule references an argument absent from the call', () => {
    const d = engine({ mail: mailServer }).decide('mail', 'send_email', 'mail__send_email', { to: 'me@corp.example' });
    expect(d.verdict).toBe('deny');
    expect(d.rule).toBe('policy');
    expect(d.policy?.errors[0]?.message).toMatch(/not in the call: body/);
  });
});

describe('PolicyEngine: declassify lifts the trifecta invariant', () => {
  const servers = {
    web: { command: 'x', tools: { fetch: { effect: 'read', integrity: 'untrusted' } } },
    files: { command: 'x', defaults: { effect: 'read', integrity: 'trusted' } },
    mail: { command: 'x', tools: { send_email: { effect: 'egress', integrity: 'trusted' } } },
  };
  const declassify = [{ id: 'own-inbox', tool: 'mail__send_email', when: 'arg.to == "me@corp.example"', reason: 'user inbox; accepted risk' }];

  function trifectaEngine(extra: Record<string, unknown>) {
    const e = engine(servers, extra);
    e.ingest('tool', 'web', 'web__fetch', 'fetch', text('untrusted page'));
    e.ingest('tool', 'files', 'files__read', 'read', text('AWS_ACCESS_KEY_ID=' + CANARY));
    return e;
  }

  it('blocks the trifecta without a declassify', () => {
    expect(trifectaEngine({}).decide('mail', 'send_email', 'mail__send_email', { to: 'me@corp.example' }).verdict).toBe('deny');
  });

  it('allows it when a matching declassify entry applies, recording the exception', () => {
    const d = trifectaEngine({ declassify }).decide('mail', 'send_email', 'mail__send_email', { to: 'me@corp.example' });
    expect(d.verdict).toBe('allow');
    expect(d.reason).toContain("declassify 'own-inbox'");
  });

  it('does not lift the invariant when the declassify condition is false', () => {
    expect(trifectaEngine({ declassify }).decide('mail', 'send_email', 'mail__send_email', { to: 'attacker@evil.example' }).verdict).toBe('deny');
  });
});

describe('PolicyEngine: cost budget', () => {
  it('denies when arguments exceed the size budget', () => {
    const d = engine({ mail: mailServer }).decide('mail', 'send_email', 'mail__send_email', { to: 'me@corp.example', body: 'x'.repeat(300 * 1024) });
    expect(d.verdict).toBe('deny');
    expect(d.policy?.errors[0]?.message).toMatch(/too large/);
  });
});

describe('lintPolicy', () => {
  const schemas = new Map([['mail__send_email', new Set(['to', 'body'])]]);
  it('passes clean rules', () => {
    expect(lintPolicy(cfg({ mail: mailServer }), schemas)).toEqual([]);
  });
  it('errors on a rule referencing an undeclared argument', () => {
    const bad = { command: 'x', tools: { send_email: { effect: 'egress', rules: [{ deny: 'arg.subject == "x"' }] } } };
    expect(lintPolicy(cfg({ mail: bad }), schemas).some((i) => i.level === 'error' && /subject/.test(i.message))).toBe(true);
  });
  it('errors on rules for a tool no server offers', () => {
    expect(lintPolicy(cfg({ mail: mailServer }), new Map()).some((i) => i.level === 'error' && /no configured server offers/.test(i.message))).toBe(true);
  });
  it('warns on precision-mode from()', () => {
    const p = { command: 'x', tools: { send_email: { effect: 'egress', rules: [{ deny: 'from(arg.to, "untrusted")' }] } } };
    expect(lintPolicy(cfg({ mail: p }), schemas).some((i) => i.level === 'warning' && /precision-mode/.test(i.message))).toBe(true);
  });
  it('schemaArgNames reads top-level properties', () => {
    expect(schemaArgNames({ type: 'object', properties: { a: {}, b: {} } })).toEqual(new Set(['a', 'b']));
  });
});

describe('compile', () => {
  it('extracts arg refs and rejects a parse error', () => {
    expect([...compile('arg.to in ["x"] && arg.body != ""').argRefs].sort()).toEqual(['body', 'to']);
    expect(() => compile('arg.to ===')).toThrow();
  });
});
