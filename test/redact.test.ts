import { describe, expect, it } from 'vitest';
import { findSecrets } from '../src/secrets/detectors.js';
import { Redactor, safeCut, TRUNCATED } from '../src/secrets/redact.js';

const r = new Redactor();

/**
 * Fixture credentials are assembled at runtime from fragments so the repository itself never contains
 * a string that secret scanners (gitleaks, GitHub push protection) would flag. All values are synthetic.
 */
const fake = (...parts: string[]): string => parts.join('');

describe('secret detectors', () => {
  // Synthetic values in the documented formats; none are real credentials.
  const cases: [string, string][] = [
    ['aws-access-key-id', 'key AKIAIOSFODNN7EXAMPLE here'],
    ['aws-secret-access-key', 'aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'],
    ['github-token', 'token ghp_' + 'A1b2'.repeat(9)],
    ['github-token', 'github_pat_' + 'x'.repeat(30)],
    ['gitlab-token', 'glpat-' + 'a'.repeat(20)],
    ['slack-token', fake('xox', 'b-1234567890-abcdefghij')],
    ['anthropic-key', 'sk-ant-api03-' + 'z'.repeat(30)],
    ['openai-key', 'sk-proj-' + 'q'.repeat(30)],
    ['google-api-key', 'AIza' + 'B'.repeat(35)],
    ['stripe-key', 'sk_live_' + '4'.repeat(24)],
    ['npm-token', 'npm_' + 'n'.repeat(36)],
    ['jwt', [fake('ey', 'JhbGciOiJIUzI1NiJ9'), fake('ey', 'JzdWIiOiJmaXh0dXJlIn0'), 'c2lnbmF0dXJlLW5vdC1yZWFs'].join('.')],
    ['bearer-token', 'Authorization: Bearer abcdefghijklmnop1234'],
    ['url-credentials', 'postgres://admin:hunter2hunter2@db.internal:5432/x'],
    ['credential-assignment', 'password="correct horse"'],
    ['private-key', fake('-----BEGIN RSA ', 'PRIVATE KEY-----\nAAAA\n-----END RSA ', 'PRIVATE KEY-----')],
  ];

  it.each(cases)('detects %s', (rule, text) => {
    expect(findSecrets(text).map((m) => m.rule)).toContain(rule);
  });

  it('keeps prefixes so logs stay readable', () => {
    expect(r.redactString('Authorization: Bearer abcdefghijklmnop1234')).toBe('Authorization: Bearer [REDACTED:bearer-token]');
    expect(r.redactString('postgres://admin:hunter2hunter2@db')).toBe('postgres://admin:[REDACTED:url-credentials]@db');
  });

  it('redacts an unterminated private key to the end of the text', () => {
    const out = r.redactString(fake('x -----BEGIN ', 'PRIVATE KEY-----\nAAAA...truncated'));
    expect(out).toBe('x [REDACTED:private-key]');
  });

  it('does not flag ordinary prose or code', () => {
    const benign = 'The quick brown fox. function add(a, b) { return a + b } // see https://example.com/docs?page=2';
    expect(findSecrets(benign)).toEqual([]);
  });

  it('runs in linear time on adversarial input (no ReDoS)', () => {
    const inputs = [
      '-----BEGIN PRIVATE KEY-----'.repeat(40_000),
      '-----BEGIN '.repeat(80_000),
      'a:'.repeat(400_000) + '@',
      'password='.repeat(100_000),
      'eyJ' + 'a'.repeat(500_000) + '.',
      'x://' + 'a'.repeat(300) + ':' + 'b'.repeat(500_000),
    ];
    for (const s of inputs) {
      const t0 = performance.now();
      findSecrets(s);
      expect(performance.now() - t0, `input starting ${s.slice(0, 20)}`).toBeLessThan(2000);
    }
  });
});

describe('Redactor', () => {
  it('redacts configured secrets and their base64/URL-encoded forms', () => {
    const red = new Redactor({ knownSecrets: ['my-db-password-123', 'short'] });
    const b64 = Buffer.from('my-db-password-123').toString('base64');
    expect(red.redactString(`a my-db-password-123 b ${b64} c my-db-password-123`)).toBe(
      'a [REDACTED:configured-secret] b [REDACTED:configured-secret] c [REDACTED:configured-secret]',
    );
    // Values shorter than 8 chars would cause noise; they are not treated as secrets.
    expect(red.redactString('short')).toBe('short');
  });

  it('redacts values under sensitive keys regardless of content, at any depth', () => {
    const out = r.redactValue({ headers: { Authorization: 'x', 'X-Api-Key': 'y' }, nested: [{ password: 'p', ok: 'fine' }] });
    expect(out).toEqual({
      headers: { Authorization: '[REDACTED:sensitive-key]', 'X-Api-Key': '[REDACTED:sensitive-key]' },
      nested: [{ password: '[REDACTED:sensitive-key]', ok: 'fine' }],
    });
  });

  it('never mutates its input', () => {
    const input = { a: 'AKIAIOSFODNN7EXAMPLE', b: [{ token: 'x' }] };
    const copy = structuredClone(input);
    r.redactValue(input);
    expect(input).toEqual(copy);
  });

  it('enforces the budget and drops (not logs) everything beyond it', () => {
    const small = new Redactor({ budgetChars: 100 });
    const out = small.redactValue({ a: 'x '.repeat(40), b: 'y'.repeat(100), c: 'z' }) as Record<string, unknown>;
    const json = JSON.stringify(out);
    expect(json).toContain(TRUNCATED);
    expect(json).not.toContain('zz');
    expect(json.length).toBeLessThan(400);
  });

  it('never half-logs a secret cut by the budget', () => {
    const key = 'ghp_' + 'Q'.repeat(36);
    for (let budget = 1; budget < 60; budget++) {
      const out = JSON.stringify(new Redactor({ budgetChars: budget }).redactValue(`prefix ${key}`));
      expect(out, `budget ${budget}`).not.toMatch(/ghp_Q{4,}/);
    }
  });

  it('bounds recursion depth', () => {
    let deep: unknown = 'leaf';
    for (let i = 0; i < 100; i++) deep = { d: deep };
    expect(JSON.stringify(r.redactValue(deep))).toContain(TRUNCATED);
  });
});

describe('safeCut', () => {
  it('returns short text unchanged', () => {
    expect(safeCut('error: thing failed within 1500 ms', 4096)).toBe('error: thing failed within 1500 ms');
  });
  it('cuts back to the last delimiter', () => {
    expect(safeCut('abc def ghijkl', 10)).toBe('abc def ');
  });
  it('drops an undelimited tail entirely', () => {
    expect(safeCut('x'.repeat(10_000), 9_000)).toBe('x'.repeat(9_000 - 4096));
  });
});
