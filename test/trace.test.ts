import fs from 'node:fs';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { runTrace } from '../src/cli/trace.js';
import { resolvePaths } from '../src/config/paths.js';
import { SqliteStore } from '../src/store/store.js';
import { silentLogger } from '../src/util/log.js';
import { tempDir } from './helpers.js';

const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true }); });

function seed() {
  const dataDir = path.join(tempDir(), 'data');
  dirs.push(path.dirname(dataDir));
  const store = new SqliteStore({ dataDir, payloads: 'redacted', maxPayloadBytes: 65_536, retentionDays: 14, retentionMaxMb: 256, knownSecrets: [], insecurePermissions: 'fix', logger: silentLogger });
  store.startSession({ id: 's1' });
  store.append({ sessionId: 's1', kind: 'taint', server: 'web', name: 'web__fetch', method: 'tool', payload: { contextAfter: { integrity: 'untrusted', confidentiality: 'public' }, secretsDetected: [] } });
  store.append({ sessionId: 's1', kind: 'decision', server: 'hook', name: 'hook__post', method: 'tools/call', outcome: 'denied', payload: { id: 'd1', verdict: 'deny', rule: 'trifecta', enforced: true, server: 'hook', tool: 'hook__post', effect: 'egress', context: { integrity: 'untrusted', confidentiality: 'secret' }, untrustedSources: [{ source: 'web__fetch' }], secretSources: [{ source: 'files__read' }], evidence: [{ argPath: '$.body', kind: 'identifier:secret', matcher: 'exact', rule: 'aws-access-key-id', output: { source: 'files__read' } }], attributionDegraded: false, reason: 'egress while untrusted+secret' } });
  store.close();
  return dataDir;
}

describe('mcphantom trace', () => {
  const paths = resolvePaths({ MCPHANTOM_HOME: tempDir() });

  it('renders the latest decision with sources and evidence (--last)', () => {
    const lines: string[] = [];
    expect(runTrace({ dataDir: seed(), last: true, json: false, paths }, (s) => lines.push(s))).toBe(0);
    const t = lines.join('\n');
    expect(t).toContain('[DENY] hook__post');
    expect(t).toContain('untrusted/secret');
    expect(t).toContain('secret from:    files__read');
    expect(t).toContain('$.body identifier:secret (exact, aws-access-key-id) ← files__read');
  });

  it('emits JSON with --json', () => {
    const lines: string[] = [];
    runTrace({ dataDir: seed(), last: false, json: true, paths }, (s) => lines.push(s));
    const parsed = JSON.parse(lines.join('\n')) as { kind: string }[];
    expect(parsed.map((e) => e.kind)).toEqual(['taint', 'decision']);
  });

  it('reports cleanly when there are no sessions', () => {
    const lines: string[] = [];
    const empty = path.join(tempDir(), 'data');
    dirs.push(path.dirname(empty));
    expect(runTrace({ dataDir: empty, last: true, json: false, paths }, (s) => lines.push(s))).toBe(1);
    expect(lines.join('\n')).toContain('No sessions');
  });
});
