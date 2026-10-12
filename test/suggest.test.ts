import { describe, expect, it } from 'vitest';
import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { suggestClassification } from '../src/cli/suggest.js';

const tool = (name: string, annotations?: Record<string, unknown>): Tool => ({ name, description: name, inputSchema: { type: 'object' }, ...(annotations ? { annotations } : {}) });

describe('suggestClassification (owner note #3: server-claimed, tighten-or-match only)', () => {
  it('a read-only annotation is marked loosen and server-claimed (needs explicit consent)', () => {
    const s = suggestClassification(tool('get_thing', { readOnlyHint: true }));
    expect(s.classification.effect).toBe('read');
    expect(s.relation).toBe('loosen'); // read is looser than the egress default
    expect(s.serverClaimed).toBe(true);
    expect(s.basis).toContain('readOnlyHint');
  });

  it('an exec-sounding name tightens (stricter than default) and is not server-claimed', () => {
    const s = suggestClassification(tool('run_shell'));
    expect(s.classification.effect).toBe('exec');
    expect(s.relation).toBe('tighten');
    expect(s.serverClaimed).toBe(false);
  });

  it('an egress-sounding name matches the default', () => {
    expect(suggestClassification(tool('send_email')).relation).toBe('match');
  });

  it('openWorldHint keeps untrusted (matches the default) and is server-claimed', () => {
    const s = suggestClassification(tool('fetch_url', { openWorldHint: true }));
    expect(s.classification.integrity).toBe('untrusted');
    expect(s.serverClaimed).toBe(true);
  });

  it('a read name without annotation still only suggests read as loosen (so it needs consent)', () => {
    expect(suggestClassification(tool('list_files')).relation).toBe('loosen');
  });

  it('a server cannot get its tool auto-trusted: trusted integrity is never the suggestion from annotations', () => {
    // No annotation can produce trusted integrity; the default stays untrusted.
    expect(suggestClassification(tool('anything', { readOnlyHint: true, openWorldHint: false })).classification.integrity).not.toBe('trusted');
  });
});
