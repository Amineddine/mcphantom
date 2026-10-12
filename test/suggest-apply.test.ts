import { describe, expect, it } from 'vitest';
import { applySuggestions, type Suggestion } from '../src/cli/suggest.js';

const sug = (tool: string, relation: Suggestion['relation'], classification: Suggestion['classification']): Suggestion => ({ tool, relation, classification, basis: 'test', serverClaimed: false });

describe('applySuggestions', () => {
  it('applies tighten/match, skips loosen unless accepted', () => {
    const doc = { servers: { s: { tools: {} as Record<string, Record<string, unknown>> } } };
    const byServer = new Map([['s', [sug('a', 'tighten', { effect: 'exec' }), sug('b', 'match', { effect: 'egress' }), sug('c', 'loosen', { effect: 'read' })]]]);
    const r = applySuggestions(doc, byServer, false);
    expect(r.applied).toBe(2);
    expect(r.skippedLoose).toEqual(['s__c']);
    expect(doc.servers.s.tools).toEqual({ a: { effect: 'exec' }, b: { effect: 'egress' } });
  });
  it('applies loosen when accepted', () => {
    const doc = { servers: { s: { tools: {} as Record<string, Record<string, unknown>> } } };
    const r = applySuggestions(doc, new Map([['s', [sug('c', 'loosen', { effect: 'read' })]]]), true);
    expect(r.applied).toBe(1);
    expect(doc.servers.s.tools).toEqual({ c: { effect: 'read' } });
  });
  it('merges with existing per-tool config without dropping other keys', () => {
    const doc = { servers: { s: { tools: { a: { rules: [{ deny: "x" }] } } as Record<string, Record<string, unknown>> } } };
    applySuggestions(doc, new Map([['s', [sug('a', 'match', { effect: 'egress' })]]]), false);
    expect(doc.servers.s.tools.a).toEqual({ rules: [{ deny: 'x' }], effect: 'egress' });
  });
});
