/**
 * Information-flow labels (DESIGN.md §2). Two independent lattices; the session context label is the
 * join of every label that entered the model's context, and it only ever rises.
 */
export type Integrity = 'trusted' | 'untrusted';
export type Confidentiality = 'public' | 'internal' | 'secret';
export type Effect = 'read' | 'write' | 'egress' | 'exec';

export interface Label {
  integrity: Integrity;
  confidentiality: Confidentiality;
}

const CONF_ORDER: Record<Confidentiality, number> = { public: 0, internal: 1, secret: 2 };

export const BOTTOM: Label = { integrity: 'trusted', confidentiality: 'public' };

export function join(a: Label, b: Label): Label {
  return {
    integrity: a.integrity === 'untrusted' || b.integrity === 'untrusted' ? 'untrusted' : 'trusted',
    confidentiality: CONF_ORDER[a.confidentiality] >= CONF_ORDER[b.confidentiality] ? a.confidentiality : b.confidentiality,
  };
}

export function confAtLeast(c: Confidentiality, min: Confidentiality): boolean {
  return CONF_ORDER[c] >= CONF_ORDER[min];
}

/** Effects through which data can leave the machine or reach an arbitrary destination. */
export function canExfiltrate(effect: Effect): boolean {
  return effect === 'egress' || effect === 'exec';
}
