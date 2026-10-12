import type { TextSpan } from './extract.js';

export type Severity = 'info' | 'low' | 'medium' | 'high';
export type Category =
  | 'hidden-unicode'
  | 'embedded-instruction'
  | 'exfiltration-hint'
  | 'tool-shadowing'
  | 'data-access-hint'
  | 'excessive-permission';

export interface Finding {
  category: Category;
  severity: Severity;
  where: string;
  /** Short, human-readable evidence. Control characters are shown by name, never raw. */
  evidence: string;
  detail: string;
}

export const SEVERITY_ORDER: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3 };

// --------------------------------------------------------------------------------------------------
// Hidden / invisible characters. These carry no legitimate meaning in a tool description and are the
// highest-confidence signal, so they are rated high and have ~zero false positives on real text.

interface InvisibleClass {
  id: string;
  re: RegExp;
  label: string;
}

const INVISIBLE: InvisibleClass[] = [
  // Built from strings so the source file itself contains no invisible characters.
  { id: 'unicode-tags', re: new RegExp('[\u{E0000}-\u{E007F}]', 'u'), label: 'Unicode tag characters (ASCII smuggling, e.g. hidden instructions)' },
  { id: 'bidi-control', re: new RegExp('[\u202A-\u202E\u2066-\u2069]', 'u'), label: 'bidirectional override characters (can reorder/hide text)' },
  { id: 'zero-width', re: new RegExp('[\u200B-\u200D\u2060\uFEFF\u180E]', 'u'), label: 'zero-width characters' },
  { id: 'private-use', re: new RegExp('[\u{E000}-\u{F8FF}\u{F0000}-\u{FFFFD}\u{100000}-\u{10FFFD}]', 'u'), label: 'private-use characters' },
  { id: 'other-format', re: new RegExp('\\u00AD|\\u034F|\\u2028|\\u2029', 'u'), label: 'format/separator control characters' },
];

export function detectHiddenUnicode(span: TextSpan): Finding[] {
  const out: Finding[] = [];
  for (const cls of INVISIBLE) {
    const m = cls.re.exec(span.text);
    if (!m) continue;
    const count = countMatches(span.text, cls.re);
    out.push({
      category: 'hidden-unicode',
      severity: cls.id === 'private-use' || cls.id === 'other-format' ? 'medium' : 'high',
      where: span.where,
      evidence: `${count}× ${describeCodepoint(m[0])}`,
      detail: `contains ${cls.label}`,
    });
  }
  return out;
}

// --------------------------------------------------------------------------------------------------
// Instructions aimed at the assistant embedded in a description. Tool descriptions describe what a
// tool does; imperative instructions to the model ("ignore previous", "do not tell the user", role
// markers, fake system blocks) are the classic tool-poisoning payload.

interface Pattern {
  re: RegExp;
  severity: Severity;
  detail: string;
}

const INSTRUCTION_PATTERNS: Pattern[] = [
  { re: /\bignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\b/i, severity: 'high', detail: 'instruction to ignore prior context' },
  { re: /\bdisregard\s+(?:all\s+)?(?:previous|prior|above|the\s+above)\b/i, severity: 'high', detail: 'instruction to disregard prior context' },
  { re: /\b(?:do\s*not|don'?t|never)\s+(?:tell|inform|mention|reveal|notify|alert|warn)\b(?:[^.]{0,40})\b(?:user|human|person|them)\b/i, severity: 'high', detail: 'instruction to hide activity from the user' },
  { re: /\bwithout\s+(?:telling|informing|notifying|alerting|asking)\s+the\s+(?:user|human)\b/i, severity: 'high', detail: 'instruction to act without informing the user' },
  { re: /<\/?(?:system|assistant|instructions?|important)\b[^>]{0,40}>/i, severity: 'high', detail: 'fake role / system markup' },
  { re: /\[(?:system|assistant|instructions?)\]/i, severity: 'medium', detail: 'role marker in brackets' },
  { re: /^\s*(?:system|assistant)\s*:/im, severity: 'medium', detail: 'role-prefixed line' },
  { re: /\b(?:you\s+must|you\s+should\s+always|it\s+is\s+(?:required|mandatory|imperative)\s+that\s+you|always\s+remember\s+to)\b/i, severity: 'low', detail: 'imperative directed at the model' },
  // An imperative to the model that also directs invoking another tool or forwarding data is a
  // concrete hijack, not mere emphasis — generalised from a dev-split false negative.
  { re: /\b(?:you\s+must|you\s+should|always|as\s+an\s+ai\b[^.]{0,30}\byou\b)[^.]{0,60}\b(?:call|use|invoke|forward|send|include|pass)\b[^.]{0,40}\btool\b/i, severity: 'medium', detail: 'instruction to the model to invoke or feed another tool' },
  { re: /\b(?:before|after|when|whenever)\s+(?:using|calling|invoking|running)\s+this\s+tool\b[^.]{0,80}\b(?:you|the\s+(?:assistant|model|agent))\b/i, severity: 'medium', detail: 'conditional instruction to the model tied to this tool' },
  { re: /\bnew\s+(?:instructions?|rules?|directives?|task)\b\s*[:.]/i, severity: 'medium', detail: 'declares new instructions' },
  { re: /\bas\s+an\s+ai\b|\bas\s+a\s+language\s+model\b/i, severity: 'low', detail: 'addresses the model as an AI' },
];

export function detectEmbeddedInstruction(span: TextSpan): Finding[] {
  // The name/title are short identifiers; instruction prose there is still suspicious but rated via
  // the same patterns. Enum/const values are data, so a role-prefixed enum is only low-interest — but
  // we still flag high-confidence markers anywhere.
  const out: Finding[] = [];
  for (const p of INSTRUCTION_PATTERNS) {
    const m = p.re.exec(span.text);
    if (m) out.push({ category: 'embedded-instruction', severity: p.severity, where: span.where, evidence: excerpt(span.text, m.index, m[0].length), detail: p.detail });
  }
  return out;
}

// --------------------------------------------------------------------------------------------------
// Exfiltration hints: a description that tells the model to send/post data somewhere, or that names a
// destination together with an imperative. On its own "POST to a URL" is normal for an HTTP tool, so
// this is medium and gains weight when it co-occurs with instruction or secret-file patterns.

const SEND_VERB = /\b(?:send|post|exfiltrate|upload|transmit|forward|leak|report|deliver|copy)\b/i;
const DESTINATION = /\b(?:https?:\/\/\S+|to\s+(?:the\s+)?(?:following|this)\s+(?:url|address|endpoint|webhook|server))\b/i;

export function detectExfiltrationHint(span: TextSpan): Finding[] {
  const sv = SEND_VERB.exec(span.text);
  if (!sv) return [];
  if (!DESTINATION.test(span.text)) return [];
  return [{ category: 'exfiltration-hint', severity: 'medium', where: span.where, evidence: excerpt(span.text, sv.index, 24), detail: 'description directs sending data to an external destination' }];
}

// --------------------------------------------------------------------------------------------------
// Data-access hints: a description that points the model at sensitive local files. Legitimate in a
// few tools, so medium and most useful in combination.

const SENSITIVE_PATHS = /(?:^|[\s"'`(=/])(?:\.env(?:\.[a-z]+)?|\.ssh\/|id_rsa\b|\.aws\/credentials|\.netrc|\.git-credentials|\.npmrc|secrets?\.(?:json|ya?ml|txt)|\.pem\b|\.p12\b)/i;

export function detectDataAccessHint(span: TextSpan): Finding[] {
  const m = SENSITIVE_PATHS.exec(span.text);
  if (!m) return [];
  return [{ category: 'data-access-hint', severity: 'medium', where: span.where, evidence: excerpt(span.text, m.index, 24), detail: 'description references sensitive credential files' }];
}

// --------------------------------------------------------------------------------------------------
// Tool shadowing: a description that talks about *another* tool and changes how it should be used.
// This is how one malicious server hijacks a trusted server's tool (Invariant Labs' shadowing).

const SHADOW = /\b(?:when|before|after|instead\s+of|rather\s+than)\s+(?:using|calling|invoking)\s+(?:the\s+)?[`'"]?([a-z][a-z0-9_]{2,})[`'"]?\s+tool\b/i;
const SHADOW2 = /\bthe\s+[`'"]?([a-z][a-z0-9_]{2,})[`'"]?\s+tool\s+(?:must|should|will|now)\b/i;

export function detectShadowing(span: TextSpan, ownToolName: string): Finding[] {
  for (const re of [SHADOW, SHADOW2]) {
    const m = re.exec(span.text);
    if (m && m[1] && m[1].toLowerCase() !== ownToolName.toLowerCase()) {
      return [{ category: 'tool-shadowing', severity: 'high', where: span.where, evidence: excerpt(span.text, m.index, 40), detail: `description redefines the behaviour of another tool ('${m[1]}')` }];
    }
  }
  return [];
}

// --------------------------------------------------------------------------------------------------
// Helpers

function countMatches(s: string, re: RegExp): number {
  const g = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g');
  let n = 0;
  while (g.exec(s)) n++;
  return n;
}

export function describeCodepoint(ch: string): string {
  const cp = ch.codePointAt(0) ?? 0;
  return `U+${cp.toString(16).toUpperCase().padStart(4, '0')}`;
}

/** A short, control-character-free excerpt around a match, so findings never re-inject the payload. */
export function excerpt(text: string, index: number, len: number): string {
  const start = Math.max(0, index - 8);
  const raw = text.slice(start, Math.min(text.length, index + Math.max(len, 1) + 8));
  const clean = raw.replace(/[\p{Cc}\p{Cf}\u2028\u2029]/gu, '\u00B7');
  return (start > 0 ? '…' : '') + clean.trim().slice(0, 80);
}
