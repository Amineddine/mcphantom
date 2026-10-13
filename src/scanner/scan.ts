import type { Prompt, Tool } from '@modelcontextprotocol/sdk/types.js';
import { decodeVariants, type DecodeLimits } from '../text/decode.js';
import { despace, fold } from '../text/normalize.js';
import {
  detectDataAccessHint,
  detectEmbeddedInstruction,
  detectExfiltrationHint,
  detectHiddenUnicode,
  detectMixedScript,
  detectShadowing,
  SEVERITY_ORDER,
  type Category,
  type Finding,
  type Severity,
} from './detectors.js';
import { instructionsSpan, promptSpans, toolSpans, type TextSpan } from './extract.js';

export type { Finding, Severity, Category };

export interface ScanResult {
  findings: Finding[];
  /** Highest severity present, or undefined if clean. */
  worst: Severity | undefined;
  /** True if the subject should be hidden from the client at list time. */
  flagged: boolean;
}

export interface ScanOptions {
  /** Minimum severity that causes the tool/prompt to be hidden. Default: medium. */
  block: Severity;
}

export const DEFAULT_SCAN_OPTIONS: ScanOptions = { block: 'medium' };

/** The content detectors: everything except the invisible-character ones, which only mean something
 *  on the raw text. */
function contentDetectors(span: TextSpan, ownName: string): Finding[] {
  return [...detectEmbeddedInstruction(span), ...detectExfiltrationHint(span), ...detectDataAccessHint(span), ...detectShadowing(span, ownName)];
}

function runDetectors(spans: TextSpan[], ownName: string): Finding[] {
  const findings: Finding[] = [];
  for (const span of spans) {
    findings.push(...detectHiddenUnicode(span));
    findings.push(...detectMixedScript(span));
    findings.push(...contentDetectors(span, ownName));
  }
  findings.push(...crossSpan(spans, findings));
  findings.push(...disguised(spans, ownName, findings));
  return combine(findings);
}

/** Decoding bounds for definitions. Rot13 and reversal apply to the whole text: an instruction is a
 *  sentence, not a token. */
const SCAN_DECODE: DecodeLimits = { maxDepth: 2, maxVariants: 16, maxChars: 256 * 1024 };
/** Characters of model-visible text per definition that are examined in disguise-undone form. Real
 *  definitions are a few KB; a hostile one stuffed with encoded text would otherwise make list-time
 *  scanning slow (measured: ~3.5 s for 2 MB in 2000 property descriptions). Past this the definition is
 *  reported `unscannable` (medium: hidden by default) — what cannot be inspected is not shown. */
export const MAX_DERIVED_SCAN_CHARS = 64 * 1024;

/**
 * Disguise-undone forms of a span (Phase-3 review B1/B3/B4, closed through the shared pipeline used by
 * Layer-2 provenance): look-alikes / width / invisible characters folded, letter spacing joined, and
 * encodings decoded. Labelled with the disguise, for the finding's `via`.
 */
function derivedSpans(span: TextSpan): { span: TextSpan; via: string }[] {
  const out: { span: TextSpan; via: string }[] = [];
  const seen = new Set([span.text]);
  const add = (text: string, via: string): void => {
    if (seen.has(text)) return;
    seen.add(text);
    out.push({ span: { where: span.where, text }, via });
  };
  const folded = fold(span.text);
  add(folded, 'folded');
  add(despace(folded), 'letter-spacing');
  for (const v of decodeVariants(folded, SCAN_DECODE).variants) add(fold(v.text), `decoded:${v.chain.join('>')}`);
  return out;
}

/**
 * Runs the content detectors on every span's disguise-undone forms (and on the combined descriptions'
 * forms). A finding is added only if the raw text did not already produce it, so the false-positive
 * rate on undisguised text is unchanged. An instruction to the model that only appears once a disguise
 * is undone is rated at least medium: a benign description has no reason to obfuscate one.
 */
function disguised(spans: TextSpan[], ownName: string, raw: Finding[]): Finding[] {
  const known = new Set(raw.map((f) => `${f.category}|${f.detail}`));
  const out: Finding[] = [];
  const consider = (f: Finding, via: string): void => {
    const key = `${f.category}|${f.detail}`;
    if (known.has(key)) return;
    known.add(key);
    const severity = f.category === 'embedded-instruction' && SEVERITY_ORDER[f.severity] < SEVERITY_ORDER.medium ? 'medium' : f.severity;
    out.push({ ...f, severity, via });
  };
  const total = spans.reduce((n, s) => n + s.text.length, 0);
  if (total > MAX_DERIVED_SCAN_CHARS) {
    return [{ category: 'unscannable', severity: 'medium', where: 'definition', evidence: `${total} characters of model-visible text`, detail: `definition too large to inspect for disguised text (> ${MAX_DERIVED_SCAN_CHARS} characters)` }];
  }
  for (const span of spans) for (const d of derivedSpans(span)) for (const f of contentDetectors(d.span, ownName)) consider(f, d.via);
  const combined = combinedDescriptions(spans);
  if (combined) for (const d of derivedSpans(combined)) for (const f of detectEmbeddedInstruction(d.span)) consider(f, d.via);
  return out;
}

function combinedDescriptions(spans: TextSpan[]): TextSpan | undefined {
  const descriptive = spans.filter((s) => /description|title|\$comment|instructions/.test(s.where));
  if (descriptive.length < 2) return undefined;
  return { where: 'combined-descriptions', text: descriptive.map((s) => s.text).join('\n') };
}

/**
 * Catches an instruction split across several descriptions, each benign alone (Phase-3 review B2).
 * All description-like spans are concatenated (newline-joined, so word boundaries are preserved) and
 * the instruction patterns run again. A finding is only added when it did NOT already fire on a single
 * span — i.e. the match genuinely crosses a boundary — so this adds recall without changing per-span
 * false positives.
 */
function crossSpan(spans: TextSpan[], perSpan: Finding[]): Finding[] {
  const combined = combinedDescriptions(spans);
  if (!combined) return [];
  const already = new Set(perSpan.filter((f) => f.category === 'embedded-instruction').map((f) => f.detail));
  return detectEmbeddedInstruction(combined).filter((f) => !already.has(f.detail));
}

/**
 * Raises severity for co-occurring signals that together describe a complete attack: a description
 * that both points at secret files *and* directs sending data out is a full exfiltration instruction,
 * worse than either hint alone. Individual hints stay where they are so the FPR of the combination,
 * not of each hint, is what gates blocking.
 */
function combine(findings: Finding[]): Finding[] {
  const cats = new Set(findings.map((f) => f.category));
  if (cats.has('exfiltration-hint') && cats.has('data-access-hint')) {
    findings.push({
      category: 'exfiltration-hint',
      severity: 'high',
      where: 'description',
      evidence: 'data-access + exfiltration',
      detail: 'description both references credential files and directs sending data to an external destination',
    });
  }
  if (cats.has('embedded-instruction') && (cats.has('exfiltration-hint') || cats.has('data-access-hint'))) {
    const inst = findings.find((f) => f.category === 'embedded-instruction');
    if (inst && SEVERITY_ORDER[inst.severity] < SEVERITY_ORDER.high) {
      findings.push({ category: 'embedded-instruction', severity: 'high', where: inst.where, evidence: inst.evidence, detail: 'instruction to the model combined with a data-movement hint' });
    }
  }
  return findings;
}

function verdict(findings: Finding[], opts: ScanOptions): ScanResult {
  let worst: Severity | undefined;
  for (const f of findings) if (worst === undefined || SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[worst]) worst = f.severity;
  const flagged = worst !== undefined && SEVERITY_ORDER[worst] >= SEVERITY_ORDER[opts.block];
  return { findings, worst, flagged };
}

export function scanTool(tool: Tool, opts: ScanOptions = DEFAULT_SCAN_OPTIONS): ScanResult {
  return verdict(runDetectors(toolSpans(tool), tool.name), opts);
}

export function scanPrompt(prompt: Prompt, opts: ScanOptions = DEFAULT_SCAN_OPTIONS): ScanResult {
  return verdict(runDetectors(promptSpans(prompt), prompt.name), opts);
}

export function scanInstructions(instructions: string | undefined, opts: ScanOptions = DEFAULT_SCAN_OPTIONS): ScanResult {
  return verdict(runDetectors(instructionsSpan(instructions), ''), opts);
}
