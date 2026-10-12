import type { Prompt, Tool } from '@modelcontextprotocol/sdk/types.js';
import {
  detectDataAccessHint,
  detectEmbeddedInstruction,
  detectExfiltrationHint,
  detectHiddenUnicode,
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

function runDetectors(spans: TextSpan[], ownName: string): Finding[] {
  const findings: Finding[] = [];
  for (const span of spans) {
    findings.push(...detectHiddenUnicode(span));
    findings.push(...detectEmbeddedInstruction(span));
    findings.push(...detectExfiltrationHint(span));
    findings.push(...detectDataAccessHint(span));
    findings.push(...detectShadowing(span, ownName));
  }
  return combine(findings);
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
