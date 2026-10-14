/**
 * Secret detectors. Used for log redaction now, and as a taint source in the runtime engine later.
 *
 * Every pattern must run in linear time on adversarial input: no nested quantifiers, no unbounded
 * lazy scans that can restart at many positions. Callers also cap input size (see redact.ts).
 */
export interface SecretRule {
  id: string;
  re: RegExp;
  /** Capture group to keep in front of the redaction marker (e.g. the `password=` prefix). */
  keepPrefixGroup?: number;
}

export const SECRET_RULES: readonly SecretRule[] = [
  { id: 'aws-access-key-id', re: /\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/g },
  {
    id: 'aws-secret-access-key',
    re: /(aws_?secret_?access_?key["']?\s{0,8}[:=]\s{0,8}["']?)[A-Za-z0-9/+=]{40}/gi,
    keepPrefixGroup: 1,
  },
  { id: 'github-token', re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/g },
  { id: 'gitlab-token', re: /\bglpat-[A-Za-z0-9_-]{20,255}\b/g },
  { id: 'slack-token', re: /\bxox[abposr]-[A-Za-z0-9-]{10,255}\b/g },
  { id: 'slack-webhook', re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/_-]{20,255}/g },
  { id: 'anthropic-key', re: /\bsk-ant-[A-Za-z0-9_-]{20,255}\b/g },
  { id: 'openai-key', re: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,255}\b/g },
  { id: 'google-api-key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { id: 'stripe-key', re: /\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,255}\b/g },
  { id: 'npm-token', re: /\bnpm_[A-Za-z0-9]{36}\b/g },
  // PostHog personal (phx_), secret (phs_), OAuth access/refresh (pha_/phr_) and heatmap (phh_) keys:
  // base57 bodies, 22-48 characters today (posthog/models/utils.py). phc_ project tokens are public
  // by design (client-side ingestion) and deliberately not matched.
  { id: 'posthog-key', re: /\bph[xsarh]_[A-Za-z0-9]{20,128}\b/g },
  { id: 'jwt', re: /\beyJ[A-Za-z0-9_-]{8,4096}\.eyJ[A-Za-z0-9_-]{8,8192}\.[A-Za-z0-9_-]{8,4096}\b/g },
  { id: 'bearer-token', re: /(\bBearer\s{1,8})[A-Za-z0-9._~+/=-]{16,4096}/gi, keepPrefixGroup: 1 },
  {
    id: 'url-credentials',
    re: /(\b[a-z][a-z0-9+.-]{1,20}:\/\/[^\s:/@]{1,256}:)[^\s@/]{1,256}(?=@)/gi,
    keepPrefixGroup: 1,
  },
  {
    id: 'credential-assignment',
    re: /(\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|auth[_-]?token)["']?\s{0,8}[:=]\s{0,8}["']?)[^\s"',;]{6,1024}/gi,
    keepPrefixGroup: 1,
  },
];

/** Object keys whose values are always redacted, regardless of content. */
export const SENSITIVE_KEY_RE =
  /^(?:authorization|proxy-authorization|cookie|set-cookie|password|passwd|secret|token|api[-_]?key|x-api-key|access[-_]?token|refresh[-_]?token|id[-_]?token|client[-_]?secret|private[-_]?key|session[-_]?token)$/i;

export interface SecretMatch {
  rule: string;
  start: number;
  end: number;
}

export function findSecrets(text: string, rules: readonly SecretRule[] = SECRET_RULES): SecretMatch[] {
  const out: SecretMatch[] = findPrivateKeys(text);
  for (const rule of rules) {
    rule.re.lastIndex = 0;
    for (const m of text.matchAll(rule.re)) {
      const prefix = rule.keepPrefixGroup !== undefined ? (m[rule.keepPrefixGroup] ?? '') : '';
      out.push({ rule: rule.id, start: m.index + prefix.length, end: m.index + m[0].length });
    }
  }
  return out;
}

const PK_BEGIN = '-----BEGIN ';
const PK_TAIL = 'PRIVATE KEY-----';
const PK_END = '-----END ';

/**
 * PEM private keys, found with indexOf instead of a regex so the scan is linear even with many
 * unterminated BEGIN lines. An unterminated block is redacted to the end of the text: a truncated
 * key in a log is still a leaked key.
 */
function findPrivateKeys(text: string): SecretMatch[] {
  const out: SecretMatch[] = [];
  let from = 0;
  for (;;) {
    const begin = text.indexOf(PK_BEGIN, from);
    if (begin < 0) break;
    const headerEnd = text.indexOf('-----', begin + PK_BEGIN.length);
    const header = headerEnd < 0 ? '' : text.slice(begin, headerEnd + 5);
    if (headerEnd < 0 || headerEnd - begin > 64 || !header.endsWith(PK_TAIL)) {
      from = begin + PK_BEGIN.length;
      continue;
    }
    let endIdx = -1;
    let search = headerEnd + 5;
    for (;;) {
      const e = text.indexOf(PK_END, search);
      if (e < 0) break;
      const close = text.indexOf('-----', e + PK_END.length);
      if (close >= 0 && close - e <= 64 && text.slice(e, close + 5).endsWith(PK_TAIL)) {
        endIdx = close + 5;
        break;
      }
      search = e + PK_END.length;
    }
    const stop = endIdx < 0 ? text.length : endIdx;
    out.push({ rule: 'private-key', start: begin, end: stop });
    from = stop;
  }
  return out;
}
