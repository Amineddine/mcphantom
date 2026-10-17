/**
 * Filler for `bench:perf` (pre-registered in bench/perf/PREREGISTRATION-perf.md), generated at run time from a
 * fixed seed, so no filler content is committed.
 *
 * - `prose`: lower-case dictionary words and full stops. It holds no identifier (no URL, e-mail, path,
 *   token or secret shape), so it fills Tier A and leaves Tier B alone.
 * - `tokens`: distinct random 32-character base62 tokens separated by spaces. Each is an identifier that
 *   Tier B indexes under two hashes (raw and normalized): the identifier flood of arm F3.
 */
import crypto from 'node:crypto';
import { rng } from './stats.js';

const WORDS = (
  'the of and to in is for on with as by at from that this which are was be it an or not have has but all ' +
  'report team quarter review meeting project schedule budget plan update office service customer order ' +
  'summary notes draft section page chapter policy process change system support release version market ' +
  'weather garden river mountain coffee morning evening travel museum library history music painting ' +
  'recipe kitchen bread butter apple orange season winter summer autumn spring holiday family friend ' +
  'school student lesson teacher reading writing number question answer result method example'
).split(' ');

/** About `bytes` characters of identifier-free prose (ASCII, so characters = bytes). */
export function prose(bytes: number, seed: number): string {
  const r = rng(seed);
  const out: string[] = [];
  let n = 0;
  let inSentence = 0;
  while (n < bytes) {
    const w = WORDS[Math.floor(r() * WORDS.length)] ?? 'the';
    inSentence++;
    const end = inSentence >= 8 + Math.floor(r() * 10);
    const piece = end ? `${w}. ` : `${w} `;
    if (end) inSentence = 0;
    out.push(piece);
    n += piece.length;
  }
  return out.join('').slice(0, bytes);
}

const B62 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

/** `count` distinct random 32-character base62 tokens (from a seeded hash chain), space-separated. */
export function tokens(count: number, seed: number): string {
  const out: string[] = [];
  for (let i = 0; i < count; i++) {
    const d = crypto.createHash('sha256').update(`bench-perf-flood:${seed}:${i}`).digest();
    out.push(Array.from(d, (b) => B62[b % 62]).join('').slice(0, 32));
  }
  return out.join(' ');
}

/** Tokens that fit in `bytes` characters (32 characters + one space each). */
export const tokensIn = (bytes: number) => Math.floor((bytes + 1) / 33);
