/**
 * Minimal glob matching for policy predicates such as matching a path against patterns like a
 * credentials glob. Supports `*` (any run except slash), a double-star (any run including slash),
 * `?` (one non-slash char), and literal text. A leading `~/` expands to the home dir.
 *
 * The matcher is an iterative single-backtrack-pointer algorithm (O(value x pattern) worst case), NOT
 * a regex: the value comes from untrusted tool arguments, and a regex glob (`.*[^/]*...`) backtracks
 * catastrophically on a long adversarial value. This algorithm cannot.
 */
import os from 'node:os';

type Token =
  | { t: 'lit'; c: string }
  | { t: 'one' } // ?  (one non-slash)
  | { t: 'star' } // *  (run of non-slash)
  | { t: 'globstar' }; // ** (run of anything)

function tokenize(glob: string): Token[] {
  const g = glob.startsWith('~/') ? os.homedir().replace(/\\/g, '/') + '/' + glob.slice(2) : glob;
  const toks: Token[] = [];
  for (let i = 0; i < g.length; i++) {
    const c = g[i] as string;
    if (c === '*') {
      if (g[i + 1] === '*') {
        i++;
        if (g[i + 1] === '/') i++; // treat `**/` like `**`
        // collapse adjacent globstars
        if (toks[toks.length - 1]?.t !== 'globstar') toks.push({ t: 'globstar' });
      } else if (toks[toks.length - 1]?.t !== 'star') {
        toks.push({ t: 'star' });
      }
    } else if (c === '?') {
      toks.push({ t: 'one' });
    } else {
      toks.push({ t: 'lit', c });
    }
  }
  return toks;
}

const cache = new Map<string, Token[]>();

function tokensFor(pattern: string): Token[] {
  let toks = cache.get(pattern);
  if (!toks) {
    toks = tokenize(pattern);
    if (cache.size < 1000) cache.set(pattern, toks);
  }
  return toks;
}

export function globMatch(value: string, pattern: string): boolean {
  const v = value.replace(/\\/g, '/');
  const p = tokensFor(pattern);
  let i = 0; // index into v
  let j = 0; // index into p
  let star = -1; // last star token position
  let starAllowsSlash = false;
  let starMatch = 0; // where the star started consuming
  while (i < v.length) {
    const tok = p[j];
    if (tok && tok.t === 'lit' && tok.c === v[i]) {
      i++;
      j++;
    } else if (tok && tok.t === 'one' && v[i] !== '/') {
      i++;
      j++;
    } else if (tok && (tok.t === 'star' || tok.t === 'globstar')) {
      star = j;
      starAllowsSlash = tok.t === 'globstar';
      starMatch = i;
      j++; // first try matching zero characters
    } else if (star !== -1 && (starAllowsSlash || v[i] !== '/')) {
      // Backtrack: let the last star consume one more character of v.
      j = star + 1;
      i = starMatch + 1;
      starMatch = i;
    } else {
      return false;
    }
  }
  while (j < p.length && (p[j]?.t === 'star' || p[j]?.t === 'globstar')) j++;
  return j === p.length;
}

export function globMatchAny(value: string, patterns: readonly string[]): boolean {
  return patterns.some((p) => globMatch(value, p));
}
