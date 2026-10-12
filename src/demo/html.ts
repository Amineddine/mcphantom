/**
 * Crude HTML → text, like many fetch tools: drops tags, scripts, styles and comments but keeps all
 * other text, including text a browser would not display (hidden elements) — which is how indirect
 * prompt injections in web pages reach models.
 *
 * The input is attacker-controlled, so block removal is a linear indexOf scan rather than lazy
 * regexes (which go quadratic on many unterminated `<script` openings).
 */
export function htmlToText(html: string): string {
  let s = stripBlocks(html, '<!--', '-->');
  s = stripElement(s, 'script');
  s = stripElement(s, 'style');
  return s
    .replace(/<br\s*\/?>|<\/(p|div|h[1-6]|li|tr)>/gi, '\n')
    .replace(/<[^<>]{0,2000}>/g, ' ')
    .replace(/&nbsp;/g, ' ').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&')
    .replace(/[ \t]+/g, ' ')
    .replace(/\n\s*\n+/g, '\n\n')
    .trim();
}

function stripBlocks(s: string, open: string, close: string): string {
  let out = '';
  let pos = 0;
  for (;;) {
    const a = s.indexOf(open, pos);
    if (a < 0) return out + s.slice(pos);
    out += s.slice(pos, a) + ' ';
    const b = s.indexOf(close, a + open.length);
    if (b < 0) return out; // unterminated: drop the rest
    pos = b + close.length;
  }
}

function stripElement(s: string, tag: string): string {
  const lower = s.toLowerCase();
  let out = '';
  let pos = 0;
  for (;;) {
    const a = lower.indexOf(`<${tag}`, pos);
    if (a < 0) return out + s.slice(pos);
    out += s.slice(pos, a) + ' ';
    const b = lower.indexOf(`</${tag}`, a);
    if (b < 0) return out;
    const end = lower.indexOf('>', b);
    pos = end < 0 ? s.length : end + 1;
  }
}
