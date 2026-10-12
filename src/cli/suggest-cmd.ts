import fs from 'node:fs';
import { parse as parseYaml, stringify } from 'yaml';
import type { Paths } from '../config/paths.js';
import { ConfigSchema } from '../config/schema.js';
import { writePrivateFile } from '../security/fileperms.js';
import { collectLive } from './schemas.js';
import { applySuggestions, suggestClassification, type Suggestion } from './suggest.js';

export interface SuggestIo {
  out(text: string): void;
}

export interface SuggestOptions {
  configFile: string;
  paths: Paths;
  write: boolean;
  acceptLoose: boolean;
}

/**
 * `mcphantom suggest`: connect to the configured servers, derive classification suggestions from their
 * tool annotations and names, and print them. Annotation-derived suggestions are flagged
 * server-claimed. Only tighten/match suggestions are written automatically; a `loosen` suggestion
 * (which would grant more capability or trust than the secure default) needs `--accept-loose`.
 */
export async function runSuggest(opts: SuggestOptions, io: SuggestIo): Promise<number> {
  const live = await collectLive(opts.configFile, opts.paths);
  try {
    const byServer = new Map<string, Suggestion[]>();
    for (const [serverId, tools] of Object.entries(live.tools)) {
      byServer.set(serverId, tools.map(suggestClassification));
    }
    io.out('Classification suggestions (secure default = egress / untrusted / internal):\n');
    for (const [serverId, suggestions] of byServer) {
      for (const s of suggestions) {
        const c = `${s.classification.effect ?? '-'}/${s.classification.integrity ?? '-'}`;
        const tags = [s.relation === 'loosen' ? 'LOOSEN (needs --accept-loose)' : s.relation, s.serverClaimed ? 'server-claimed' : ''].filter(Boolean).join(', ');
        io.out(`  ${serverId}__${s.tool}  →  ${c}  [${tags}]  ${s.basis}`);
      }
    }
    if (!opts.write) {
      io.out('\n(dry run: pass --write to apply tighten/match suggestions to the profile; add --accept-loose to also apply looser ones)');
      return 0;
    }
    const raw = fs.readFileSync(opts.configFile, 'utf8');
    const doc = parseYaml(raw) as { servers: Record<string, { tools?: Record<string, Record<string, unknown>> }> };
    const { applied, skippedLoose } = applySuggestions(doc, byServer, opts.acceptLoose);
    const check = ConfigSchema.safeParse(doc);
    if (!check.success) throw new Error('internal error: profile became invalid after applying suggestions');
    writePrivateFile(opts.configFile, stringify(doc));
    io.out(`\nApplied ${applied} suggestion(s) to ${opts.configFile}.`);
    if (skippedLoose.length > 0) io.out(`Skipped ${skippedLoose.length} looser suggestion(s) (re-run with --accept-loose to apply): ${skippedLoose.join(', ')}`);
    io.out('Run `mcphantom policy lint` to check any rules against the updated classifications.');
    return 0;
  } finally {
    await live.close();
  }
}
