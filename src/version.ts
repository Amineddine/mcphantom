import fs from 'node:fs';

// src/version.ts and dist/version.js are both one level below the package root.
const pkg = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string };

export const VERSION: string = pkg.version;
