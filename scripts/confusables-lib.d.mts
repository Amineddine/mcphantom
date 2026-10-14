export interface ParsedConfusables {
  version: string;
  sha256: string;
  entries: [number, string][];
}
export function parseConfusables(raw: Buffer): ParsedConfusables;
export function renderConfusables(parsed: ParsedConfusables): string;
