/** Round-trip payload sizes for `bench:perf` (pre-registered in bench/perf/PREREGISTRATION-perf.md, section L). */
export const SIZES = {
  '1k': { label: '1 KiB', text: () => 'x'.repeat(1024), warm: 20, n: 200 },
  '64k': { label: '64 KiB', text: () => 'x'.repeat(65_536), warm: 20, n: 100 },
  '1m': { label: '1 MiB', text: () => 'x'.repeat(1_048_576), warm: 5, n: 20 },
  slash128k: { label: '128 KiB slash-heavy (R6b-10)', text: () => 'aBcdefghijklmnoP/'.repeat(7710), warm: 5, n: 40 },
} as const;
export type SizeId = keyof typeof SIZES;
