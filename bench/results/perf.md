# Latency, memory and eviction loss

Phase 7 item 5, pre-registered in `bench/perf/PREREGISTRATION-perf.md` (committed and pushed before the first run).
Generated from `bench/results/perf/ci-1-eviction-1of8.json`, `bench/results/perf/ci-1-eviction-2of8.json`, `bench/results/perf/ci-1-eviction-3of8.json`, `bench/results/perf/ci-1-eviction-4of8.json`, `bench/results/perf/ci-1-eviction-5of8.json`, `bench/results/perf/ci-1-eviction-6of8.json`, `bench/results/perf/ci-1-eviction-7of8.json`, `bench/results/perf/ci-1-eviction-8of8.json`, `bench/results/perf/ci-1.json`, `bench/results/perf/ci-2.json`, `bench/results/perf/ci-3.json`, `bench/results/perf/laptop-1.json` by `bench/perf/report.mts`.

Percentiles: nearest rank on pooled samples. Intervals: 95% cluster bootstrap (B = 2000, seed 20261017), resampling
VMs, then launches, then samples (the laptop has one VM). Gateway − direct deltas are paired at the launch level. All times in ms.

## Environments

| file | where | date | commit | CPU | cores | memory | OS | Node | power | launches |
|---|---|---|---|---|---|---|---|---|---|---|
| ci-1-eviction-1of8.json | GitHub Actions 1000000461 (github-hosted, image ubuntu24 20261012.334.1) | 2026-10-17T02:31:43.051Z | `251b5ed` | AMD EPYC 7763 64-Core Processor | 4 | 16 GB | Linux 6.17.0-1022-azure x64 | v22.23.3 | n/a | 10 |
| ci-1-eviction-2of8.json | GitHub Actions 1000000459 (github-hosted, image ubuntu24 20261012.334.1) | 2026-10-17T02:31:42.238Z | `251b5ed` | AMD EPYC 9V74 80-Core Processor | 4 | 16 GB | Linux 6.17.0-1022-azure x64 | v22.23.3 | n/a | 10 |
| ci-1-eviction-3of8.json | GitHub Actions 1000000457 (github-hosted, image ubuntu24 20261012.334.1) | 2026-10-17T02:31:44.347Z | `251b5ed` | AMD EPYC 7763 64-Core Processor | 4 | 16 GB | Linux 6.17.0-1022-azure x64 | v22.23.3 | n/a | 10 |
| ci-1-eviction-4of8.json | GitHub Actions 1000000458 (github-hosted, image ubuntu24 20261012.334.1) | 2026-10-17T02:31:42.812Z | `251b5ed` | AMD EPYC 7763 64-Core Processor | 4 | 16 GB | Linux 6.17.0-1022-azure x64 | v22.23.3 | n/a | 10 |
| ci-1-eviction-5of8.json | GitHub Actions 1000000463 (github-hosted, image ubuntu24 20261012.334.1) | 2026-10-17T02:31:44.226Z | `251b5ed` | AMD EPYC 9V74 80-Core Processor | 4 | 16 GB | Linux 6.17.0-1022-azure x64 | v22.23.3 | n/a | 10 |
| ci-1-eviction-6of8.json | GitHub Actions 1000000453 (github-hosted, image ubuntu24 20261012.334.1) | 2026-10-17T02:31:42.726Z | `251b5ed` | AMD EPYC 7763 64-Core Processor | 4 | 16 GB | Linux 6.17.0-1022-azure x64 | v22.23.3 | n/a | 10 |
| ci-1-eviction-7of8.json | GitHub Actions 1000000462 (github-hosted, image ubuntu24 20261012.334.1) | 2026-10-17T02:31:42.602Z | `251b5ed` | INTEL(R) XEON(R) PLATINUM 8573C | 4 | 16 GB | Linux 6.17.0-1022-azure x64 | v22.23.3 | n/a | 10 |
| ci-1-eviction-8of8.json | GitHub Actions 1000000455 (github-hosted, image ubuntu24 20261012.334.1) | 2026-10-17T02:31:42.486Z | `251b5ed` | AMD EPYC 7763 64-Core Processor | 4 | 16 GB | Linux 6.17.0-1022-azure x64 | v22.23.3 | n/a | 10 |
| ci-1.json | GitHub Actions 1000000456 (github-hosted, image ubuntu24 20261012.334.1) | 2026-10-17T02:31:43.037Z | `251b5ed` | AMD EPYC 7763 64-Core Processor | 4 | 16 GB | Linux 6.17.0-1022-azure x64 | v22.23.3 | n/a | 10 |
| ci-2.json | GitHub Actions 1000000454 (github-hosted, image ubuntu24 20261012.334.1) | 2026-10-17T02:31:43.650Z | `251b5ed` | INTEL(R) XEON(R) PLATINUM 8573C | 4 | 16 GB | Linux 6.17.0-1022-azure x64 | v22.23.3 | n/a | 10 |
| ci-3.json | GitHub Actions 1000000460 (github-hosted, image ubuntu24 20261012.334.1) | 2026-10-17T02:31:43.273Z | `251b5ed` | AMD EPYC 7763 64-Core Processor | 4 | 16 GB | Linux 6.17.0-1022-azure x64 | v22.23.3 | n/a | 10 |
| laptop-1.json | local | 2026-10-17T02:31:53.713Z | `251b5ed` | Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz | 8 | 16 GB | Windows_NT 10.0.26200 x64 | v22.19.0 | on AC: yes; Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced) | 10 |

The CI runner is a **shared VM, not a quiet machine**: the per-VM and per-launch spreads below are part of the result.

## L — round trip, direct vs gateway

### CI (primary): GitHub-hosted `ubuntu-latest`, three replicate VMs

| size | gateway arm | calls (direct / gateway) | direct p50 | p95 | p99 | gateway p50 | p95 | p99 | Δ p50 | Δ p95 | Δ p99 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 KiB | payloads: redacted | 6000 / 6000 | 0.30 (0.19–0.33) | 0.43 (0.37–0.48) | 0.83 (0.59–1.04) | 16.55 (14.14–18.81) | 26.91 (20.32–27.50) | 31.52 (28.62–33.82) | +16.25 (13.83–18.49) | +26.48 (19.86–27.04) | +30.69 (27.61–33.10) |
| 1 KiB | payloads: none | 6000 / 6000 | 0.30 (0.19–0.33) | 0.43 (0.37–0.48) | 0.83 (0.59–1.04) | 5.36 (5.06–5.51) | 6.34 (5.86–6.80) | 9.86 (9.07–11.81) | +5.06 (4.87–5.19) | +5.91 (5.50–6.36) | +9.02 (8.19–11.38) |
| 64 KiB | payloads: redacted | 3000 / 3000 | 1.07 (0.85–1.15) | 2.29 (1.97–2.60) | 4.24 (3.87–5.19) | 38.00 (34.87–40.35) | 48.10 (42.96–48.57) | 54.36 (51.60–58.28) | +36.93 (33.89–39.23) | +45.80 (40.47–46.45) | +50.13 (47.47–53.84) |
| 64 KiB | payloads: none | 3000 / 3000 | 1.07 (0.85–1.15) | 2.29 (1.97–2.60) | 4.24 (3.87–5.19) | 29.86 (27.71–30.66) | 37.11 (33.73–37.94) | 40.97 (38.14–43.44) | +28.80 (26.84–29.52) | +34.82 (31.13–35.85) | +36.73 (33.49–39.38) |
| 1 MiB | payloads: redacted | 600 / 600 | 17.81 (16.76–18.93) | 27.14 (25.28–28.38) | 29.89 (28.57–32.20) | 136.92 (130.99–142.77) | 170.14 (153.50–199.07) | 203.78 (187.84–210.80) | +119.11 (113.96–124.06) | +143.00 (127.55–171.25) | +173.89 (155.84–181.71) |
| 1 MiB | payloads: none | 600 / 600 | 17.81 (16.76–18.93) | 27.14 (25.28–28.38) | 29.89 (28.57–32.20) | 125.49 (121.85–129.54) | 142.96 (137.64–146.21) | 152.75 (145.95–162.71) | +107.68 (104.58–110.85) | +115.82 (111.23–119.02) | +122.85 (116.19–133.45) |
| 128 KiB slash-heavy (R6b-10) | payloads: redacted | 1200 / 1200 | 2.25 (1.89–2.33) | 4.83 (3.85–5.66) | 7.33 (6.38–11.39) | 92.45 (86.10–96.18) | 105.93 (99.16–109.11) | 114.38 (108.93–118.47) | +90.19 (83.97–94.08) | +101.10 (94.78–104.13) | +107.05 (101.18–111.42) |
| 128 KiB slash-heavy (R6b-10) | payloads: none | 1200 / 1200 | 2.25 (1.89–2.33) | 4.83 (3.85–5.66) | 7.33 (6.38–11.39) | 83.86 (78.10–86.31) | 93.72 (85.62–97.17) | 102.13 (94.80–104.39) | +81.61 (76.22–84.07) | +88.89 (81.52–92.27) | +94.80 (86.26–97.20) |
| real server: server-filesystem `read_text_file`, 64 KiB | payloads: redacted | 3000 / 3000 | 1.53 (1.30–1.59) | 2.63 (2.15–3.25) | 6.64 (6.18–7.05) | 43.16 (42.30–43.75) | 47.88 (47.06–49.04) | 57.37 (51.21–62.01) | +41.63 (40.97–42.17) | +45.25 (44.33–46.39) | +50.73 (44.42–55.72) |

Run-to-run variance (ci): p50 of each launch, and of each VM.

| size | arm | launch p50: min / median / max | CV of launch p50 | p50 per VM |
|---|---|---|---|---|
| 1 KiB | direct | 0.12 / 0.30 / 0.38 | 25.7% | 0.32, 0.19, 0.33 |
| 1 KiB | gateway/redacted | 13.72 / 18.37 / 19.48 | 12.9% | 18.72, 14.01, 18.41 |
| 1 KiB | gateway/none | 4.93 / 5.41 / 5.59 | 4.0% | 5.42, 5.05, 5.52 |
| 64 KiB | direct | 0.80 / 1.10 / 1.25 | 14.0% | 1.14, 0.84, 1.12 |
| 64 KiB | gateway/redacted | 34.29 / 39.68 / 40.95 | 6.8% | 39.94, 34.71, 40.23 |
| 64 KiB | gateway/none | 27.52 / 30.28 / 30.89 | 4.6% | 30.27, 27.68, 30.67 |
| 1 MiB | direct | 15.20 / 18.46 / 22.45 | 9.1% | 17.44, 16.93, 18.61 |
| 1 MiB | gateway/redacted | 126.96 / 136.94 / 145.66 | 3.9% | 136.10, 130.53, 142.86 |
| 1 MiB | gateway/none | 120.02 / 125.47 / 133.17 | 3.2% | 124.43, 121.87, 129.72 |
| 128 KiB slash-heavy (R6b-10) | direct | 1.70 / 2.29 / 2.54 | 10.8% | 2.28, 1.88, 2.34 |
| 128 KiB slash-heavy (R6b-10) | gateway/redacted | 84.50 / 94.03 / 97.54 | 5.0% | 93.82, 85.83, 96.48 |
| 128 KiB slash-heavy (R6b-10) | gateway/none | 77.27 / 84.00 / 87.11 | 4.3% | 83.88, 78.03, 86.42 |
| real server: server-filesystem `read_text_file`, 64 KiB | direct | 1.22 / 1.56 / 1.63 | 9.5% | 1.55, 1.30, 1.59 |
| real server: server-filesystem `read_text_file`, 64 KiB | gateway/redacted | 41.80 / 43.52 / 44.14 | 1.7% | 43.67, 42.24, 43.62 |

### Laptop (reduced set)

| size | gateway arm | calls (direct / gateway) | direct p50 | p95 | p99 | gateway p50 | p95 | p99 | Δ p50 | Δ p95 | Δ p99 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 MiB | payloads: redacted | 200 / 200 | 45.48 (37.18–57.57) | 78.30 (61.62–105.39) | 107.97 (68.72–109.53) | 293.40 (252.63–328.60) | 499.26 (370.32–615.08) | 620.56 (415.51–674.10) | +247.92 (214.94–278.81) | +420.96 (299.64–527.75) | +512.59 (310.12–575.60) |
| 128 KiB slash-heavy (R6b-10) | payloads: redacted | 400 / 400 | 5.20 (4.70–5.76) | 9.49 (7.26–13.02) | 17.80 (13.02–22.26) | 228.80 (204.16–251.15) | 366.27 (286.40–463.86) | 500.14 (342.41–858.80) | +223.60 (199.47–249.87) | +356.78 (275.19–454.62) | +482.35 (320.72–841.94) |

Run-to-run variance (laptop): p50 of each launch, and of each VM.

| size | arm | launch p50: min / median / max | CV of launch p50 | p50 per VM |
|---|---|---|---|---|
| 1 MiB | direct | 32.46 / 50.01 / 71.23 | 27.4% | 45.48 |
| 1 MiB | gateway/redacted | 235.83 / 301.35 / 394.61 | 18.1% | 293.40 |
| 128 KiB slash-heavy (R6b-10) | direct | 4.14 / 5.04 / 6.90 | 16.7% | 5.20 |
| 128 KiB slash-heavy (R6b-10) | gateway/redacted | 187.23 / 233.55 / 333.65 | 18.9% | 228.80 |

## B — cost breakdown of one `tools/call`

Stages are timestamped inside the gateway process by the internal timing hook (bench entry `bench/perf/timed-gateway.mts`, hook on).
**Gateway overhead** = client round trip − `up.wait` (upstream pipe + fixture). `redact` and `store.write` are the parts of the three `audit.*` stages
spent redacting payloads and inserting into SQLite. **Unattributed** = overhead − the stages listed (pipe transfer to and from the client, scheduling).

### CI (primary): GitHub-hosted `ubuntu-latest`, three replicate VMs

**1 KiB** — round trip p50 16.67 (14.39–18.89); `up.wait` p50 0.38 (0.31–0.42); gateway overhead p50 16.28 (13.96–18.54), mean 16.86.

| stage | p50 | mean | share of mean overhead |
|---|---|---|---|
| `down.parse` | 0.03 (0.03–0.03) | 0.03 | 0.2% |
| `down.validate` | 0.08 (0.07–0.09) | 0.08 | 0.5% |
| `resolve` | 0.00 (0.00–0.01) | 0.00 | 0.0% |
| `decide` | 4.55 (4.14–4.94) | 4.61 | 27.3% |
| `audit.decision` | 10.43 (8.51–12.23) | 10.85 | 64.4% |
| `sent` | 0.02 (0.01–0.02) | 0.02 | 0.1% |
| `up.send` | 0.03 (0.03–0.04) | 0.04 | 0.2% |
| `up.parse` | 0.05 (0.04–0.05) | 0.05 | 0.3% |
| `up.validate` | 0.06 (0.06–0.08) | 0.07 | 0.4% |
| `ingest` | 0.26 (0.25–0.27) | 0.27 | 1.6% |
| `audit.ingest` | 0.21 (0.18–0.22) | 0.27 | 1.6% |
| `audit.request` | 0.15 (0.11–0.15) | 0.18 | 1.1% |
| `down.respond` | 0.02 (0.02–0.02) | 0.02 | 0.1% |
| `down.send` | 0.03 (0.03–0.03) | 0.03 | 0.2% |
| `down.drain` | 0.00 (0.00–0.00) | 0.00 | 0.0% |
| of which `redact` | 10.49 (8.56–12.31) | 10.86 | 64.4% |
| of which `store.write` | 0.22 (0.20–0.25) | 0.43 | 2.5% |
| SDK parse + validation (4 stages) | | 0.23 | 1.4% |
| unattributed | | 0.33 | 2.0% |

**1 MiB** — round trip p50 132.85 (129.04–137.24); `up.wait` p50 13.20 (11.59–14.13); gateway overhead p50 118.89 (114.63–123.35), mean 120.91.

| stage | p50 | mean | share of mean overhead |
|---|---|---|---|
| `down.parse` | 1.39 (1.38–1.40) | 1.49 | 1.2% |
| `down.validate` | 0.13 (0.12–0.13) | 0.14 | 0.1% |
| `resolve` | 0.01 (0.01–0.01) | 0.01 | 0.0% |
| `decide` | 15.85 (15.17–16.86) | 16.02 | 13.3% |
| `audit.decision` | 1.55 (1.35–1.90) | 1.58 | 1.3% |
| `sent` | 0.02 (0.02–0.02) | 0.02 | 0.0% |
| `up.send` | 4.13 (4.05–4.17) | 4.13 | 3.4% |
| `up.parse` | 3.11 (2.88–3.35) | 2.92 | 2.4% |
| `up.validate` | 0.10 (0.10–0.10) | 0.10 | 0.1% |
| `ingest` | 71.54 (67.01–75.08) | 71.75 | 59.3% |
| `audit.ingest` | 0.40 (0.37–0.47) | 2.45 | 2.0% |
| `audit.request` | 1.92 (1.86–2.26) | 2.40 | 2.0% |
| `down.respond` | 0.05 (0.05–0.06) | 0.05 | 0.0% |
| `down.send` | 4.19 (4.13–4.22) | 4.19 | 3.5% |
| `down.drain` | 2.02 (1.81–2.13) | 3.19 | 2.6% |
| of which `redact` | 3.51 (3.04–3.83) | 4.78 | 4.0% |
| of which `store.write` | 0.41 (0.39–0.43) | 1.57 | 1.3% |
| SDK parse + validation (4 stages) | | 4.65 | 3.8% |
| unattributed | | 10.47 | 8.7% |

**128 KiB slash-heavy (R6b-10)** — round trip p50 94.81 (88.59–98.60); `up.wait` p50 1.73 (1.53–1.82); gateway overhead p50 92.90 (87.04–96.61), mean 93.26.

| stage | p50 | mean | share of mean overhead |
|---|---|---|---|
| `down.parse` | 0.25 (0.24–0.26) | 0.26 | 0.3% |
| `down.validate` | 0.10 (0.09–0.10) | 0.10 | 0.1% |
| `resolve` | 0.01 (0.01–0.01) | 0.01 | 0.0% |
| `decide` | 44.22 (41.72–45.66) | 44.38 | 47.6% |
| `audit.decision` | 4.69 (3.90–5.53) | 5.00 | 5.4% |
| `sent` | 0.02 (0.02–0.02) | 0.02 | 0.0% |
| `up.send` | 0.64 (0.62–0.66) | 0.64 | 0.7% |
| `up.parse` | 0.27 (0.25–0.28) | 0.27 | 0.3% |
| `up.validate` | 0.07 (0.07–0.07) | 0.07 | 0.1% |
| `ingest` | 34.82 (33.19–36.15) | 35.03 | 37.6% |
| `audit.ingest` | 0.28 (0.25–0.30) | 0.46 | 0.5% |
| `audit.request` | 4.30 (3.93–4.49) | 4.54 | 4.9% |
| `down.respond` | 0.05 (0.03–0.05) | 0.05 | 0.0% |
| `down.send` | 0.63 (0.61–0.66) | 0.63 | 0.7% |
| `down.drain` | 0.00 (0.00–0.00) | 0.00 | 0.0% |
| of which `redact` | 8.74 (7.71–9.85) | 9.16 | 9.8% |
| of which `store.write` | 0.39 (0.35–0.41) | 0.80 | 0.9% |
| SDK parse + validation (4 stages) | | 0.71 | 0.8% |
| unattributed | | 1.80 | 1.9% |

**Hook overhead** (Δ p50, paired by launch):

| size | bench entry, hook on − hook off | bench entry, hook off − CLI |
|---|---|---|
| 1 KiB | -0.06 (-0.33–0.45) | +0.01 (-0.39–0.34) |
| 1 MiB | +0.14 (-3.03–3.38) | +1.91 (-0.82–4.96) |
| 128 KiB slash-heavy (R6b-10) | -0.03 (-0.64–0.95) | +1.02 (0.13–1.97) |

### Laptop (reduced set)

**1 MiB** — round trip p50 322.50 (289.64–347.92); `up.wait` p50 27.83 (24.94–32.71); gateway overhead p50 291.21 (262.67–318.24), mean 298.23.

| stage | p50 | mean | share of mean overhead |
|---|---|---|---|
| `down.parse` | 2.12 (1.92–2.32) | 2.34 | 0.8% |
| `down.validate` | 0.32 (0.29–0.34) | 0.45 | 0.1% |
| `resolve` | 0.02 (0.02–0.03) | 0.06 | 0.0% |
| `decide` | 39.83 (35.91–42.74) | 41.96 | 14.1% |
| `audit.decision` | 4.20 (4.00–4.65) | 4.98 | 1.7% |
| `sent` | 0.04 (0.04–0.05) | 0.05 | 0.0% |
| `up.send` | 7.47 (6.97–7.92) | 8.43 | 2.8% |
| `up.parse` | 6.95 (6.57–7.98) | 7.66 | 2.6% |
| `up.validate` | 0.31 (0.29–0.33) | 0.43 | 0.1% |
| `ingest` | 178.98 (156.44–195.82) | 185.15 | 62.1% |
| `audit.ingest` | 1.01 (0.93–1.11) | 1.10 | 0.4% |
| `audit.request` | 4.43 (3.98–4.65) | 4.99 | 1.7% |
| `down.respond` | 0.08 (0.08–0.09) | 0.11 | 0.0% |
| `down.send` | 13.78 (12.66–15.65) | 15.61 | 5.2% |
| `down.drain` | 0.02 (0.01–0.02) | 0.02 | 0.0% |
| of which `redact` | 8.25 (7.76–8.75) | 9.25 | 3.1% |
| of which `store.write` | 1.44 (1.33–1.55) | 1.64 | 0.6% |
| SDK parse + validation (4 stages) | | 10.88 | 3.6% |
| unattributed | | 24.90 | 8.4% |

**128 KiB slash-heavy (R6b-10)** — round trip p50 230.16 (199.52–247.33); `up.wait` p50 3.11 (2.89–3.26); gateway overhead p50 226.79 (196.42–243.70), mean 230.76.

| stage | p50 | mean | share of mean overhead |
|---|---|---|---|
| `down.parse` | 0.37 (0.36–0.40) | 0.50 | 0.2% |
| `down.validate` | 0.17 (0.16–0.18) | 0.23 | 0.1% |
| `resolve` | 0.01 (0.01–0.01) | 0.01 | 0.0% |
| `decide` | 108.28 (96.00–115.83) | 112.48 | 48.7% |
| `audit.decision` | 11.73 (10.56–13.08) | 13.01 | 5.6% |
| `sent` | 0.04 (0.04–0.05) | 0.05 | 0.0% |
| `up.send` | 0.89 (0.86–0.93) | 0.97 | 0.4% |
| `up.parse` | 0.38 (0.37–0.42) | 0.43 | 0.2% |
| `up.validate` | 0.12 (0.12–0.13) | 0.15 | 0.1% |
| `ingest` | 83.27 (74.70–89.76) | 87.25 | 37.8% |
| `audit.ingest` | 0.61 (0.58–0.66) | 0.87 | 0.4% |
| `audit.request` | 8.93 (8.55–9.43) | 10.51 | 4.6% |
| `down.respond` | 0.07 (0.07–0.07) | 0.08 | 0.0% |
| `down.send` | 1.16 (1.10–1.22) | 1.25 | 0.5% |
| `down.drain` | 0.01 (0.01–0.01) | 0.01 | 0.0% |
| of which `redact` | 20.40 (18.63–22.29) | 22.07 | 9.6% |
| of which `store.write` | 1.18 (1.14–1.26) | 2.26 | 1.0% |
| SDK parse + validation (4 stages) | | 1.31 | 0.6% |
| unattributed | | 2.95 | 1.3% |

**Hook overhead** (Δ p50, paired by launch):

| size | bench entry, hook on − hook off | bench entry, hook off − CLI |
|---|---|---|
| 1 MiB | +7.32 (-20.65–31.81) | +24.86 (-3.46–71.05) |
| 128 KiB slash-heavy (R6b-10) | -6.41 (-19.12–3.35) | -2.85 (-16.69–9.42) |

## D — decision level, in process (ci)

The `bench:policy` configuration. Whole decision (attribution + policy + invariant).

| case | calls | p50 | p95 | p99 | denied by the 50 ms policy deadline |
|---|---|---|---|---|---|
| small arguments | 60000 | 0.31 (0.21–0.33) | 0.51 (0.40–0.61) | 1.02 (0.77–1.13) | 0 / 60000 (0.0%; 0.0% – 0.0%) |
| 128 KB body | 3000 | 24.36 (22.85–25.03) | 26.03 (24.04–26.61) | 29.63 (26.37–31.94) | 0 / 3000 (0.0%; 0.0% – 0.1%) |
| 128 KB slash-heavy body (R6b-10) | 3000 | 39.30 (36.51–40.32) | 42.56 (38.96–43.57) | 49.22 (44.73–52.98) | 0 / 3000 (0.0%; 0.0% – 0.1%) |
| 1 MiB body (policy size check: fast deny) | 1500 | 13.88 (12.78–15.45) | 16.03 (14.01–16.57) | 18.40 (14.77–23.35) | 0 / 1500 (0.0%; 0.0% – 0.3%) |
| 64-character prose body, empty index | 15000 | 0.41 (0.30–0.46) | 0.78 (0.61–0.85) | 1.27 (1.18–1.34) | 0 / 15000 (0.0%; 0.0% – 0.0%) |
| 64-character prose body, Tier A full (32 MiB) | 6000 | 11.09 (10.80–12.29) | 12.91 (11.56–13.20) | 13.77 (12.25–14.22) | 0 / 6000 (0.0%; 0.0% – 0.1%) |
| 8 KiB prose body, Tier A full (32 MiB) — amendment 2 | 600 | 82.21 (80.69–82.56) | 84.84 (84.21–86.07) | 90.70 (86.20–96.24) | 0 / 600 (0.0%; 0.0% – 0.6%) |

Full-index case: 1717 outputs of 8 KiB ingested, Tier A 32.0 MiB in 1716 outputs, 1 evicted.

## M2 — long session (ci)

4,000 calls reading 8 KiB files of identifier-free prose through `server-filesystem` and a real gateway process (amendment 1). Medians across launches (and VMs); MiB.

| budget | calls | RSS | heapUsed | Tier A | Tier B entries | evicted |
|---|---|---|---|---|---|---|
| 32 | 100 | 133.7 | 39.1 | 3.4 | 0 | 0 |
| 32 | 1000 | 190.4 | 68.4 | 32.0 | 0 | 66 |
| 32 | 2000 | 198.1 | 66.3 | 32.0 | 0 | 1066 |
| 32 | 3000 | 199.9 | 63.5 | 32.0 | 0 | 2066 |
| 32 | 4000 | 201.4 | 68.2 | 32.0 | 0 | 3066 |
| 4 | 100 | 133.5 | 39.0 | 3.4 | 0 | 0 |
| 4 | 1000 | 174.6 | 45.3 | 4.0 | 0 | 884 |
| 4 | 2000 | 174.8 | 40.4 | 4.0 | 0 | 1884 |
| 4 | 3000 | 175.3 | 41.0 | 4.0 | 0 | 2884 |
| 4 | 4000 | 175.1 | 42.6 | 4.0 | 0 | 3884 |

- budget 32 MiB: max Tier A over every sample 32.0 MiB (within the budget); RSS growth from the first eviction to the end: median 5.7%, max 9.0%.
- budget 4 MiB: max Tier A over every sample 4.0 MiB (within the budget); RSS growth from the first eviction to the end: median 23.5%, max 44.9%.

