#!/usr/bin/env node
/**
 * Builds bench/corpus/benign-outputs-synthetic.json: synthetic but realistic BENIGN tool outputs, for
 * the false-positive side of `npm run bench:entropy`.
 *
 *   node bench/corpus/build-benign-outputs.mjs
 *
 * Each template reproduces the shape of a real tool's output (cloud CLIs, kubectl, docker, payment and
 * issue-tracker APIs, tracing, analytics query results, document stores) and fills it with the kind of
 * random-looking identifiers those tools really return: instance and request ids, pod hashes, digests,
 * object ids, document ids, trace ids. Those are exactly what an entropy detector confuses with secrets,
 * so this set is deliberately hard. It contains NO secrets and no provider secret formats (no keys,
 * tokens or passwords), so nothing here should be flagged by a known-format rule.
 *
 * Deterministic: a seeded PRNG, so the file is reproducible and reviewable. Splits are assigned in the
 * benchmark by a stable hash of the id, never by looking at results.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// mulberry32
function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const B62 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const B36 = 'abcdefghijklmnopqrstuvwxyz0123456789';
const HEX = '0123456789abcdef';
const B64URL = B62 + '-_';
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

function gen(r) {
  const s = (alpha, n) => Array.from({ length: n }, () => alpha[Math.floor(r() * alpha.length)]).join('');
  const pick = (xs) => xs[Math.floor(r() * xs.length)];
  const int = (lo, hi) => lo + Math.floor(r() * (hi - lo + 1));
  const uuid = (v = 4) => `${s(HEX, 8)}-${s(HEX, 4)}-${v}${s(HEX, 3)}-${pick(['8', '9', 'a', 'b'])}${s(HEX, 3)}-${s(HEX, 12)}`;
  const iso = () => `2026-${String(int(1, 9)).padStart(2, '0')}-${String(int(1, 28)).padStart(2, '0')}T${String(int(0, 23)).padStart(2, '0')}:${String(int(0, 59)).padStart(2, '0')}:${String(int(0, 59)).padStart(2, '0')}Z`;
  return { s, pick, int, uuid, iso };
}

const names = ['alice', 'bob', 'carol', 'dave', 'erin', 'frank', 'grace', 'heidi'];
const words = ['billing', 'search', 'checkout', 'onboarding', 'reports', 'gateway', 'worker', 'scheduler', 'pricing', 'notifications'];

const templates = {
  'aws-ec2-describe-instances': (g) => JSON.stringify({
    Reservations: Array.from({ length: 2 }, () => ({
      ReservationId: `r-0${g.s(HEX, 16)}`,
      OwnerId: String(g.int(100000000000, 999999999999)),
      Instances: [{
        InstanceId: `i-0${g.s(HEX, 16)}`, ImageId: `ami-0${g.s(HEX, 16)}`, InstanceType: g.pick(['t3.micro', 'm6i.large', 'c7g.xlarge']),
        SubnetId: `subnet-0${g.s(HEX, 16)}`, VpcId: `vpc-0${g.s(HEX, 16)}`, PrivateIpAddress: `10.0.${g.int(0, 255)}.${g.int(1, 254)}`,
        LaunchTime: g.iso(), State: { Code: 16, Name: 'running' },
        NetworkInterfaces: [{ NetworkInterfaceId: `eni-0${g.s(HEX, 16)}`, MacAddress: Array.from({ length: 6 }, () => g.s(HEX, 2)).join(':') }],
        Tags: [{ Key: 'Name', Value: `${g.pick(words)}-${g.int(1, 9)}` }],
      }],
    })),
  }, null, 2),
  'aws-s3-ls': (g) => Array.from({ length: 12 }, () => `${g.iso().replace('T', ' ').replace('Z', '')}  ${String(g.int(100, 9_000_000)).padStart(10)} exports/${g.pick(words)}/${g.uuid()}.parquet`).join('\n'),
  'aws-s3-head-object': (g) => JSON.stringify({ AcceptRanges: 'bytes', LastModified: g.iso(), ContentLength: g.int(1000, 900000), ETag: `"${g.s(HEX, 32)}"`, VersionId: g.s(B62 + '._', 32), ContentType: 'application/octet-stream', ServerSideEncryption: 'AES256', Metadata: {} }, null, 2),
  'aws-cloudtrail-event': (g) => JSON.stringify({ eventVersion: '1.09', eventTime: g.iso(), eventSource: 's3.amazonaws.com', eventName: 'GetObject', awsRegion: 'eu-west-1', requestID: g.s('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', 16), eventID: g.uuid(), readOnly: true, recipientAccountId: String(g.int(100000000000, 999999999999)), requestParameters: { bucketName: `${g.pick(words)}-exports`, key: `daily/${g.uuid()}.csv` } }, null, 2),
  'kubectl-get-pods': (g) => ['NAME                                READY   STATUS    RESTARTS   AGE', ...Array.from({ length: 10 }, () => `${g.pick(words)}-${g.s(B36, 10)}-${g.s(B36, 5)}`.padEnd(36) + `1/1     Running   ${g.int(0, 3)}          ${g.int(1, 40)}d`)].join('\n'),
  'kubectl-describe-pod': (g) => `Name:         ${g.pick(words)}-${g.s(B36, 10)}-${g.s(B36, 5)}\nNamespace:    production\nNode:         ip-10-0-${g.int(1, 200)}-${g.int(1, 200)}.eu-west-1.compute.internal\nStart Time:   ${g.iso()}\nLabels:       app=${g.pick(words)}\n              pod-template-hash=${g.s(B36, 10)}\nStatus:       Running\nIP:           10.1.${g.int(0, 255)}.${g.int(1, 254)}\nControlled By:  ReplicaSet/${g.pick(words)}-${g.s(B36, 10)}\nContainers:\n  app:\n    Container ID:   containerd://${g.s(HEX, 64)}\n    Image:          registry.example/${g.pick(words)}:1.${g.int(0, 40)}.${g.int(0, 9)}\n    Image ID:       registry.example/${g.pick(words)}@sha256:${g.s(HEX, 64)}\n    State:          Running\n      Started:      ${g.iso()}\n    Ready:          True\nEvents:  <none>`,
  'docker-images': (g) => ['REPOSITORY                    TAG       IMAGE ID       CREATED        SIZE', ...Array.from({ length: 8 }, () => `registry.example/${g.pick(words)}`.padEnd(30) + `1.${g.int(0, 9)}.${g.int(0, 9)}     ${g.s(HEX, 12)}   ${g.int(2, 30)} days ago    ${g.int(40, 900)}MB`)].join('\n'),
  'docker-inspect': (g) => JSON.stringify([{ Id: `sha256:${g.s(HEX, 64)}`, RepoDigests: [`registry.example/${g.pick(words)}@sha256:${g.s(HEX, 64)}`], Created: g.iso(), Config: { Env: ['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin', 'NODE_VERSION=22.19.0'], Cmd: ['node', 'dist/main.js'] }, RootFS: { Type: 'layers', Layers: Array.from({ length: 5 }, () => `sha256:${g.s(HEX, 64)}`) } }], null, 2),
  'payments-customer-list': (g) => JSON.stringify({ object: 'list', has_more: true, data: Array.from({ length: 6 }, () => ({ id: `cus_${g.s(B62, 14)}`, object: 'customer', created: g.int(1.7e9, 1.79e9), email: `${g.pick(names)}@example.com`, invoice_prefix: g.s('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', 8), default_source: `card_${g.s(B62, 24)}`, metadata: { plan: g.pick(['free', 'pro', 'team']) } })) }, null, 2),
  'payments-intent': (g) => JSON.stringify({ id: `pi_${g.s(B62, 24)}`, object: 'payment_intent', amount: g.int(100, 90000), currency: 'eur', status: 'succeeded', customer: `cus_${g.s(B62, 14)}`, latest_charge: `ch_${g.s(B62, 24)}`, payment_method: `pm_${g.s(B62, 24)}`, created: g.int(1.7e9, 1.79e9) }, null, 2),
  'issue-tracker-issue': (g) => JSON.stringify({ id: String(g.int(10000, 99999)), key: `${g.pick(['OPS', 'WEB', 'API'])}-${g.int(10, 4000)}`, fields: { summary: `${g.pick(words)} job fails on retry`, status: { name: g.pick(['To Do', 'In Progress', 'Done']) }, assignee: { accountId: `${g.s(HEX, 6)}:${g.uuid()}`, displayName: g.pick(names) }, created: g.iso(), description: 'Steps: run the nightly job, observe the second retry exits with code 137.' } }, null, 2),
  'error-tracker-event': (g) => JSON.stringify({ eventID: g.s(HEX, 32), groupID: String(g.int(1e9, 9e9)), title: "TypeError: Cannot read properties of undefined (reading 'id')", culprit: `app/${g.pick(words)}/handler.ts in handle`, dateCreated: g.iso(), contexts: { trace: { trace_id: g.s(HEX, 32), span_id: g.s(HEX, 16), op: 'http.server' } }, tags: [['release', `${g.pick(words)}@${g.s(HEX, 12)}`], ['environment', 'production']] }, null, 2),
  'otel-trace-spans': (g) => JSON.stringify({ resourceSpans: [{ resource: { attributes: [{ key: 'service.name', value: { stringValue: g.pick(words) } }] }, scopeSpans: [{ spans: Array.from({ length: 5 }, () => ({ traceId: g.s(HEX, 32), spanId: g.s(HEX, 16), parentSpanId: g.s(HEX, 16), name: `GET /api/${g.pick(words)}`, startTimeUnixNano: String(g.int(1.7e9, 1.79e9)) + '000000000' })) }] }] }, null, 2),
  'analytics-sql-result': (g) => JSON.stringify({ columns: ['uuid', 'event', 'distinct_id', 'timestamp', 'properties'], results: Array.from({ length: 8 }, () => [g.uuid(7), g.pick(['$pageview', 'signed_up', 'checkout_started', '$autocapture']), g.pick([g.uuid(7), `${g.pick(names)}@example.com`, g.s(B36, 25)]), g.iso(), JSON.stringify({ $session_id: g.uuid(7), $current_url: `https://app.example/${g.pick(words)}`, $browser: g.pick(['Chrome', 'Firefox', 'Safari']), $lib: 'web' })]) }, null, 2),
  'chat-history': (g) => JSON.stringify({ ok: true, messages: Array.from({ length: 6 }, () => ({ type: 'message', user: `U0${g.s('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', 9)}`, text: `deploy of ${g.pick(words)} finished`, ts: `${g.int(1.7e9, 1.79e9)}.${String(g.int(0, 999999)).padStart(6, '0')}`, client_msg_id: g.uuid() })), has_more: false }, null, 2),
  'ci-runs-list': (g) => JSON.stringify({ total_count: 40, workflow_runs: Array.from({ length: 4 }, () => ({ id: g.int(1e10, 9e10), name: 'ci', head_branch: 'main', head_sha: g.s(HEX, 40), run_number: g.int(10, 900), status: 'completed', conclusion: g.pick(['success', 'failure']), node_id: `WFR_kwLO${g.s(B64URL, 16)}`, check_suite_node_id: `CS_kwDO${g.s(B64URL, 20)}`, created_at: g.iso() })) }, null, 2),
  'drive-files-list': (g) => JSON.stringify({ files: Array.from({ length: 6 }, () => ({ id: `1${g.s(B64URL, 32)}`, name: `${g.pick(words)} plan Q${g.int(1, 4)}.docx`, mimeType: 'application/vnd.google-apps.document', modifiedTime: g.iso() })), nextPageToken: undefined }, null, 2),
  'notes-page-list': (g) => JSON.stringify({ results: Array.from({ length: 5 }, () => ({ object: 'page', id: g.uuid(), url: `https://notes.example/${g.pick(words)}-${g.s(HEX, 32)}`, created_time: g.iso(), properties: { title: `${g.pick(words)} meeting notes` } })) }, null, 2),
  'mongo-find': (g) => Array.from({ length: 6 }, () => `{ _id: ObjectId('${g.s(HEX, 24)}'), user: '${g.pick(names)}', cart: [ ObjectId('${g.s(HEX, 24)}') ], updatedAt: ISODate('${g.iso()}') }`).join('\n'),
  'postgres-explain': (g) => `Hash Join  (cost=${g.int(10, 900)}.00..${g.int(1000, 9000)}.12 rows=${g.int(10, 9000)} width=${g.int(8, 200)})\n  Hash Cond: (orders.customer_id = customers.id)\n  ->  Seq Scan on orders  (cost=0.00..${g.int(100, 900)}.00 rows=${g.int(1000, 90000)} width=48)\n  ->  Hash  (cost=${g.int(10, 99)}.00..${g.int(100, 999)}.00 rows=${g.int(100, 9000)} width=16)\n        ->  Index Scan using customers_pkey on customers\nPlanning Time: 0.${g.int(100, 999)} ms\nExecution Time: ${g.int(1, 90)}.${g.int(100, 999)} ms`,
  'app-log-lines': (g) => Array.from({ length: 14 }, () => `${g.iso()} INFO  [${g.pick(words)}] request_id=${g.s(CROCKFORD, 26)} trace=${g.s(HEX, 32)} user=${g.s(B36, 25)} status=${g.pick([200, 200, 201, 304, 404])} dur=${g.int(1, 900)}ms`).join('\n'),
  'nanoid-records': (g) => JSON.stringify(Array.from({ length: 8 }, () => ({ id: g.s(B64URL, 21), slug: `${g.pick(words)}-${g.s(B36, 6)}`, created: g.iso() })), null, 2),
  'cdn-response-headers': (g) => `HTTP/2 200\ncontent-type: text/html; charset=utf-8\ncache-control: public, max-age=300\netag: W/"${g.s(HEX, 8)}-${g.s(B62, 27)}"\nx-request-id: ${g.uuid()}\nx-amz-cf-id: ${g.s(B62 + '_-', 56)}==\nserver-timing: cdn-cache;desc=HIT, edge;dur=${g.int(1, 40)}\nvia: 1.1 ${g.s(HEX, 32)}.cloudfront.example (CloudFront)`,
  'terraform-state-list': (g) => Array.from({ length: 10 }, () => `${g.pick(['aws_instance', 'aws_s3_bucket', 'aws_iam_role', 'aws_lambda_function'])}.${g.pick(words)}_${g.int(1, 9)}  id=${g.pick([`i-0${g.s(HEX, 16)}`, `${g.pick(words)}-${g.s(B36, 8)}`, `AROA${g.s('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', 17)}`])}`).join('\n'),
  'deployments-list': (g) => JSON.stringify({ deployments: Array.from({ length: 5 }, () => ({ uid: `dpl_${g.s(B62, 28)}`, name: g.pick(words), url: `${g.pick(words)}-${g.s(B36, 9)}-team.app.example`, state: 'READY', created: g.int(1.7e12, 1.79e12), meta: { commitSha: g.s(HEX, 40), commitMessage: 'fix: handle empty cart' } })) }, null, 2),
  'video-embed-list': (g) => JSON.stringify({ items: Array.from({ length: 6 }, () => ({ kind: 'video', etag: g.s(B64URL, 27), id: g.s(B64URL, 11), title: `${g.pick(words)} walkthrough` })), pageInfo: { totalResults: 6 } }, null, 2),
  'npm-audit-json': (g) => JSON.stringify({ auditReportVersion: 2, vulnerabilities: {}, metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 }, dependencies: { prod: g.int(10, 90), dev: g.int(100, 900), total: g.int(200, 999) } } }, null, 2),
  'feature-flags-list': (g) => JSON.stringify({ results: Array.from({ length: 5 }, () => ({ id: g.int(1000, 99999), key: `${g.pick(words)}-${g.pick(['v2', 'beta', 'rollout'])}`, active: g.pick([true, false]), created_by: { uuid: g.uuid(7), first_name: g.pick(names) }, filters: { groups: [{ rollout_percentage: g.int(0, 100) }] } })) }, null, 2),
  'calendar-events': (g) => JSON.stringify({ items: Array.from({ length: 4 }, () => ({ id: g.s(B36.slice(0, 32), 26), iCalUID: `${g.s(B36, 26)}@calendar.example`, summary: `${g.pick(words)} sync`, start: { dateTime: g.iso() }, hangoutLink: `https://meet.example/${g.s('abcdefghijklmnopqrstuvwxyz', 3)}-${g.s('abcdefghijklmnopqrstuvwxyz', 4)}-${g.s('abcdefghijklmnopqrstuvwxyz', 3)}` })) }, null, 2),
  'git-lfs-pointers': (g) => Array.from({ length: 4 }, () => `version https://git-lfs.github.com/spec/v1\noid sha256:${g.s(HEX, 64)}\nsize ${g.int(1000, 90000000)}`).join('\n\n'),
  'base64-thumbnail-json': (g) => JSON.stringify({ name: 'avatar.png', width: 16, height: 16, data: `data:image/png;base64,iVBORw0KGgo${g.s(B62 + '+/', 300)}==` }),
};

const PER_TEMPLATE = 3;
const items = [];
let seed = 20261014;
for (const [name, make] of Object.entries(templates)) {
  for (let i = 1; i <= PER_TEMPLATE; i++) items.push({ id: `${name}-${i}`, template: name, text: make(gen(rng(seed++))) });
}

const here = path.dirname(fileURLToPath(import.meta.url));
const out = path.join(here, 'benign-outputs-synthetic.json');
fs.writeFileSync(out, JSON.stringify({ generator: 'bench/corpus/build-benign-outputs.mjs', note: 'Synthetic benign outputs; ids are random but none is a secret.', items }, null, 2) + '\n');
process.stdout.write(`wrote ${out}: ${items.length} outputs from ${Object.keys(templates).length} templates\n`);
