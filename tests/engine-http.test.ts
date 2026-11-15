import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import { createServer as createTcp } from 'node:net';
import type { AddressInfo } from 'node:net';
import { join } from 'node:path';
import { createHttpHandler, createTokenVerifier, generateSigningKey, serve, signAccessToken } from '../src/service-kit.ts';
import { routes, zipRead } from '../src/engine/index.ts';
import { ALL_CAPS, code, ctx, events, needsPg, PKG, reviewed, soon, withEngine } from './helpers/engine.ts';

const listen = (handler: (req: IncomingMessage, res: ServerResponse) => void): Promise<Server> => new Promise((r) => { const s = createServer(handler); s.listen(0, '127.0.0.1', () => r(s)); });
const port = (s: { address(): AddressInfo | string | null }): number => (s.address() as AddressInfo).port;

test('destination adapters: uncertain outcomes are recorded and reconciled, never blindly repeated; webhook, HTTP PUT and email handoff', needsPg, async () => {
  let mode: 'drop' | 'error' | 'ok' = 'drop'; const seen: { method: string; url: string; auth: string; idem: string; size: number }[] = []; let stored: Buffer | null = null;
  const remote = await listen((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      seen.push({ method: req.method ?? '', url: req.url ?? '', auth: String(req.headers.authorization ?? ''), idem: String(req.headers['idempotency-key'] ?? ''), size: body.byteLength });
      if (req.method === 'HEAD') { if (stored === null) { res.writeHead(404); res.end(); } else { res.writeHead(200, { 'content-length': String(stored.byteLength) }); res.end(); } return; }
      if (mode === 'drop') { stored = body; req.socket.destroy(); return; } // received, but the reply is lost
      if (mode === 'error') { res.writeHead(502); res.end('bad gateway'); return; }
      stored = body; res.writeHead(201, { 'x-request-id': 'remote-1' }); res.end('{}');
    });
  });
  const mails: string[] = [];
  const smtp = createTcp((socket) => {
    let data = false, buf = '';
    socket.write('220 sink.example.org ESMTP\r\n');
    socket.on('data', (chunk) => {
      buf += chunk.toString('utf8');
      if (data) { if (buf.includes('\r\n.\r\n')) { mails.push(buf); buf = ''; data = false; socket.write('250 queued\r\n'); } return; }
      let i: number;
      while ((i = buf.indexOf('\r\n')) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 2);
        if (/^(EHLO|HELO)/i.test(line)) socket.write('250 sink.example.org\r\n');
        else if (/^DATA/i.test(line)) { data = true; socket.write('354 go\r\n'); }
        else if (/^QUIT/i.test(line)) { socket.write('221 bye\r\n'); socket.end(); }
        else socket.write('250 ok\r\n');
      }
    });
    socket.on('error', () => undefined);
  });
  await new Promise<void>((r) => smtp.listen(0, '127.0.0.1', () => r()));
  try {
    await withEngine(async (h) => {
      const base = `http://127.0.0.1:${port(remote)}`;
      const engine = h.make({ ...h.baseConfig, destinations: { ...h.baseConfig.destinations, httpHosts: [`127.0.0.1:${port(remote)}`], allowInsecureHttp: true, secrets: { partner: 'tok-SECRET-123' }, httpTimeoutMs: 5000, smtp: { sink: { host: '127.0.0.1', port: port(smtp), from: 'releases@example.org', allowInsecure: true } } } });
      // SSRF / configuration guards
      const mk = (name: string, kind: 'http_put' | 'webhook', config: Record<string, unknown>) => engine.createDestination(ctx(), { name, kind, audiences: ['licensed_partner'], config });
      assert.equal(await code(mk('x1', 'http_put', { url: 'http://169.254.169.254/latest/meta-data' })), 'invalid_input');
      assert.equal(await code(mk('x2', 'http_put', { url: `http://user:pw@127.0.0.1:${port(remote)}/a.zip` })), 'invalid_input');
      assert.equal(await code(mk('x3', 'webhook', { url: 'file:///etc/passwd' })), 'invalid_input');
      assert.equal(await code(mk('x4', 'webhook', { url: `${base}/hook`, secretRef: 'unknown' })), 'invalid_input');
      assert.equal(await code(h.engine.createDestination(ctx(), { name: 'x5', kind: 'webhook', audiences: ['licensed_partner'], config: { url: `${base}/hook` } })), 'invalid_input', 'host not allow-listed by default');
      const put = await mk('partner drop', 'http_put', { url: `${base}/inbox/package.zip`, secretRef: 'partner' });
      assert.doesNotMatch(JSON.stringify(put), /tok-SECRET/);
      const build = (title: string) => engine.buildChronology(ctx(), { title, audience: 'licensed_partner', package: PKG, formats: ['html'] });
      const go = async (title: string, destinationId: string) => { const c = await build(title); const d = await reviewed(engine, c.id); const a = await engine.approve(ctx(), c.id, { candidateDigest: d, audience: 'licensed_partner', destinationId, expiresAt: soon() }); return { c, a, input: { approvalId: a.id, audience: 'licensed_partner', destinationId } }; };

      // 1. reply lost after the remote received the bytes → uncertain; a retry must not send again
      const one = await go('Chronology one', put.id);
      const r1 = await engine.release(ctx(), one.c.id, one.input);
      assert.equal(r1.state, 'uncertain'); assert.equal(r1.receipt, null);
      assert.equal(seen.filter((s) => s.method === 'PUT').length, 1); assert.equal(seen[0]?.auth, 'Bearer tok-SECRET-123'); assert.equal(seen[0]?.idem, r1.id);
      mode = 'ok';
      const retry = await engine.release(ctx(), one.c.id, one.input);
      assert.equal(retry.state, 'uncertain'); assert.equal(retry.replayed, true); assert.equal(retry.id, r1.id);
      assert.equal(seen.filter((s) => s.method === 'PUT').length, 1, 'no second send');
      assert.equal((await engine.distributionHistory(ctx(), { candidateId: one.c.id }))[0]?.state, 'uncertain');
      assert.ok((await events(h, 'release.delivery_uncertain')).length === 1);
      // reconciliation by probing the destination (also what the job worker does)
      const probed = await engine.probeRelease(ctx(), r1.id);
      assert.equal(probed.state, 'delivered'); assert.equal((probed.receipt as { adapterResponse: { reconciledBy: string } }).adapterResponse.reconciledBy, 'destination_probe');
      const d1 = await engine.distributionHistory(ctx(), { candidateId: one.c.id }); assert.equal(d1.length, 1); assert.equal(d1[0]?.state, 'delivered');
      assert.deepEqual(zipRead(new Uint8Array(stored as unknown as Buffer)).map((e) => e.path), ['chronology.html', 'chronology.json', 'chronology.md', 'manifest.json']);
      assert.doesNotMatch(JSON.stringify([await engine.audit(ctx()), await events(h), await engine.getRelease(ctx(), r1.id)]), /tok-SECRET/);

      // 2. gateway error → uncertain; a human records it was not delivered; the next attempt delivers exactly once
      mode = 'error'; stored = null;
      const two = await go('Chronology two', put.id);
      const r2 = await engine.release(ctx(), two.c.id, two.input);
      assert.equal(r2.state, 'uncertain');
      assert.equal((await engine.probeRelease(ctx(), r2.id)).state, 'failed', 'destination says it has no such object');
      mode = 'error';
      const three = await go('Chronology three', put.id); stored = null;
      const r3 = await engine.release(ctx(), three.c.id, three.input); assert.equal(r3.state, 'uncertain');
      stored = Buffer.from('something else entirely');
      assert.equal((await engine.probeRelease(ctx(), r3.id)).state, 'uncertain', 'probe cannot tell');
      assert.equal(await code(engine.reconcileRelease(ctx({ actor: { id: 'svc', kind: 'service', roles: [] } }), r3.id, { outcome: 'delivered', evidence: 'x' })), 'forbidden');
      const nd = await engine.reconcileRelease(ctx(), r3.id, { outcome: 'not_delivered', evidence: 'Partner confirmed by phone that nothing arrived.' });
      assert.equal(nd.state, 'failed'); assert.equal((await engine.distributionHistory(ctx(), { candidateId: three.c.id }))[0]?.state, 'not_delivered');
      mode = 'ok';
      const before = seen.filter((s) => s.method === 'PUT').length;
      const r3b = await engine.release(ctx(), three.c.id, three.input);
      assert.equal(r3b.state, 'delivered'); assert.equal(r3b.id, r3.id); assert.equal(r3b.attempts, 2); assert.equal(seen.filter((s) => s.method === 'PUT').length, before + 1);
      assert.equal((await engine.release(ctx(), three.c.id, three.input)).replayed, true); assert.equal(seen.filter((s) => s.method === 'PUT').length, before + 1);
      assert.deepEqual((await engine.distributionHistory(ctx(), { candidateId: three.c.id })).map((d) => d.state), ['not_delivered', 'delivered']);
      // human confirmation path
      mode = 'error'; const four = await go('Chronology four', put.id); const r4 = await engine.release(ctx(), four.c.id, four.input);
      const ok4 = await engine.reconcileRelease(ctx(), r4.id, { outcome: 'delivered', evidence: 'Partner acknowledged receipt in writing.' });
      assert.equal(ok4.state, 'delivered'); assert.equal((ok4.receipt as { adapterResponse: { evidence: string } }).adapterResponse.evidence, 'Partner acknowledged receipt in writing.');
      // job worker: only reconciles
      mode = 'drop'; stored = null; const five = await go('Chronology five', put.id); const r5 = await engine.release(ctx(), five.c.id, five.input); assert.equal(r5.state, 'uncertain');
      await h.sql.query(`update e12_release._jobs set run_at=now() - interval '1 second' where state='queued'`);
      assert.ok(await engine.runJobsOnce('w1') >= 1);
      assert.equal((await engine.getRelease(ctx(), r5.id)).state, 'delivered');

      // 3. connection refused → definite failure (nothing left), retry allowed
      const dead = await listen(() => undefined); const deadPort = port(dead); await new Promise((r) => dead.close(r));
      const e2 = h.make({ ...h.baseConfig, destinations: { ...h.baseConfig.destinations, httpHosts: [`127.0.0.1:${deadPort}`, `127.0.0.1:${port(remote)}`], allowInsecureHttp: true } });
      const hookDown = await e2.createDestination(ctx(), { name: 'down hook', kind: 'webhook', audiences: ['licensed_partner'], config: { url: `http://127.0.0.1:${deadPort}/hook` } });
      const six = await go('Chronology six', hookDown.id);
      assert.equal((await e2.release(ctx(), six.c.id, six.input)).state, 'failed'); assert.deepEqual(await e2.distributionHistory(ctx(), { candidateId: six.c.id }), []);
      // webhook success
      mode = 'ok';
      const hook = await e2.createDestination(ctx(), { name: 'hook', kind: 'webhook', audiences: ['licensed_partner'], config: { url: `${base}/hook` } });
      const seven = await go('Chronology seven', hook.id);
      const r7 = await e2.release(ctx(), seven.c.id, seven.input);
      assert.equal(r7.state, 'delivered'); assert.equal(seen.at(-1)?.url, '/hook'); assert.equal((r7.receipt as { adapterResponse: { status: number } }).adapterResponse.status, 201);

      // 4. email handoff: a signed, expiring link (never the package itself) through the configured SMTP server
      const mail = await engine.createDestination(ctx(), { name: 'partner email', kind: 'email', audiences: ['licensed_partner'], config: { smtp: 'sink', to: ['desk@partner.example.org'], ttlSeconds: 600 } });
      const eight = await go('Chronology eight', mail.id);
      const r8 = await engine.release(ctx(), eight.c.id, eight.input);
      assert.equal(r8.state, 'delivered', JSON.stringify(r8.adapterResponse)); assert.equal(mails.length, 1);
      const message = (mails[0] as string).replace(/\r\n\.\./g, '\r\n.').replace(/=\r\n/g, ''); // undo SMTP dot-stuffing and quoted-printable soft breaks
      assert.match(message, /To: desk@partner\.example\.org/); assert.ok(message.includes(eight.c.digest as string));
      const link = /http:\/\/127\.0\.0\.1:1\/v1\/downloads\/([A-Za-z0-9._=-]+)/.exec(message.replace(/=3D/g, '='))?.[1] as string;
      assert.equal((await engine.download(link)).sha256, (await engine.exportCandidateZip(ctx(), eight.c.id)).sha256);
      // 5. adapters whose deployment settings are missing answer `unavailable` and record a failed (not delivered) attempt
      assert.equal(await code(engine.createDestination(ctx(), { name: 'sftp', kind: 'sftp', audiences: ['licensed_partner'], config: { server: 'nowhere' } })), 'invalid_input');
      const noLinks = h.make({ ...h.baseConfig, destinations: { roots: {} } });
      const dl = await noLinks.createDestination(ctx(), { name: 'dl', kind: 'signed_download', audiences: ['licensed_partner'], config: {} });
      const nine = await go('Chronology nine', dl.id);
      assert.equal(await code(noLinks.release(ctx(), nine.c.id, nine.input)), 'unavailable'); assert.deepEqual(await noLinks.listReleases(ctx(), { candidateId: nine.c.id }), []);
    });
  } finally { remote.closeAllConnections(); await new Promise((r) => remote.close(r)); await new Promise((r) => smtp.close(r)); }
});

test('HTTP end to end: build, review, approve, dispatch to a signed download, expiry, withdrawal, isolation', needsPg, async () => {
  await withEngine(async (h) => {
    const key = generateSigningKey('k1');
    let engine = h.engine;
    const server = await serve(createHttpHandler({ name: 'E12', version: '1', routes: [], verify: async () => { throw new Error('unused'); } }), 0);
    const p = port(server); server.close();
    engine = h.make({ ...h.baseConfig, destinations: { ...h.baseConfig.destinations, publicBaseUrl: `http://127.0.0.1:${p}` } });
    const http = await serve(createHttpHandler({ name: 'E12', version: '1.0.0', routes: routes(engine), health: () => engine.health(), verify: createTokenVerifier({ publicKeys: { k1: key.publicKeyPem }, issuer: 'iap' }) }), p);
    const now = Math.floor(Date.now() / 1000);
    const token = (sub: string, over: Record<string, unknown> = {}): string => signAccessToken({ iss: 'iap', sub, kind: 'human', tid: 't1', pid: 'p1', roles: [], caps: ALL_CAPS, cmp: [], purpose: 'release', pv: '1', iat: now, exp: now + 600, jti: `j-${sub}`, ...over } as never, key);
    const call = async (method: string, path: string, body?: unknown, tok: string | null = token('owner-1'), headers: Record<string, string> = {}): Promise<{ status: number; json: any; bytes: Uint8Array }> => {
      const r = await fetch(`http://127.0.0.1:${p}${path}`, { method, headers: { ...(tok === null ? {} : { authorization: `Bearer ${tok}` }), ...(body === undefined ? {} : { 'content-type': 'application/json' }), ...headers }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
      const bytes = new Uint8Array(await r.arrayBuffer()); let json: unknown = null; try { json = JSON.parse(new TextDecoder().decode(bytes)); } catch { /* binary */ }
      return { status: r.status, json, bytes };
    };
    try {
      assert.equal((await call('GET', '/healthz', undefined, null)).json.ok, true);
      assert.equal((await call('GET', '/v1/manifest', undefined, null)).json.id, 'E12');
      assert.equal((await call('GET', '/v1/candidates', undefined, null)).status, 401);
      assert.equal((await call('POST', '/v1/packages', { kind: 'chronology', title: 'x', audience: 'legal_counsel', package: PKG }, token('reader', { caps: ['release:read'] }))).status, 403);
      const built = await call('POST', '/v1/packages', { kind: 'investigation_report', title: 'Harbour report', audience: 'legal_counsel', package: PKG, formats: ['html'] });
      assert.equal(built.status, 201); const id = built.json.id as string, digest = built.json.digest as string;
      assert.equal((await call('POST', '/v1/packages', { kind: 'nonsense', title: 'x', audience: 'legal_counsel' })).status, 400);
      assert.equal((await call('GET', `/v1/candidates/${id}/manifest`)).json.kind, 'investigation_report');
      assert.match(new TextDecoder().decode((await call('GET', `/v1/candidates/${id}/component?path=report.md`)).bytes), /ESTABLISHED/);
      assert.equal((await call('GET', `/v1/candidates/${id}/component?path=../../etc/passwd`)).status, 404);
      const zip = await call('GET', `/v1/candidates/${id}/package.zip`); assert.equal(zip.status, 200); assert.ok(zipRead(zip.bytes).some((e) => e.path === 'manifest.json'));
      const dest = await call('POST', '/v1/destinations', { name: 'counsel download', kind: 'signed_download', audiences: ['legal_counsel'], config: { ttlSeconds: 600 } }); assert.equal(dest.status, 201);
      assert.equal((await call('POST', `/v1/candidates/${id}/review`, { reviewers: ['rev-1'] })).json.state, 'in_review');
      assert.equal((await call('POST', `/v1/candidates/${id}/review/comments`, { body: 'Looks right.' }, token('rev-1'))).status, 201);
      assert.equal((await call('POST', `/v1/candidates/${id}/review/verdict`, { candidateDigest: digest, outcome: 'accepted' }, token('rev-1'))).json.state, 'reviewed');
      const authz = { candidateDigest: digest, audience: 'legal_counsel', destinationId: dest.json.id, expiresAt: soon() };
      assert.equal((await call('POST', `/v1/releases/${id}/authorize`, authz, token('agent-1', { kind: 'agent' }))).status, 403);
      assert.equal((await call('POST', `/v1/releases/${id}/authorize`, { ...authz, candidateDigest: 'c'.repeat(64) })).json.error.code, 'approval_invalid');
      const ap = await call('POST', `/v1/releases/${id}/authorize`, authz, token('owner-1'), { 'idempotency-key': 'http-ap-1' }); assert.equal(ap.status, 201);
      assert.equal((await call('POST', `/v1/releases/${id}/authorize`, authz, token('owner-1'), { 'idempotency-key': 'http-ap-1' })).json.id, ap.json.id);
      const dispatch = { approvalId: ap.json.id, audience: 'legal_counsel', destinationId: dest.json.id, recipients: ['Counsel A'] };
      assert.equal((await call('POST', `/v1/releases/${id}/dispatch`, dispatch, token('nopub', { caps: ALL_CAPS.filter((c) => c !== 'release:publish') }))).status, 403);
      const rel = await call('POST', `/v1/releases/${id}/dispatch`, dispatch); assert.equal(rel.json.state, 'delivered');
      assert.equal((await call('POST', `/v1/releases/${id}/dispatch`, dispatch)).json.replayed, true);
      assert.equal((await call('GET', `/v1/distributions?candidateId=${id}`)).json.length, 1);
      const url = rel.json.receipt.adapterResponse.downloadUrl as string;
      assert.ok(url.startsWith(`http://127.0.0.1:${p}/v1/downloads/`));
      // the recipient needs no account: the signed link alone serves exactly the approved archive
      const got = await fetch(url); assert.equal(got.status, 200); assert.equal(got.headers.get('x-content-sha256'), zip.bytes.length > 0 ? rel.json.receipt.zipSha256 : '');
      assert.deepEqual(new Uint8Array(await got.arrayBuffer()), zip.bytes);
      assert.equal((await fetch(`${url.slice(0, -3)}abc`)).status, 404, 'tampered signature');
      assert.equal((await fetch(url.replace(/\.(\d{9,})\./, (_m, e: string) => `.${Number(e) + 9999}.`))).status, 404, 'extended expiry');
      // expiry is enforced
      await h.sql.query(`update e12_release.download_links set expires_at = now() - interval '1 second'`);
      assert.equal((await fetch(url)).status, 404);
      await h.sql.query(`update e12_release.download_links set expires_at = now() + interval '5 minutes'`);
      assert.equal((await fetch(url)).status, 200);
      // other tenants see nothing through HTTP
      const foreign = token('owner-9', { tid: 't2' });
      for (const path of [`/v1/candidates/${id}`, `/v1/candidates/${id}/package.zip`, `/v1/dispatches/${rel.json.id}`, `/v1/inspect?ref=${encodeURIComponent(built.json.ref)}`]) assert.equal((await call('GET', path, undefined, foreign)).status, 404, path);
      assert.deepEqual((await call('GET', '/v1/candidates', undefined, foreign)).json, []); assert.deepEqual((await call('GET', '/v1/search?q=Harbour', undefined, foreign)).json, []);
      assert.equal((await call('GET', '/v1/search?q=Harbour')).json.length, 1);
      assert.equal((await call('GET', '/v1/events')).json.at(-1).type, 'release.released');
      // upstream change through HTTP, then withdrawal revokes the link
      const up = await call('POST', '/v1/upstream-changes', { eventId: 'http-ev-1', kind: 'source_corrected', refs: ['E05:evidence_version:doc-1'], reason: 'corrected' });
      assert.ok(up.json.affected.includes(built.json.ref)); assert.equal((await call('GET', `/v1/inspect?ref=${encodeURIComponent(built.json.ref)}`)).json.stale, true);
      assert.equal((await call('GET', `/v1/distributions?candidateId=${id}&needsFollowUp=true`)).json.length, 1);
      const wd = await call('POST', `/v1/releases/${id}/withdraw`, { reason: 'Withdrawn pending correction.' }); assert.equal(wd.status, 201);
      assert.equal((await fetch(url)).status, 404, 'withdrawn');
      assert.equal((await call('POST', `/v1/withdrawals/${wd.json.id}`, { state: 'completed', note: 'Link revoked.' })).json.state, 'completed');
      assert.equal(await code(engine.download('not-a-token')), 'not_found');
      void join;
    } finally { http.closeAllConnections(); await new Promise((r) => http.close(r)); }
  });
});

test('standalone server starts from environment configuration and serves health', needsPg, async () => {
  const { withDisposableDatabase, generateSigningKey: gen } = await import('../src/service-kit.ts');
  const pg = (await import('pg')).default;
  const { mkdtemp, rm } = await import('node:fs/promises'); const { tmpdir } = await import('node:os');
  const { main, configFromEnv } = await import('../src/engine/serve.ts');
  const dir = await mkdtemp(join(tmpdir(), 'e12-serve-'));
  try {
    await withDisposableDatabase(pg, process.env.TEST_DATABASE_URL as string, async (url) => {
      const key = gen('k1');
      const env = { DATABASE_URL: url, PORT: '0', IDENTITY_PUBLIC_KEYS: JSON.stringify({ k1: key.publicKeyPem }), OBJECT_STORE_PATH: join(dir, 'objects'), RELEASE_JURISDICTION_PACKS_DIR: new URL('../examples/jurisdiction-packs', import.meta.url).pathname, RELEASE_DESTINATION_ROOTS: JSON.stringify({ portal: join(dir, 'portal') }), RELEASE_SECRET_PARTNER: 's3cret', RELEASE_DOWNLOAD_SECRET: 'x'.repeat(32), RELEASE_PUBLIC_BASE_URL: 'http://127.0.0.1:9', RELEASE_JOB_INTERVAL_MS: '250' };
      const cfg = await configFromEnv(env);
      assert.equal(cfg.accountabilityPolicy, 'legal_first'); assert.equal(cfg.standaloneRights, 'deny'); assert.equal(cfg.jurisdictionPacks?.[0]?.id, 'example-republic'); assert.equal(cfg.destinations?.secrets?.partner, 's3cret');
      const s = await main(env);
      try {
        const health = await (await fetch(`http://127.0.0.1:${s.port}/healthz`)).json() as { ok: boolean; detail: { jurisdictionPacks: string[]; accountabilityPolicy: string } };
        assert.equal(health.ok, true); assert.deepEqual(health.detail.jurisdictionPacks, ['example-republic']); assert.equal(health.detail.accountabilityPolicy, 'legal_first');
        assert.equal((await fetch(`http://127.0.0.1:${s.port}/v1/candidates`)).status, 401);
      } finally { await s.close(); }
      await assert.rejects(main({ PORT: '0' }), /DATABASE_URL/);
    });
  } finally { await rm(dir, { recursive: true, force: true }); }
});
