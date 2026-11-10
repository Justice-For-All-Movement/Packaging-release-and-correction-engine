import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pg from 'pg';
import { FsObjectStore, withDisposableDatabase } from '../../src/service-kit.ts';
import type { ServiceContext, Sql, UseDecision, UseDecisionPort } from '../../src/service-kit.ts';
import { createEngine, migrate } from '../../src/engine/index.ts';
import type { InvestigationPackage, JurisdictionPack, ReleaseConfig, ReleaseDeps, ReleaseEngine } from '../../src/engine/index.ts';
import { run } from '../../src/engine/tools.ts';

export const ADMIN = process.env.TEST_DATABASE_URL ?? '';
export const needsPg = ADMIN === '' ? { skip: 'TEST_DATABASE_URL is not set; real-PostgreSQL test not executed' } : {};
export const ALL_CAPS = ['release:read', 'release:write', 'release:review', 'release:participant_review', 'release:legal_review', 'release:approve', 'release:publish', 'release:export', 'release:withdraw', 'release:admin', 'release:events', 'release:upstream'];
export const ctx = (over: Partial<ServiceContext> = {}): ServiceContext => ({ tenantId: 't1', projectId: 'p1', purpose: 'test', requestId: 'r1', now: new Date().toISOString(), actor: { id: 'owner-1', kind: 'human', roles: ['owner'] }, capabilities: ALL_CAPS, compartments: [], ...over });
export const as = (id: string, over: Partial<ServiceContext> = {}): ServiceContext => ctx({ actor: { id, kind: 'human', roles: [] }, ...over });
export const PROTECTED = 'Marisol Quenby';

export const pack = async (): Promise<JurisdictionPack> => JSON.parse(await readFile(new URL('../../examples/jurisdiction-packs/example-republic.json', import.meta.url), 'utf8')) as JurisdictionPack;
export const PKG: InvestigationPackage = {
  investigationRef: 'E08:investigation:inv-1', title: 'Harbour contract inquiry', summary: 'Summary of the harbour dredging contract inquiry.',
  findings: [
    { id: 'F1', ref: 'E08:finding:f-1@1', status: 'established', statement: 'The harbour authority signed the dredging contract on 3 March 2025.', sources: [{ ref: 'E05:evidence_version:doc-1@1', locator: 'page 2' }], limitations: ['Only the signature page was available.'] },
    { id: 'F2', status: 'disputed', statement: 'The contractor says the tender was advertised; the authority has no record of an advertisement.', sources: [{ ref: 'E07:claim:c-2@1' }] },
    { id: 'F3', status: 'unknown', statement: 'Who authorised the first payment is not known.' },
  ],
  chronology: [{ date: '2025-03-03', event: 'Dredging contract signed', status: 'established', findingIds: ['F1'] }, { date: '2025-02-01', event: 'Tender said to have been advertised', status: 'disputed', sources: [{ ref: 'E07:claim:c-2@1' }] }],
  openQuestions: [{ id: 'Q1', question: 'Who authorised the first payment?', recordsSought: 'Payment authorisation records for the dredging contract' }],
  limitations: ['The inquiry relied on documents supplied by two sources.'],
};

export class FakeConsent implements UseDecisionPort {
  denied = new Set<string>(); restrictions: string[] = []; permissionRefs: string[] = ['E11:permission:perm-1@1']; calls: { subjects: readonly string[]; action: string; audience?: string }[] = []; n = 0;
  async decide(_ctx: ServiceContext, request: { subjects: readonly string[]; action: string; audience?: string }): Promise<UseDecision & { decisionRef: string }> {
    this.calls.push(request);
    const deny = request.subjects.some((s) => this.denied.has(s));
    return { decision: deny ? 'deny' : 'allow', reasons: deny ? ['permission withdrawn'] : [], permissionRefs: [...this.permissionRefs], restrictions: [...this.restrictions], decidedAt: new Date().toISOString(), decisionRef: `E11:decision:d-${++this.n}` };
  }
}

export type Harness = { sql: Sql; engine: ReleaseEngine; dir: string; objects: FsObjectStore; objectRoot: string; make(config?: ReleaseConfig, ports?: ReleaseDeps['ports']): ReleaseEngine; baseConfig: ReleaseConfig };
export async function withEngine(fn: (h: Harness) => Promise<void>, config: ReleaseConfig = {}, ports: ReleaseDeps['ports'] = {}): Promise<void> {
  await withDisposableDatabase(pg, ADMIN, async (_url, sql) => {
    await migrate(sql);
    const dir = await mkdtemp(join(tmpdir(), 'e12-test-'));
    try {
      const objectRoot = join(dir, 'objects');
      const objects = new FsObjectStore(objectRoot);
      const baseConfig: ReleaseConfig = { jurisdictionPacks: [await pack()], ...config, destinations: { roots: { portal: join(dir, 'portal'), site: join(dir, 'site') }, downloadSecret: 'test-download-secret-0123456789', publicBaseUrl: 'http://127.0.0.1:1', ...config.destinations } };
      const make = (c: ReleaseConfig = baseConfig, p: ReleaseDeps['ports'] = ports): ReleaseEngine => createEngine({ sql, objects, config: c, ...(p === undefined ? {} : { ports: p }) });
      await fn({ sql, engine: make(), dir, objects, objectRoot, make, baseConfig });
    } finally { await rm(dir, { recursive: true, force: true }); }
  });
}
export async function tool(cmd: string, args: string[], input?: Uint8Array): Promise<string> { const r = await run(cmd, args, input === undefined ? {} : { input }); return r.stdout.toString('utf8') + r.stderr; }
export const b64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64');
export async function image(dir: string, name: string, color: string, exif: Record<string, string> = {}): Promise<Uint8Array> {
  const file = join(dir, name);
  await run('convert', ['-size', '96x64', `xc:${color}`, file]);
  if (Object.keys(exif).length > 0) await run('exiftool', ['-q', '-overwrite_original', ...Object.entries(exif).map(([k, v]) => `-${k}=${v}`), file]);
  return new Uint8Array(await readFile(file));
}
export async function pdf(dir: string, name: string, text: string, meta: Record<string, string> = {}): Promise<Uint8Array> {
  const md = join(dir, `${name}.md`), docx = join(dir, `${name}.docx`);
  await writeFile(md, text);
  await run('pandoc', ['-f', 'markdown', '-t', 'docx', '-o', docx, md]);
  await run('soffice', [`-env:UserInstallation=file://${join(dir, 'lo-profile')}`, '--headless', '--convert-to', 'pdf', '--outdir', dir, docx], { timeoutMs: 180_000 });
  const file = join(dir, `${name}.pdf`);
  if (Object.keys(meta).length > 0) await run('exiftool', ['-q', '-overwrite_original', ...Object.entries(meta).map(([k, v]) => `-${k}=${v}`), file]);
  return new Uint8Array(await readFile(file));
}
/** Builds, reviews and returns a candidate ready for approval. */
export async function reviewed(engine: ReleaseEngine, candidateId: string): Promise<string> {
  const c = await engine.submitForReview(ctx(), candidateId, { reviewers: ['rev-1'] });
  const done = await engine.recordReview(as('rev-1'), candidateId, { candidateDigest: c.digest as string, outcome: 'accepted' });
  if (done.state !== 'reviewed') throw new Error(`expected reviewed, got ${done.state}`);
  return c.digest as string;
}
export const soon = (seconds = 3600): string => new Date(Date.now() + seconds * 1000).toISOString();
export async function code(p: Promise<unknown>): Promise<string> { try { await p; return 'ok'; } catch (e) { return (e as { code?: string }).code ?? `error:${(e as Error).message}`; } }
export async function events(h: Harness, type?: string): Promise<{ type: string; subject: string; payload: unknown }[]> {
  for (let i = 0; ; i++) {
    const all = await h.engine.events(ctx(), { limit: 1000 });
    const count = Number((await h.sql.query(`select count(*)::int as n from e12_release._events where tenant_id='t1'`))[0]?.n ?? 0);
    if (all.length >= count || i > 100) return all.filter((e) => type === undefined || e.type === type);
    await new Promise((r) => setTimeout(r, 100));
  }
}
