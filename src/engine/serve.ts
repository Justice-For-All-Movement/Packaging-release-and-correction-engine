// Standalone E12 server: migrations, HTTP API and the delivery-reconciliation job loop (jobs never start a release).
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import pg from 'pg';
import { createHttpHandler, createTokenVerifier, objectStoreFromEnv, pgSql, serve } from '../service-kit.ts';
import { createEngine, manifest, migrate, routes } from './index.ts';
import type { JurisdictionPack, ReleaseConfig } from './index.ts';

async function publicKeys(env: NodeJS.ProcessEnv): Promise<Record<string, string>> {
  const raw = env.IDENTITY_PUBLIC_KEYS ?? (env.IDENTITY_JWKS_FILE === undefined ? undefined : await readFile(env.IDENTITY_JWKS_FILE, 'utf8'));
  if (raw === undefined) throw new Error('IDENTITY_PUBLIC_KEYS (JSON map kid→PEM) or IDENTITY_JWKS_FILE is required');
  const parsed = JSON.parse(raw) as unknown;
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed) || !Object.values(parsed).every((v) => typeof v === 'string')) throw new Error('Identity public keys must be a JSON object mapping key id to PEM');
  return parsed as Record<string, string>;
}

/** Builds engine configuration from the environment. Secrets come only from RELEASE_SECRET_<NAME> variables. */
export async function configFromEnv(env: NodeJS.ProcessEnv): Promise<ReleaseConfig> {
  const file = env.RELEASE_CONFIG_FILE === undefined ? {} : JSON.parse(await readFile(env.RELEASE_CONFIG_FILE, 'utf8')) as Record<string, unknown>;
  const packs: JurisdictionPack[] = [];
  if (env.RELEASE_JURISDICTION_PACKS_DIR !== undefined) for (const name of (await readdir(env.RELEASE_JURISDICTION_PACKS_DIR)).filter((n) => n.endsWith('.json')).sort()) packs.push(JSON.parse(await readFile(join(env.RELEASE_JURISDICTION_PACKS_DIR, name), 'utf8')) as JurisdictionPack);
  const secrets: Record<string, string> = {};
  for (const [k, v] of Object.entries(env)) if (k.startsWith('RELEASE_SECRET_') && typeof v === 'string' && v !== '') secrets[k.slice('RELEASE_SECRET_'.length).toLowerCase()] = v;
  const fileDest = (file.destinations ?? {}) as Record<string, unknown>;
  return {
    ...(file.audiences === undefined ? {} : { audiences: file.audiences as NonNullable<ReleaseConfig['audiences']> }),
    accountabilityPolicy: (env.RELEASE_ACCOUNTABILITY_POLICY ?? file.accountabilityPolicy ?? 'legal_first') === 'human_decision' ? 'human_decision' : 'legal_first',
    standaloneRights: env.RELEASE_STANDALONE_RIGHTS === 'allow_without_port' ? 'allow_without_port' : 'deny',
    jurisdictionPacks: packs,
    ...(env.RELEASE_MAX_APPROVAL_SECONDS === undefined ? {} : { maxApprovalSeconds: Number(env.RELEASE_MAX_APPROVAL_SECONDS) }),
    destinations: {
      ...(fileDest.smtp === undefined ? {} : { smtp: fileDest.smtp as never }), ...(fileDest.sftp === undefined ? {} : { sftp: fileDest.sftp as never }),
      roots: { ...(fileDest.roots as Record<string, string> | undefined), ...(env.RELEASE_DESTINATION_ROOTS === undefined ? {} : JSON.parse(env.RELEASE_DESTINATION_ROOTS) as Record<string, string>) },
      httpHosts: [...((fileDest.httpHosts as string[] | undefined) ?? []), ...(env.RELEASE_HTTP_HOSTS ?? '').split(',').map((h) => h.trim()).filter((h) => h !== '')],
      secrets,
      ...(env.RELEASE_DOWNLOAD_SECRET === undefined ? {} : { downloadSecret: env.RELEASE_DOWNLOAD_SECRET }),
      ...(env.RELEASE_PUBLIC_BASE_URL === undefined ? {} : { publicBaseUrl: env.RELEASE_PUBLIC_BASE_URL }),
    },
  };
}

export async function main(env: NodeJS.ProcessEnv = process.env): Promise<{ close(): Promise<void>; port: number }> {
  if (env.DATABASE_URL === undefined || env.DATABASE_URL === '') throw new Error('DATABASE_URL is required');
  const keys = await publicKeys(env);
  const config = await configFromEnv(env);
  const pool = new pg.Pool({ connectionString: env.DATABASE_URL, max: Number(env.DATABASE_POOL_MAX ?? 10) });
  const sql = pgSql(pool);
  await migrate(sql);
  // Standalone: no consent, evidence or protected-terms services are wired. Approval of anything with rights subjects is
  // therefore denied unless RELEASE_STANDALONE_RIGHTS=allow_without_port. A host (PAM) supplies the ports in-process.
  const engine = createEngine({ sql, objects: objectStoreFromEnv(env, env.OBJECT_STORE_PATH ?? './data/objects'), config });
  const handler = createHttpHandler({
    name: manifest.id, version: manifest.version, routes: routes(engine), health: () => engine.health(), maxBodyBytes: Number(env.RELEASE_MAX_BODY_BYTES ?? 512 * 1024 * 1024),
    verify: createTokenVerifier({ publicKeys: keys, ...(env.IDENTITY_ISSUER === undefined ? {} : { issuer: env.IDENTITY_ISSUER }) }),
    onError: (error, info) => { console.error(JSON.stringify({ level: 'error', requestId: info.requestId, method: info.method, path: info.path, error: error instanceof Error ? error.name : 'unknown' })); },
  });
  const server = await serve(handler, Number(env.PORT ?? 8112), env.HOST ?? '127.0.0.1');
  let stopped = false;
  const interval = Math.max(Number(env.RELEASE_JOB_INTERVAL_MS ?? 5000), 250);
  const loop = (async () => {
    while (!stopped) {
      try { await engine.runJobsOnce('release-serve'); } catch (error) { console.error(JSON.stringify({ level: 'error', job: 'release.reconcile', error: error instanceof Error ? error.name : 'unknown' })); }
      await new Promise((r) => setTimeout(r, interval));
    }
  })();
  const address = server.address();
  return {
    port: typeof address === 'object' && address !== null ? address.port : 0,
    async close() { stopped = true; server.closeAllConnections(); await new Promise<void>((r) => server.close(() => r())); await Promise.race([loop, new Promise((r) => setTimeout(r, interval + 100))]); await pool.end(); },
  };
}

if (process.argv[1] !== undefined && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  main().then((s) => { console.log(JSON.stringify({ level: 'info', engine: manifest.id, port: s.port })); }, (error: unknown) => { console.error(error instanceof Error ? error.message : 'startup failed'); process.exit(1); });
}
