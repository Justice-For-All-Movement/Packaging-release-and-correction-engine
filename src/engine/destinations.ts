// Destination adapters. An adapter performs exactly one delivery of an already approved, already re-verified
// package and reports delivered / failed (nothing left the system) / uncertain (outcome unknown; never blindly retried).
import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, join, resolve, sep } from 'node:path';
import { DomainError, invariant } from '../contracts.ts';
import type { Json } from '../contracts.ts';
import { run, withTempDir } from './tools.ts';

export type DestinationKind = 'local_directory' | 'signed_download' | 'webhook' | 'http_put' | 'sftp' | 'email' | 'public_web';
export const DESTINATION_KINDS: readonly DestinationKind[] = ['local_directory', 'signed_download', 'webhook', 'http_put', 'sftp', 'email', 'public_web'];
/** Deployment-side settings: adapters can only reach roots, hosts, servers and secrets named here. */
export type DestinationRuntime = Readonly<{
  roots?: Readonly<Record<string, string>>;
  /** Exact `host:port` values webhook / HTTP PUT destinations may address. */
  httpHosts?: readonly string[];
  allowInsecureHttp?: boolean;
  /** Secret values by name; destinations reference names only. Never returned, logged or stored. */
  secrets?: Readonly<Record<string, string>>;
  smtp?: Readonly<Record<string, Readonly<{ host: string; port: number; secure?: boolean; user?: string; passwordSecret?: string; from: string; allowInsecure?: boolean }>>>;
  sftp?: Readonly<Record<string, Readonly<{ host: string; port?: number; user: string; identityFile: string; knownHostsFile: string; remoteDir: string }>>>;
  downloadSecret?: string;
  /** Base URL under which this engine's HTTP routes are reachable by recipients (for signed download links). */
  publicBaseUrl?: string;
  httpTimeoutMs?: number;
}>;
export type DeliveryPayload = Readonly<{
  releaseId: string; candidateId: string; lineageId: string; version: number; digest: string; title: string; kind: string; audience: string;
  zip: Uint8Array; zipSha256: string; files: readonly Readonly<{ path: string; bytes: Uint8Array }>[];
  notices: readonly Readonly<{ name: string; text: string }>[]; searchText: string; downloadUrl?: string; expiresAt?: string;
  scope: Readonly<{ tenantId: string; projectId: string }>;
}>;
export type DeliveryResult = Readonly<{ outcome: 'delivered' | 'failed' | 'uncertain'; response: Json }>;
export type ProbeResult = 'delivered' | 'not_delivered' | 'unknown';
const seg = (s: string): string => { invariant(/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(s) && !s.includes('..'), 'invalid_input', 'Invalid path segment'); return s; };
const esc = (s: string): string => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string);

export function validateDestinationConfig(kind: DestinationKind, config: Record<string, unknown>, rt: DestinationRuntime): void {
  const keys = (allowed: string[]): void => invariant(Object.keys(config).every((k) => allowed.includes(k)), 'invalid_input', `Unknown destination setting for ${kind}`);
  const ttl = (): void => invariant(config.ttlSeconds === undefined || (Number.isSafeInteger(config.ttlSeconds) && (config.ttlSeconds as number) >= 60 && (config.ttlSeconds as number) <= 30 * 86400), 'invalid_input', 'ttlSeconds must be between 60 and 2592000');
  if (kind === 'local_directory' || kind === 'public_web') { keys(['root']); invariant(typeof config.root === 'string' && Object.hasOwn(rt.roots ?? {}, config.root), 'invalid_input', 'Destination root is not configured by the deployment'); }
  else if (kind === 'signed_download') { keys(['ttlSeconds']); ttl(); }
  else if (kind === 'webhook' || kind === 'http_put') {
    keys(['url', 'secretRef']);
    const url = httpUrl(config.url, rt);
    invariant(kind === 'webhook' || url.pathname.length > 1, 'invalid_input', 'HTTP PUT destination needs a path');
    invariant(config.secretRef === undefined || (typeof config.secretRef === 'string' && Object.hasOwn(rt.secrets ?? {}, config.secretRef)), 'invalid_input', 'Secret reference is not configured by the deployment');
  } else if (kind === 'email') {
    keys(['smtp', 'to', 'ttlSeconds']); ttl();
    invariant(typeof config.smtp === 'string' && Object.hasOwn(rt.smtp ?? {}, config.smtp), 'invalid_input', 'SMTP server is not configured by the deployment');
    invariant(Array.isArray(config.to) && config.to.length > 0 && config.to.length <= 50 && config.to.every((a) => typeof a === 'string' && /^[^\s@<>,;"]+@[A-Za-z0-9.-]+$/.test(a)), 'invalid_input', 'Email destination needs recipient addresses');
  } else { keys(['server']); invariant(typeof config.server === 'string' && Object.hasOwn(rt.sftp ?? {}, config.server), 'invalid_input', 'SFTP server is not configured by the deployment'); }
}
function httpUrl(value: unknown, rt: DestinationRuntime): URL {
  invariant(typeof value === 'string' && value.length <= 2000, 'invalid_input', 'Destination URL is required');
  let url: URL;
  try { url = new URL(value); } catch { throw new DomainError('invalid_input', 'Destination URL is invalid'); }
  invariant(url.username === '' && url.password === '' && url.hash === '', 'invalid_input', 'Destination URL must not carry credentials or fragments');
  invariant(url.protocol === 'https:' || (url.protocol === 'http:' && rt.allowInsecureHttp === true), 'invalid_input', 'Destination URL must use https');
  const hostPort = `${url.hostname}:${url.port || (url.protocol === 'https:' ? '443' : '80')}`;
  invariant((rt.httpHosts ?? []).includes(hostPort), 'invalid_input', 'Destination host is not allow-listed by the deployment');
  return url;
}

async function writeTree(base: string, files: readonly { path: string; bytes: Uint8Array }[]): Promise<void> {
  for (const f of files) {
    const full = join(base, ...f.path.split('/').map(seg));
    invariant(resolve(full).startsWith(resolve(base) + sep), 'invalid_input', 'Invalid file path');
    await mkdir(dirname(full), { recursive: true });
    await writeFile(full, f.bytes, { mode: 0o640 });
  }
}
function folder(rt: DestinationRuntime, config: Record<string, unknown>, p: Pick<DeliveryPayload, 'scope' | 'lineageId'>): string {
  const root = rt.roots?.[config.root as string];
  if (root === undefined) throw new DomainError('unavailable', 'Destination root is not configured');
  return join(resolve(root), seg(p.scope.tenantId), seg(p.scope.projectId), seg(p.lineageId));
}
const versionDir = (p: Pick<DeliveryPayload, 'version' | 'digest'>): string => `v${p.version}-${p.digest.slice(0, 16)}`;

async function fsDeliver(rt: DestinationRuntime, config: Record<string, unknown>, p: DeliveryPayload, site: boolean): Promise<DeliveryResult> {
  const base = folder(rt, config, p);
  const final = join(base, versionDir(p));
  try {
    const tmp = join(base, `.tmp-${p.releaseId}`);
    await rm(tmp, { recursive: true, force: true });
    await writeTree(tmp, [...p.files, ...p.notices.map((n) => ({ path: `correction-notices/${n.name}`, bytes: new TextEncoder().encode(n.text) })), ...(site ? [] : [{ path: 'package.zip', bytes: p.zip }])]);
    await rm(final, { recursive: true, force: true });
    await rename(tmp, final);
    if (site) {
      // The public index and search index are derived only from released files of the current version.
      const html = p.files.filter((f) => f.path.endsWith('.html'));
      const index = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><title>${esc(p.title)}</title></head><body><main><h1>${esc(p.title)}</h1><p>Current version ${p.version}. Package digest <code>${p.digest}</code>.</p>${p.notices.length === 0 ? '' : `<h2>Correction notices</h2>${p.notices.map((n) => `<pre>${esc(n.text)}</pre>`).join('')}`}<h2>Documents</h2><ul>${html.map((f) => `<li><a href="${esc(`${versionDir(p)}/${f.path}`)}">${esc(f.path)}</a></li>`).join('')}</ul><h2>All files</h2><ul>${p.files.map((f) => `<li><a href="${esc(`${versionDir(p)}/${f.path}`)}">${esc(f.path)}</a></li>`).join('')}</ul></main></body></html>`;
      await writeFile(join(base, 'index.html'), index, { mode: 0o644 });
      await writeFile(join(base, 'search-index.json'), JSON.stringify({ title: p.title, version: p.version, digest: p.digest, text: p.searchText }), { mode: 0o644 });
    }
  } catch (error) {
    if (error instanceof DomainError) throw error;
    return { outcome: 'failed', response: { error: 'write_failed', code: (error as NodeJS.ErrnoException).code ?? 'unknown' } };
  }
  return { outcome: 'delivered', response: { location: `${seg(p.scope.tenantId)}/${seg(p.scope.projectId)}/${p.lineageId}/${versionDir(p)}`, files: p.files.length + p.notices.length } };
}

async function httpDeliver(kind: 'webhook' | 'http_put', rt: DestinationRuntime, config: Record<string, unknown>, p: DeliveryPayload): Promise<DeliveryResult> {
  const url = httpUrl(config.url, rt);
  const secret = config.secretRef === undefined ? undefined : rt.secrets?.[config.secretRef as string];
  if (config.secretRef !== undefined && secret === undefined) throw new DomainError('unavailable', 'Destination secret is not configured');
  const headers: Record<string, string> = { 'idempotency-key': p.releaseId, 'x-package-digest': p.digest, 'x-content-sha256': p.zipSha256, ...(secret === undefined ? {} : { authorization: `Bearer ${secret}` }) };
  const body = kind === 'http_put' ? p.zip : JSON.stringify({ type: 'release.package', releaseId: p.releaseId, digest: p.digest, title: p.title, kind: p.kind, version: p.version, audience: p.audience, zipSha256: p.zipSha256, zipBase64: Buffer.from(p.zip).toString('base64'), correctionNotices: p.notices });
  let response: Response;
  try {
    response = await fetch(url, { method: kind === 'http_put' ? 'PUT' : 'POST', redirect: 'manual', headers: { ...headers, 'content-type': kind === 'http_put' ? 'application/zip' : 'application/json' }, body: body as BodyInit, signal: AbortSignal.timeout(rt.httpTimeoutMs ?? 60_000) });
  } catch (error) {
    const code = ((error as { cause?: { code?: string } }).cause?.code) ?? (error as Error).name;
    // Refused / unresolvable: the request never reached a server. Anything else may have been received.
    if (code === 'ECONNREFUSED' || code === 'ENOTFOUND' || code === 'EAI_AGAIN') return { outcome: 'failed', response: { error: 'not_connected', code } };
    return { outcome: 'uncertain', response: { error: 'no_response', code: String(code) } };
  }
  await response.arrayBuffer().catch(() => undefined);
  const info = { status: response.status, requestId: response.headers.get('x-request-id') };
  if (response.status >= 200 && response.status < 300) return { outcome: 'delivered', response: info };
  if (response.status >= 500) return { outcome: 'uncertain', response: info };
  return { outcome: 'failed', response: info };
}

async function emailDeliver(rt: DestinationRuntime, config: Record<string, unknown>, p: DeliveryPayload): Promise<DeliveryResult> {
  const server = rt.smtp?.[config.smtp as string];
  if (server === undefined || p.downloadUrl === undefined) throw new DomainError('unavailable', 'Email handoff needs a configured SMTP server and download link settings');
  const password = server.passwordSecret === undefined ? undefined : rt.secrets?.[server.passwordSecret];
  if (server.passwordSecret !== undefined && password === undefined) throw new DomainError('unavailable', 'SMTP secret is not configured');
  const nodemailer = (await import('nodemailer' as string)) as { default: { createTransport(o: unknown): { sendMail(m: unknown): Promise<{ messageId?: string; accepted?: unknown[]; rejected?: unknown[]; response?: string }>; close(): void } } };
  const transport = nodemailer.default.createTransport({ host: server.host, port: server.port, secure: server.secure === true, ...(server.allowInsecure === true ? { ignoreTLS: true } : { requireTLS: server.secure !== true }), connectionTimeout: 20_000, socketTimeout: 60_000, ...(server.user === undefined ? {} : { auth: { user: server.user, pass: password ?? '' } }) });
  try {
    const sent = await transport.sendMail({ from: server.from, to: (config.to as string[]).join(', '), subject: `Package available: ${p.title.replace(/[\r\n]+/g, ' ').slice(0, 150)}`, headers: { 'X-Release-Id': p.releaseId },
      text: `A package has been released to you.\n\nTitle: ${p.title}\nVersion: ${p.version}\nPackage digest (SHA-256 of manifest): ${p.digest}\nArchive SHA-256: ${p.zipSha256}\n\nDownload (expires ${p.expiresAt ?? 'soon'}):\n${p.downloadUrl}\n${p.notices.map((n) => `\n${n.text}\n`).join('')}` });
    const rejected = (sent.rejected ?? []).length;
    return { outcome: rejected === 0 ? 'delivered' : 'uncertain', response: { messageId: sent.messageId ?? null, accepted: (sent.accepted ?? []).length, rejected, note: 'accepted by the SMTP server; receipt by the recipient is not confirmed' } };
  } catch (error) {
    const code = String((error as { code?: string }).code ?? 'smtp_error');
    return { outcome: ['ECONNECTION', 'ECONNREFUSED', 'EDNS', 'EAUTH', 'EENVELOPE', 'ETLS'].includes(code) ? 'failed' : 'uncertain', response: { error: code } };
  } finally { transport.close(); }
}

async function sftpDeliver(rt: DestinationRuntime, config: Record<string, unknown>, p: DeliveryPayload): Promise<DeliveryResult> {
  const s = rt.sftp?.[config.server as string];
  if (s === undefined) throw new DomainError('unavailable', 'SFTP server is not configured');
  invariant(/^[A-Za-z0-9._-]+$/.test(s.host) && /^[A-Za-z0-9._-]+$/.test(s.user) && /^[A-Za-z0-9._/-]+$/.test(s.remoteDir) && !s.remoteDir.includes('..'), 'invalid_config', 'Invalid SFTP settings');
  return withTempDir(async (dir) => {
    const name = `${p.lineageId}-${versionDir(p)}.zip`;
    await writeFile(join(dir, name), p.zip);
    const batch = `put ${join(dir, name)} ${s.remoteDir}/${name}.part\nrename ${s.remoteDir}/${name}.part ${s.remoteDir}/${name}\n`;
    try {
      // `run` rejects with `unavailable` when the sftp client is not installed.
      const r = await run('sftp', ['-b', '-', '-P', String(s.port ?? 22), '-i', s.identityFile, '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', `UserKnownHostsFile=${s.knownHostsFile}`, '-o', 'ConnectTimeout=20', `${s.user}@${s.host}`], { input: batch, allowFail: true, timeoutMs: 600_000 });
      if (r.code === 0) return { outcome: 'delivered', response: { remote: `${s.remoteDir}/${name}` } };
      return { outcome: r.code === 255 ? 'failed' : 'uncertain', response: { exitCode: r.code } };
    } catch (error) {
      if (error instanceof DomainError && error.code === 'unavailable') throw error;
      return { outcome: 'uncertain', response: { error: 'sftp_interrupted' } };
    }
  });
}

/** Performs the delivery. `signed_download` has no external side effect: the engine has already minted the link. */
export async function deliver(kind: DestinationKind, rt: DestinationRuntime, config: Record<string, unknown>, p: DeliveryPayload): Promise<DeliveryResult> {
  switch (kind) {
    case 'local_directory': return fsDeliver(rt, config, p, false);
    case 'public_web': return fsDeliver(rt, config, p, true);
    case 'signed_download': return { outcome: 'delivered', response: { downloadUrl: p.downloadUrl ?? null, expiresAt: p.expiresAt ?? null } };
    case 'webhook': case 'http_put': return httpDeliver(kind, rt, config, p);
    case 'email': return emailDeliver(rt, config, p);
    case 'sftp': return sftpDeliver(rt, config, p);
  }
}
/** Asks the destination whether an uncertain delivery arrived. `unknown` when the destination cannot tell. */
export async function probe(kind: DestinationKind, rt: DestinationRuntime, config: Record<string, unknown>, p: Pick<DeliveryPayload, 'scope' | 'lineageId' | 'version' | 'digest'> & { zipSize: number; zipSha256: string }): Promise<ProbeResult> {
  if (kind === 'local_directory' || kind === 'public_web') {
    try { await readFile(join(folder(rt, config, p), versionDir(p), 'manifest.json')); return 'delivered'; } catch { return 'not_delivered'; }
  }
  if (kind === 'http_put') {
    try {
      const r = await fetch(httpUrl(config.url, rt), { method: 'HEAD', redirect: 'manual', signal: AbortSignal.timeout(rt.httpTimeoutMs ?? 30_000), headers: config.secretRef === undefined ? {} : { authorization: `Bearer ${rt.secrets?.[config.secretRef as string] ?? ''}` } });
      if (r.status === 404) return 'not_delivered';
      if (r.ok && (r.headers.get('x-content-sha256') === p.zipSha256 || r.headers.get('content-length') === String(p.zipSize))) return 'delivered';
    } catch { /* still unknown */ }
  }
  return 'unknown';
}
/** Removes a published version where the destination is under our control. Returns false when it must be done by hand. */
export async function unpublish(kind: DestinationKind, rt: DestinationRuntime, config: Record<string, unknown>, p: Pick<DeliveryPayload, 'scope' | 'lineageId' | 'version' | 'digest' | 'title'>, notice: string): Promise<boolean> {
  if (kind !== 'local_directory' && kind !== 'public_web') return false;
  const base = folder(rt, config, p);
  await rm(join(base, versionDir(p)), { recursive: true, force: true });
  if (kind === 'public_web') {
    await writeFile(join(base, 'index.html'), `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Withdrawn</title></head><body><main><h1>Withdrawn</h1><pre>${esc(notice)}</pre></main></body></html>`);
    await writeFile(join(base, 'search-index.json'), JSON.stringify({ withdrawn: true, text: '' }));
  }
  return true;
}
