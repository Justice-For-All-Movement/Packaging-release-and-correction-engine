// Subprocess, document rendering and deterministic ZIP helpers for the release engine.
// Every external tool is spawned with an argument array (never a shell), a timeout and an output cap.
import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { crc32, deflateRawSync, inflateRawSync } from 'node:zlib';
import { DomainError, invariant } from '../contracts.ts';

export const sha256 = (bytes: Uint8Array | string): string => createHash('sha256').update(bytes).digest('hex');
export const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);

export type RunResult = Readonly<{ code: number; stdout: Buffer; stderr: string }>;
const SAFE_ENV: Record<string, string> = { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: process.env.HOME ?? '/tmp', LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8', SOURCE_DATE_EPOCH: '946684800', TZ: 'UTC' };

export function run(cmd: string, args: readonly string[], options: { timeoutMs?: number; input?: Uint8Array | string; allowFail?: boolean; maxOutputBytes?: number; cwd?: string } = {}): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    const max = options.maxOutputBytes ?? 64 * 1024 * 1024;
    const out: Buffer[] = []; let size = 0, stderr = '', done = false, timedOut = false, overflow = false;
    const child = spawn(cmd, [...args], { env: SAFE_ENV, stdio: ['pipe', 'pipe', 'pipe'], ...(options.cwd === undefined ? {} : { cwd: options.cwd }) });
    const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, options.timeoutMs ?? 120_000);
    const finish = (fn: () => void): void => { if (done) return; done = true; clearTimeout(timer); fn(); };
    child.stdout.on('data', (c: Buffer) => { size += c.byteLength; if (size > max) { overflow = true; child.kill('SIGKILL'); } else out.push(c); });
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (c: string) => { stderr = (stderr + c).slice(-8000); });
    child.on('error', (error: NodeJS.ErrnoException) => finish(() => reject(error.code === 'ENOENT' ? new DomainError('unavailable', `Required tool is not installed: ${cmd}`) : error)));
    child.on('close', (code) => finish(() => {
      if (timedOut) return reject(new DomainError('tool_failed', `${cmd} timed out`));
      if (overflow) return reject(new DomainError('tool_failed', `${cmd} produced too much output`));
      const c = code ?? -1;
      if (c !== 0 && options.allowFail !== true) return reject(new DomainError('tool_failed', `${cmd} exited with ${c}`));
      resolve({ code: c, stdout: Buffer.concat(out), stderr });
    }));
    child.stdin.on('error', () => { /* tool closed stdin early */ });
    child.stdin.end(options.input ?? '');
  });
}

const versions = new Map<string, string | null>();
/** First version line of a tool, or null when it is not installed. */
export async function toolVersion(name: string): Promise<string | null> {
  if (versions.has(name)) return versions.get(name) ?? null;
  let v: string | null = null;
  try {
    const r = await run(name, name === 'exiftool' ? ['-ver'] : name === 'pdftotext' || name === 'pdftocairo' ? ['-v'] : name === 'ffmpeg' || name === 'convert' ? ['-version'] : ['--version'], { allowFail: true, timeoutMs: 30_000 });
    v = `${r.stdout.toString('utf8')}\n${r.stderr}`.split('\n').find((l) => l.trim() !== '')?.trim().slice(0, 120) ?? null;
  } catch { v = null; }
  versions.set(name, v);
  return v;
}

/** Runs fn with a private temporary directory that is always removed. */
export async function withTempDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), 'e12-'));
  try { return await fn(dir); } finally { await rm(dir, { recursive: true, force: true }); }
}

// LibreOffice is not safe to run concurrently against one profile: serialize within the process and isolate the profile.
let officeQueue: Promise<unknown> = Promise.resolve();
async function officeConvert(input: string, outDir: string, profile: string): Promise<void> {
  const next = officeQueue.then(() => run('soffice', [`-env:UserInstallation=file://${profile}`, '--headless', '--norestore', '--convert-to', 'pdf', '--outdir', outDir, input], { timeoutMs: 180_000 }));
  officeQueue = next.catch(() => undefined);
  await next;
}

export type DocumentFormat = 'html' | 'pdf' | 'docx';
const PANDOC_FROM = 'markdown-raw_html-raw_tex-raw_attribute-yaml_metadata_block-tex_math_dollars-citations+pipe_tables+footnotes';
const CSS = 'body{font-family:serif;max-width:46em;margin:2em auto;padding:0 1em;line-height:1.45}table{border-collapse:collapse}td,th{border:1px solid #777;padding:.25em .5em;vertical-align:top}code{word-break:break-all}.stamp{border:2px solid #000;padding:.5em;font-weight:bold}';

/** Renders generator-authored Markdown (raw HTML/TeX disabled) to HTML, DOCX and PDF with pandoc and LibreOffice. */
export async function renderDocument(markdown: string, title: string, language: string, formats: readonly DocumentFormat[]): Promise<Partial<Record<DocumentFormat, Uint8Array>>> {
  const out: Partial<Record<DocumentFormat, Uint8Array>> = {};
  if (formats.length === 0) return out;
  invariant(/^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$/.test(language), 'invalid_input', 'Invalid language tag');
  await withTempDir(async (dir) => {
    const md = join(dir, 'doc.md');
    await writeFile(md, markdown);
    const meta = ['--metadata', `pagetitle=${title}`, '--metadata', `lang=${language}`];
    if (formats.includes('html')) {
      const header = join(dir, 'header.html');
      await writeFile(header, `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; base-uri 'none'; form-action 'none'">\n<style>${CSS}</style>\n`);
      const r = await run('pandoc', ['-f', PANDOC_FROM, '-t', 'html5', '-s', '--no-highlight', ...meta, '-H', header, md]);
      out.html = new Uint8Array(r.stdout);
    }
    if (formats.includes('docx') || formats.includes('pdf')) {
      const docx = join(dir, 'doc.docx');
      await run('pandoc', ['-f', PANDOC_FROM, '-t', 'docx', ...meta, '-o', docx, md]);
      if (formats.includes('docx')) out.docx = new Uint8Array(await readFile(docx));
      if (formats.includes('pdf')) {
        const profile = join(dir, 'profile');
        await mkdir(profile);
        await officeConvert(docx, dir, profile);
        out.pdf = new Uint8Array(await readFile(join(dir, 'doc.pdf')));
      }
    }
  });
  return out;
}

/** Escapes untrusted text for inline use in generator-authored Markdown. */
export function mdEscape(text: string): string {
  return text.normalize('NFC').replace(/[\u0000-\u001f\u007f]+/g, ' ').replace(/[\\`*_{}[\]()#+\-.!|<>~^$@"'=:&/]/g, (c) => `\\${c}`).trim();
}

// ───────────────────────────── ZIP (deterministic writer, minimal reader) ─────────────────────────────
export type ZipEntry = Readonly<{ path: string; bytes: Uint8Array }>;
const DOS_DATE = (1 << 5) | 1, DOS_TIME = 0; // 1980-01-01 00:00:00: archive bytes depend only on the entries.

/** Writes a ZIP archive (deflate, UTF-8 names, fixed timestamps, sorted entries). Entries above 4 GiB are refused. */
export function zipWrite(entries: readonly ZipEntry[]): Uint8Array {
  const sorted = [...entries].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  invariant(sorted.length < 65535, 'invalid_input', 'Too many archive entries');
  const parts: Buffer[] = []; const central: Buffer[] = []; let offset = 0; const seen = new Set<string>();
  for (const e of sorted) {
    invariant(!seen.has(e.path) && !e.path.startsWith('/') && !e.path.split('/').some((p) => p === '' || p === '.' || p === '..') && !e.path.includes('\\'), 'invalid_input', 'Invalid archive path');
    seen.add(e.path);
    const name = Buffer.from(e.path, 'utf8');
    const raw = Buffer.from(e.bytes.buffer, e.bytes.byteOffset, e.bytes.byteLength);
    const deflated = deflateRawSync(raw, { level: 9 });
    const stored = deflated.byteLength >= raw.byteLength;
    const data = stored ? raw : deflated;
    invariant(raw.byteLength < 0xffffffff && offset + data.byteLength < 0xffffffff, 'payload_too_large', 'Archive too large');
    const crc = crc32(raw);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt16LE(0x0800, 6); local.writeUInt16LE(stored ? 0 : 8, 8);
    local.writeUInt16LE(DOS_TIME, 10); local.writeUInt16LE(DOS_DATE, 12); local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.byteLength, 18); local.writeUInt32LE(raw.byteLength, 22); local.writeUInt16LE(name.byteLength, 26);
    const cd = Buffer.alloc(46);
    cd.writeUInt32LE(0x02014b50, 0); cd.writeUInt16LE(20, 4); cd.writeUInt16LE(20, 6); cd.writeUInt16LE(0x0800, 8); cd.writeUInt16LE(stored ? 0 : 8, 10);
    cd.writeUInt16LE(DOS_TIME, 12); cd.writeUInt16LE(DOS_DATE, 14); cd.writeUInt32LE(crc, 16); cd.writeUInt32LE(data.byteLength, 20); cd.writeUInt32LE(raw.byteLength, 24);
    cd.writeUInt16LE(name.byteLength, 28); cd.writeUInt32LE(offset, 42);
    parts.push(local, name, data); central.push(cd, name);
    offset += 30 + name.byteLength + data.byteLength;
  }
  const cdBytes = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(sorted.length, 8); end.writeUInt16LE(sorted.length, 10); end.writeUInt32LE(cdBytes.byteLength, 12); end.writeUInt32LE(offset, 16);
  return new Uint8Array(Buffer.concat([...parts, cdBytes, end]));
}

/** Reads a (non-ZIP64, unencrypted) archive. Bounded: refuses archives that inflate beyond `maxBytes`. */
export function zipRead(bytes: Uint8Array, maxBytes = 512 * 1024 * 1024): ZipEntry[] {
  const b = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let eocd = -1;
  for (let i = b.byteLength - 22; i >= Math.max(0, b.byteLength - 65557); i--) if (b.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  invariant(eocd >= 0, 'invalid_input', 'Not a ZIP archive');
  const count = b.readUInt16LE(eocd + 10); let p = b.readUInt32LE(eocd + 16); let total = 0;
  const out: ZipEntry[] = [];
  for (let i = 0; i < count; i++) {
    invariant(p + 46 <= b.byteLength && b.readUInt32LE(p) === 0x02014b50, 'invalid_input', 'Corrupt ZIP directory');
    const flags = b.readUInt16LE(p + 8), method = b.readUInt16LE(p + 10), csize = b.readUInt32LE(p + 20), usize = b.readUInt32LE(p + 24);
    const n = b.readUInt16LE(p + 28), m = b.readUInt16LE(p + 30), k = b.readUInt16LE(p + 32), local = b.readUInt32LE(p + 42);
    const path = b.subarray(p + 46, p + 46 + n).toString('utf8');
    invariant((flags & 1) === 0 && (method === 0 || method === 8) && local + 30 <= b.byteLength, 'invalid_input', 'Unsupported ZIP entry');
    const start = local + 30 + b.readUInt16LE(local + 26) + b.readUInt16LE(local + 28);
    total += usize; invariant(total <= maxBytes && start + csize <= b.byteLength, 'payload_too_large', 'Archive too large');
    const data = b.subarray(start, start + csize);
    if (!path.endsWith('/')) out.push({ path, bytes: new Uint8Array(method === 0 ? data : inflateRawSync(data, { maxOutputLength: Math.max(usize, 1) })) });
    p += 46 + n + m + k;
  }
  return out;
}

export function tempName(ext: string): string { return `${randomUUID()}${ext}`; }
