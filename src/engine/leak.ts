// Leak-prevention pipeline: component allow-listing, metadata stripping with read-back verification, thumbnail
// regeneration from the released (redacted) bytes, and protected-term scanning of every text surface.
// Protected terms are held in memory only; persisted form is salted hashes and findings never contain a term.
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { extname, join } from 'node:path';
import { DomainError, invariant } from '../contracts.ts';
import type { Json } from '../contracts.ts';
import { run, sha256, withTempDir, zipRead } from './tools.ts';

export type ComponentClass = 'generated' | 'data' | 'redacted_derivative' | 'original' | 'caption' | 'thumbnail' | 'render';
export type DraftComponent = {
  path: string; role: string; mediaType: string; bytes: Uint8Array; class: ComponentClass;
  /** Upstream urefs this component depends on. */
  sources: readonly string[];
  basis?: string; label?: string; altText?: string;
  /** Filename as supplied by the caller (scanned even though the stored path is generated). */
  suppliedName?: string;
  /** Set by the engine after audience policy and a consent decision allowed this original. */
  originalAllowed?: boolean;
  /** Rights subject (uref) this component reproduces, if any. */
  subject?: string;
};
export type Finding = { code: string; path: string; field: string; line?: number; term?: string; detail: string };
export type RedactionAction = { path: string; action: string; detail: string };
export type FileKind = 'text' | 'pdf' | 'image' | 'media' | 'docx' | 'unknown';

const norm = (text: string): string => text.normalize('NFKC').toLowerCase().replace(/[^\p{L}\p{N}]+/gu, ' ').trim();
const compact = (text: string): string => norm(text).replaceAll(' ', '');

/** In-memory matcher over protected identity strings. */
export class ProtectedTerms {
  readonly #terms: readonly { n: string; c: string }[];
  constructor(terms: readonly string[]) {
    const seen = new Map<string, { n: string; c: string }>();
    for (const t of terms) {
      invariant(typeof t === 'string' && t.length <= 500, 'invalid_input', 'Invalid protected term');
      const n = norm(t);
      invariant(n.length >= 2, 'invalid_input', 'Protected terms need at least two letters or digits');
      seen.set(n, { n, c: n.replaceAll(' ', '') });
    }
    this.#terms = [...seen.values()].sort((a, b) => (a.n < b.n ? -1 : 1));
  }
  get count(): number { return this.#terms.length; }
  /** Salted hashes for storage: lets a later caller prove it supplied the same terms without the engine keeping them. */
  hashes(salt: string): string[] { return this.#terms.map((t) => createHash('sha256').update(`${salt}\n${t.n}`).digest('hex')).sort(); }
  #id(i: number): string { return `term#${i + 1}`; }
  /** Returns located hits; `term` is an ordinal label, never the term. */
  scan(text: string, options: { filename?: boolean } = {}): { term: string; line?: number }[] {
    if (this.#terms.length === 0 || text === '') return [];
    const hits: { term: string; line?: number }[] = [];
    const whole = ` ${norm(text)} `;
    const wholeCompact = options.filename === true ? compact(text) : '';
    let lines: string[] | undefined;
    this.#terms.forEach((t, i) => {
      const inWhole = whole.includes(` ${t.n} `);
      const inName = options.filename === true && t.c.length >= 5 && wholeCompact.includes(t.c);
      if (!inWhole && !inName) return;
      lines ??= text.split('\n').map((l) => ` ${norm(l)} `);
      const at = lines.flatMap((l, n) => (l.includes(` ${t.n} `) ? [n + 1] : []));
      if (at.length === 0) hits.push({ term: this.#id(i) });
      else for (const line of at.slice(0, 20)) hits.push({ term: this.#id(i), line });
    });
    return hits;
  }
  /** Scans raw bytes for UTF-8 and UTF-16 encodings of each term (case-insensitive for ASCII). */
  scanBytes(bytes: Uint8Array): string[] {
    if (this.#terms.length === 0) return [];
    const hay = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('latin1').toLowerCase();
    const hits: string[] = [];
    this.#terms.forEach((t, i) => {
      const variants = new Set<string>();
      for (const sep of [' ', '_', '-', '.', '']) {
        const s = t.n.replaceAll(' ', sep);
        if (sep === '' && s.length < 5) continue;
        variants.add(Buffer.from(s, 'utf8').toString('latin1'));
        variants.add(Buffer.from(s, 'utf16le').toString('latin1'));
        variants.add(Buffer.from(s, 'utf16le').swap16().toString('latin1'));
      }
      if ([...variants].some((v) => hay.includes(v.toLowerCase()))) hits.push(this.#id(i));
    });
    return hits;
  }
}

const EXT_KIND: Readonly<Record<string, FileKind>> = {
  '.txt': 'text', '.md': 'text', '.html': 'text', '.json': 'text', '.csv': 'text', '.vtt': 'text', '.srt': 'text',
  '.pdf': 'pdf', '.jpg': 'image', '.jpeg': 'image', '.png': 'image', '.gif': 'image', '.webp': 'image',
  '.mp4': 'media', '.mov': 'media', '.m4a': 'media', '.webm': 'media', '.mkv': 'media', '.mp3': 'media', '.wav': 'media', '.ogg': 'media', '.docx': 'docx',
};
export function sniff(bytes: Uint8Array): FileKind {
  const b = Buffer.from(bytes.buffer, bytes.byteOffset, Math.min(bytes.byteLength, 16));
  const s = b.toString('latin1');
  if (s.startsWith('%PDF-')) return 'pdf';
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'image';
  if (s.startsWith('\x89PNG') || s.startsWith('GIF8') || (s.startsWith('RIFF') && s.slice(8, 12) === 'WEBP')) return 'image';
  if (s.slice(4, 8) === 'ftyp' || s.startsWith('\x1a\x45\xdf\xa3') || s.startsWith('ID3') || s.startsWith('OggS') || (s.startsWith('RIFF') && s.slice(8, 12) === 'WAVE') || (b[0] === 0xff && ((b[1] ?? 0) & 0xe0) === 0xe0)) return 'media';
  if (s.startsWith('PK\x03\x04')) return 'docx';
  try { const t = new TextDecoder('utf-8', { fatal: true }).decode(bytes); return t.includes('\u0000') ? 'unknown' : 'text'; } catch { return 'unknown'; }
}
export function kindOf(path: string, bytes: Uint8Array): FileKind {
  const byExt = EXT_KIND[extname(path).toLowerCase()] ?? 'unknown';
  return byExt !== 'unknown' && sniff(bytes) === byExt ? byExt : 'unknown';
}

const DENIED_GROUP = /^(IFD|ExifIFD|SubIFD|GPS|IPTC|XMP|Photoshop|MakerNotes|InteropIFD|ICC|ItemList|UserData|Keys|ID3|Vorbis|APE|MPF|FlashPix|Adobe|Ducky|JFXX)/;
const DENIED_TAG = /^(Author|Artist|Creator|CreatorTool|Title|Subject|Keywords|Comment|Description|Copyright|Producer|Software|Make|Model|Owner.*|.*Serial.*|GPS.*|Location.*|Encoder|Album|Genre|Composer|Publisher|ModDate|CreationDate|CreateDate|ModifyDate|UserComment|XP.*|By-line.*|Thumbnail.*|PreviewImage)$/i;
const ZERO_DATE = /^0000:00:00/;

/** Reads every metadata tag back with exiftool and reports residual identifying tags and protected-term hits. */
export async function metadataFindings(file: string, path: string, terms: ProtectedTerms): Promise<Finding[]> {
  const r = await run('exiftool', ['-j', '-a', '-G1', '-n', '--', file], { allowFail: true, timeoutMs: 60_000 });
  let tags: Record<string, unknown>;
  try { tags = (JSON.parse(r.stdout.toString('utf8')) as Record<string, unknown>[])[0] ?? {}; }
  catch { return [{ code: 'metadata_unreadable', path, field: 'metadata', detail: 'exiftool could not read the file back' }]; }
  const out: Finding[] = [];
  for (const [key, value] of Object.entries(tags)) {
    const [group, name] = key.includes(':') ? key.split(':', 2) as [string, string] : ['', key];
    if (group === 'System' || group === 'ExifTool' || key === 'SourceFile') continue;
    const text = typeof value === 'string' ? value : JSON.stringify(value);
    for (const hit of terms.scan(text)) out.push({ code: 'protected_term_in_metadata', path, field: `metadata:${key}`, term: hit.term, detail: 'Protected term present in file metadata after stripping' });
    if (DENIED_GROUP.test(group) || (DENIED_TAG.test(name) && !(typeof value === 'string' && ZERO_DATE.test(value)) && value !== 0 && value !== ''))
      out.push({ code: 'metadata_residual', path, field: `metadata:${key}`, detail: 'Identifying metadata tag survived stripping' });
  }
  return out;
}

async function stripFile(dir: string, c: DraftComponent, kind: FileKind, actions: RedactionAction[]): Promise<Uint8Array> {
  const ext = extname(c.path).toLowerCase();
  const input = join(dir, `in${ext}`);
  await writeFile(input, c.bytes);
  let current = input;
  if (kind === 'pdf' && c.class !== 'generated') {
    // exiftool's PDF edits are incremental (recoverable), so supplied PDFs are first rewritten page by page.
    const rewritten = join(dir, `rw${ext}`);
    await run('pdftocairo', ['-pdf', input, rewritten], { timeoutMs: 300_000 });
    current = rewritten;
    actions.push({ path: c.path, action: 'pdf_rewritten', detail: 'Pages re-rendered into a new PDF; original document information, XMP, attachments and annotations are not carried over' });
  }
  if (kind === 'media') {
    const remux = join(dir, `rm${ext}`);
    await run('ffmpeg', ['-v', 'error', '-nostdin', '-i', current, '-map', '0', '-map_metadata', '-1', '-map_chapters', '-1', '-c', 'copy', '-fflags', '+bitexact', '-flags:v', '+bitexact', '-flags:a', '+bitexact', '-y', remux], { timeoutMs: 600_000 });
    current = remux;
    actions.push({ path: c.path, action: 'metadata_stripped', detail: 'Container metadata and chapters removed by stream copy' });
  } else {
    await run('exiftool', ['-q', '-q', '-overwrite_original', kind === 'pdf' ? '-all:all=' : '-all=', '--', current], { timeoutMs: 120_000 });
    actions.push({ path: c.path, action: 'metadata_stripped', detail: 'All writable metadata removed with exiftool' });
  }
  return new Uint8Array(await readFile(current));
}

function htmlText(html: string): string {
  return html.replace(/<\/(p|div|li|tr|h\d|w:p)>/gi, '\n').replace(/<[^>]*>/g, '').replace(/&(amp|lt|gt|quot|#39);/g, (_, e: string) => ({ amp: '&', lt: '<', gt: '>', quot: '"', '#39': "'" })[e] ?? ' ');
}

/** Extracts the human-readable text of a component (documents via pdftotext / DOCX XML / plain text). */
export async function extractText(path: string, bytes: Uint8Array, kind: FileKind): Promise<string> {
  if (kind === 'text') { const t = new TextDecoder().decode(bytes); return extname(path).toLowerCase() === '.html' ? `${htmlText(t)}\n${t}` : t; }
  if (kind === 'pdf') {
    // Reading order and content-stream order: a name split by table layout in one is usually contiguous in the other.
    const a = await run('pdftotext', ['-enc', 'UTF-8', '-', '-'], { input: bytes, timeoutMs: 120_000 });
    const b = await run('pdftotext', ['-enc', 'UTF-8', '-raw', '-', '-'], { input: bytes, timeoutMs: 120_000 });
    return `${a.stdout.toString('utf8')}\n${b.stdout.toString('utf8')}`;
  }
  if (kind === 'docx') return zipRead(bytes, 256 * 1024 * 1024).filter((e) => /\.(xml|rels)$/.test(e.path)).map((e) => htmlText(new TextDecoder().decode(e.bytes))).join('\n');
  return '';
}

async function contentFindings(c: Pick<DraftComponent, 'path' | 'bytes' | 'label' | 'altText' | 'suppliedName'>, kind: FileKind, terms: ProtectedTerms): Promise<{ findings: Finding[]; text: string }> {
  const findings: Finding[] = [];
  const add = (code: string, field: string, hits: { term: string; line?: number }[], detail: string): void => { for (const h of hits) findings.push({ code, path: c.path, field, term: h.term, ...(h.line === undefined ? {} : { line: h.line }), detail }); };
  add('protected_term_in_filename', 'filename', terms.scan(c.path, { filename: true }), 'Protected term in component path');
  if (c.suppliedName !== undefined) add('protected_term_in_filename', 'supplied_filename', terms.scan(c.suppliedName, { filename: true }), 'Protected term in the supplied file name');
  if (c.label !== undefined) add('protected_term_in_manifest', 'label', terms.scan(c.label), 'Protected term in component label');
  if (c.altText !== undefined) add('protected_term_in_alt_text', 'alt_text', terms.scan(c.altText), 'Protected term in alternative text');
  const text = await extractText(c.path, c.bytes, kind);
  add('protected_term_in_text', 'content', terms.scan(text), 'Protected term in component text');
  for (const term of terms.scanBytes(c.bytes)) if (!findings.some((f) => f.field === 'content' && f.term === term)) findings.push({ code: 'protected_term_in_bytes', path: c.path, field: 'bytes', term, detail: 'Protected term found in raw file bytes' });
  return { findings, text };
}

export type SanitizeResult = { components: DraftComponent[]; findings: Finding[]; redactions: RedactionAction[]; indexText: string };

/** Build-time pipeline. Returns sanitized components; any finding fails the candidate. */
export async function sanitize(input: readonly DraftComponent[], terms: ProtectedTerms, extraFields: Readonly<Record<string, string>> = {}): Promise<SanitizeResult> {
  const findings: Finding[] = []; const redactions: RedactionAction[] = []; const components: DraftComponent[] = []; const texts: string[] = [];
  for (const [field, value] of Object.entries(extraFields)) for (const h of terms.scan(value)) findings.push({ code: 'protected_term_in_manifest', path: 'manifest.json', field, term: h.term, ...(h.line === undefined ? {} : { line: h.line }), detail: 'Protected term in a manifest field' });
  const paths = new Set<string>();
  await withTempDir(async (root) => {
    let n = 0;
    for (const c of input) {
      invariant(/^[A-Za-z0-9][A-Za-z0-9._-]*(\/[A-Za-z0-9][A-Za-z0-9._-]*)*$/.test(c.path) && c.path.length <= 300 && c.path !== 'manifest.json' && !paths.has(c.path), 'invalid_input', 'Invalid or duplicate component path');
      paths.add(c.path);
      if (c.class === 'thumbnail') {
        for (const h of terms.scan(c.suppliedName ?? '', { filename: true })) findings.push({ code: 'protected_term_in_filename', path: c.path, field: 'supplied_filename', term: h.term, detail: 'Protected term in the supplied thumbnail name' });
        redactions.push({ path: c.path, action: 'supplied_thumbnail_discarded', detail: 'Caller-supplied thumbnails are never released; thumbnails are regenerated from the released file' });
        continue;
      }
      if (c.class === 'original' && c.originalAllowed !== true) { findings.push({ code: 'original_not_permitted', path: c.path, field: 'class', detail: 'Original files are released only when audience policy and a consent decision both allow it' }); continue; }
      const kind = kindOf(c.path, c.bytes);
      if (kind === 'unknown' || (kind === 'docx' && c.class !== 'generated')) { findings.push({ code: 'unsupported_component_type', path: c.path, field: 'bytes', detail: 'File type is not on the allow-list or does not match its extension' }); continue; }
      let bytes = c.bytes;
      const dir = join(root, String(n++));
      await run('mkdir', ['-p', dir]);
      if (kind === 'pdf' || kind === 'image' || kind === 'media') {
        try { bytes = await stripFile(dir, c, kind, redactions); }
        catch (error) { if (error instanceof DomainError && error.code === 'unavailable') throw error; findings.push({ code: 'sanitization_failed', path: c.path, field: 'bytes', detail: 'File could not be sanitized' }); continue; }
        const check = join(dir, `check${extname(c.path).toLowerCase()}`);
        await writeFile(check, bytes);
        findings.push(...await metadataFindings(check, c.path, terms));
      }
      const clean: DraftComponent = { ...c, bytes };
      const scanned = await contentFindings(clean, kind, terms);
      findings.push(...scanned.findings);
      components.push(clean); texts.push(scanned.text);
      if ((kind === 'image' || (kind === 'media' && /\.(mp4|mov|webm|mkv)$/i.test(c.path))) && c.class !== 'generated') {
        const src = join(dir, `thumbsrc${extname(c.path).toLowerCase()}`), out = join(dir, 'thumb.jpg');
        await writeFile(src, bytes);
        try {
          if (kind === 'image') await run('convert', [`${src}[0]`, '-thumbnail', '320x320', '-background', 'white', '-flatten', '-strip', `jpeg:${out}`], { timeoutMs: 120_000 });
          else await run('ffmpeg', ['-v', 'error', '-nostdin', '-i', src, '-frames:v', '1', '-vf', 'scale=320:-2', '-map_metadata', '-1', '-fflags', '+bitexact', '-y', out], { timeoutMs: 120_000 });
          await run('exiftool', ['-q', '-q', '-overwrite_original', '-all=', '--', out], { timeoutMs: 60_000 });
          const thumbPath = `thumbnails/${c.path.replaceAll('/', '_')}.jpg`;
          components.push({ path: thumbPath, role: 'thumbnail', mediaType: 'image/jpeg', bytes: new Uint8Array(await readFile(out)), class: 'generated', sources: c.sources, label: `Thumbnail of ${c.path}` });
          redactions.push({ path: thumbPath, action: 'thumbnail_regenerated', detail: `Generated from the sanitized bytes of ${c.path}` });
          findings.push(...await metadataFindings(out, thumbPath, terms));
        } catch (error) { if (error instanceof DomainError && error.code === 'unavailable') throw error; /* audio-only or undecodable: no thumbnail */ }
      }
    }
  });
  return { components, findings, redactions, indexText: texts.join('\n') };
}

/** Release-time verification of stored bytes: nothing is modified; any finding blocks the release. */
export async function verifyStored(components: readonly { path: string; bytes: Uint8Array; sha256: string; label?: string; altText?: string }[], terms: ProtectedTerms, extraFields: Readonly<Record<string, string>>): Promise<Finding[]> {
  const findings: Finding[] = [];
  for (const [field, value] of Object.entries(extraFields)) for (const h of terms.scan(value)) findings.push({ code: 'protected_term_in_manifest', path: 'manifest.json', field, term: h.term, detail: 'Protected term in a manifest field' });
  await withTempDir(async (dir) => {
    for (const [i, c] of components.entries()) {
      if (sha256(c.bytes) !== c.sha256) { findings.push({ code: 'content_changed', path: c.path, field: 'bytes', detail: 'Stored bytes no longer match the approved digest' }); continue; }
      const kind = kindOf(c.path, c.bytes);
      if (kind === 'unknown') { findings.push({ code: 'unsupported_component_type', path: c.path, field: 'bytes', detail: 'File type is not on the allow-list' }); continue; }
      if (kind === 'pdf' || kind === 'image' || kind === 'media') {
        const file = join(dir, `${i}${extname(c.path).toLowerCase()}`);
        await writeFile(file, c.bytes);
        findings.push(...await metadataFindings(file, c.path, terms));
      }
      findings.push(...(await contentFindings(c, kind, terms)).findings);
    }
  });
  return findings;
}
export const findingsJson = (f: readonly Finding[]): Json => JSON.parse(JSON.stringify(f)) as Json;
