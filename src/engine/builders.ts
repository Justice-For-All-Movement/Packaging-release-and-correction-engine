// Package builders. Each turns caller-supplied, already-sourced material into a draft: released files plus
// generator-authored Markdown documents. Builders never add facts, sources or legal authorities of their own.
import { basename, extname } from 'node:path';
import { canonical, DomainError, invariant } from '../contracts.ts';
import type { Json } from '../contracts.ts';
import { parseUref } from '../service-kit.ts';
import type { DraftComponent, RedactionAction } from './leak.ts';
import { mdEscape as e, sha256, utf8 } from './tools.ts';

export type PackageKind = 'evidence_bundle' | 'investigation_report' | 'chronology' | 'referral_package' | 'records_request' | 'legal_draft' | 'source_companion' | 'media_package';
export const PACKAGE_KINDS: readonly PackageKind[] = ['evidence_bundle', 'investigation_report', 'chronology', 'referral_package', 'records_request', 'legal_draft', 'source_companion', 'media_package'];

export type FileInput = Readonly<{ filename: string; mediaType: string; base64: string } | { filename?: string; evidenceRef: string }>;
export type ResolvedFile = { filename: string; mediaType: string; bytes: Uint8Array };
export type SourceCite = Readonly<{ ref: string; locator?: string; supports?: string }>;
export type FindingStatus = 'established' | 'disputed' | 'unknown';
export type PackageFinding = Readonly<{ id: string; ref?: string; statement: string; status: FindingStatus; sources?: readonly SourceCite[]; limitations?: readonly string[]; date?: string }>;
/** Shape of an E08 investigation package as accepted here (supplied by the caller; this engine never reads E08). */
export type InvestigationPackage = Readonly<{
  investigationRef?: string; title: string; summary?: string; methodology?: string; limitations?: readonly string[];
  findings: readonly PackageFinding[];
  chronology?: readonly Readonly<{ date: string; event: string; status: FindingStatus; findingIds?: readonly string[]; sources?: readonly SourceCite[] }>[];
  openQuestions?: readonly Readonly<{ id: string; question: string; recordsSought?: string; holder?: string }>[];
}>;
export type EvidenceItem = Readonly<{
  ref: string; label: string; description?: string; altText?: string; basis?: string;
  custody?: readonly Readonly<{ at: string; actor: string; action: string; note?: string }>[];
  redacted?: FileInput; original?: FileInput; includeOriginal?: boolean; thumbnail?: FileInput; rightsDecisionRefs?: readonly string[];
}>;
export type Party = Readonly<{ name: string; organization?: string; role?: string; address?: string; contact?: string }>;
export type CommonInput = Readonly<{
  title: string; audience: string; language?: string; formats?: readonly ('html' | 'pdf' | 'docx')[];
  protectedTerms?: readonly string[]; protectedSourceRefs?: readonly string[]; subjects?: readonly string[];
  participantReviewers?: readonly string[]; supersedes?: string; compartment?: string; idempotencyKey?: string;
}>;
export type BuildInput = CommonInput & (
  | { kind: 'evidence_bundle'; items: readonly EvidenceItem[]; note?: string }
  | { kind: 'investigation_report'; package: InvestigationPackage }
  | { kind: 'chronology'; package: InvestigationPackage }
  | { kind: 'referral_package'; recipient: Party; contact: Party; coverSummary: string; package: InvestigationPackage; items?: readonly EvidenceItem[] }
  | { kind: 'records_request'; jurisdictionPackId: string; requester: Party; recipient: Party; package?: InvestigationPackage; recordsSought?: readonly string[]; values?: Readonly<Record<string, string>>; professionalReviewId?: string }
  | { kind: 'legal_draft'; jurisdictionPackId: string; documentType: string; package: InvestigationPackage; values?: Readonly<Record<string, string>>; professionalReviewId?: string }
  | { kind: 'source_companion'; sources: readonly Readonly<{ ref: string; title?: string; publisher?: string; date?: string; url?: string; supports: readonly string[]; protected?: boolean; publicLabel?: string }>[]; introduction?: string }
  | { kind: 'media_package'; renders: readonly Readonly<{ ref: string; label: string; file: FileInput; manifest?: Json; altText?: string; thumbnail?: FileInput; captions?: readonly Readonly<{ language: string; format: 'vtt' | 'srt'; text: string }>[]; sources?: readonly string[] }>[]; credits?: readonly Readonly<{ role: string; name: string }>[]; disclosures?: readonly string[]; rightsSummary?: readonly Readonly<{ subject: string; holder?: string; license?: string; terms?: string; decisionRef?: string }>[] }
);

// ───────────────────────────── Jurisdiction packs (deployment data) ─────────────────────────────
export type PackAuthority = Readonly<{ id: string; citation: string; title?: string; reviewed: boolean; reviewedBy?: string; reviewedOn?: string; note?: string }>;
export type PackSection = Readonly<{ id: string; heading: string; required?: boolean; body: string }>;
export type PackDocumentType = Readonly<{ title: string; placeholders?: readonly Readonly<{ name: string; required?: boolean; description?: string }>[]; assumptions?: readonly string[]; sections: readonly PackSection[] }>;
export type JurisdictionPack = Readonly<{ id: string; name: string; version: number; language?: string; assumptions?: readonly string[]; authorities: readonly PackAuthority[]; documentTypes: Readonly<Record<string, PackDocumentType>> }>;
const TOKEN = /\{\{\s*([a-z_]+)(?::([A-Za-z0-9_.-]+))?\s*\}\}/g;
const TOKENS = ['var', 'facts', 'authority', 'authorities', 'records_sought', 'requester', 'recipient'];
export function validatePack(value: unknown): JurisdictionPack {
  const p = value as JurisdictionPack;
  const str = (v: unknown, max = 4000): boolean => typeof v === 'string' && v.trim() !== '' && v.length <= max;
  invariant(p !== null && typeof p === 'object' && str(p.id, 80) && /^[a-z0-9][a-z0-9-]*$/.test(p.id) && str(p.name, 200) && Number.isSafeInteger(p.version) && p.version > 0, 'invalid_config', 'Jurisdiction pack needs id, name and version');
  invariant(Array.isArray(p.authorities) && p.authorities.every((a) => str(a.id, 80) && /^[A-Za-z0-9_.-]+$/.test(a.id) && str(a.citation, 500) && typeof a.reviewed === 'boolean'), 'invalid_config', 'Jurisdiction pack authorities need id, citation and reviewed');
  invariant(new Set(p.authorities.map((a) => a.id)).size === p.authorities.length, 'invalid_config', 'Duplicate authority id');
  invariant(p.documentTypes !== null && typeof p.documentTypes === 'object', 'invalid_config', 'Jurisdiction pack needs documentTypes');
  for (const [id, d] of Object.entries(p.documentTypes)) {
    invariant(/^[a-z][a-z0-9_]*$/.test(id) && str(d.title, 300) && Array.isArray(d.sections) && d.sections.length > 0, 'invalid_config', `Invalid document type ${id}`);
    for (const s of d.sections) {
      invariant(str(s.id, 80) && str(s.heading, 300) && typeof s.body === 'string' && s.body.length <= 20000, 'invalid_config', `Invalid section in ${id}`);
      for (const m of s.body.matchAll(TOKEN)) invariant(TOKENS.includes(m[1] as string), 'invalid_config', `Unknown template token ${m[1]} in ${id}`);
      invariant(!/\{\{|\}\}/.test(s.body.replace(TOKEN, '')), 'invalid_config', `Malformed template token in ${id}`);
    }
  }
  return p;
}

export const DRAFT_STAMP = 'DRAFT — generated for review; not legal advice; not filed; not reviewed by a legal professional';
export const UNRESOLVED_AUTHORITY = '[authority to be identified by a qualified reviewer]';
export type ProfessionalReview = Readonly<{ id: string; reviewerName: string; reviewerRole: string; reviewedOn: string; contentDigest: string }>;

// ───────────────────────────── Shared pieces ─────────────────────────────
export type DocSpec = { base: string; title: string; markdown: string; role: string; sources: string[] };
export type Draft = {
  files: DraftComponent[]; redactions: RedactionAction[];
  /** Called with the sanitized files so indexes carry the digests of the bytes actually released. */
  finish(files: readonly DraftComponent[]): { docs: DocSpec[]; data: DraftComponent[] };
  /** Every upstream uref the candidate depends on (including protected ones, which never reach the manifest). */
  sources: string[]; subjects: string[]; extra: Record<string, Json>; scanFields: Record<string, string>;
};
export type BuildHelpers = {
  resolve(file: FileInput): Promise<ResolvedFile>;
  /** Audience policy AND a consent decision must both allow an original. */
  allowOriginal(subject: string): Promise<boolean>;
  pack(id: string): JurisdictionPack;
  review(id: string): Promise<ProfessionalReview>;
};

const text = (v: unknown, label: string, max = 4000): string => { invariant(typeof v === 'string' && v.trim() !== '' && v.length <= max, 'invalid_input', `${label} is required (at most ${max} characters)`); return v; };
const list = <T>(v: readonly T[] | undefined, label: string, max = 2000): readonly T[] => { invariant(v === undefined || (Array.isArray(v) && v.length <= max), 'invalid_input', `${label} must be a list of at most ${max}`); return v ?? []; };
const ref = (v: unknown): string => { invariant(typeof v === 'string', 'invalid_reference', 'Invalid universal reference'); parseUref(v); return v; };
export function safeName(name: string): string {
  const base = basename(name.replaceAll('\\', '/')).normalize('NFKD').replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^[.-]+/, '').slice(-80);
  const ext = extname(base).toLowerCase();
  const stem = base.slice(0, base.length - ext.length).replace(/\.+/g, '-') || 'file';
  return `${stem}${ext === '.jpeg' ? '.jpg' : ext}`;
}
const json = (path: string, role: string, value: unknown, sources: readonly string[]): DraftComponent => ({ path, role, mediaType: 'application/json', bytes: utf8(`${JSON.stringify(JSON.parse(canonical(JSON.parse(JSON.stringify(value)))), null, 2)}\n`), class: 'data', sources: [...sources] });

/** Numbered source notes. Protected sources are cited as "protected source" with no reference. */
class SourceNotes {
  readonly #order: string[] = []; readonly #locators = new Map<string, Set<string>>(); readonly #protected: ReadonlySet<string>;
  constructor(protectedRefs: readonly string[]) { this.#protected = new Set(protectedRefs.map(ref)); }
  cite(c: SourceCite): string {
    const r = ref(c.ref);
    if (!this.#order.includes(r)) this.#order.push(r);
    if (c.locator !== undefined && !this.#protected.has(r)) { const s = this.#locators.get(r) ?? new Set(); s.add(text(c.locator, 'locator', 300)); this.#locators.set(r, s); }
    return `\\[S${this.#order.indexOf(r) + 1}\\]`;
  }
  citeAll(cs: readonly SourceCite[] | undefined): string { return list(cs, 'sources', 200).map((c) => this.cite(c)).join(' '); }
  get all(): string[] { return [...this.#order]; }
  get public(): string[] { return this.#order.filter((r) => !this.#protected.has(r)); }
  section(): string {
    if (this.#order.length === 0) return '## Sources\n\nNo sources are cited in this document.\n';
    return `## Sources\n\n${this.#order.map((r, i) => this.#protected.has(r)
      ? `- S${i + 1} — protected source (identity withheld; held by the originating team)`
      : `- S${i + 1} — \`${r}\`${[...(this.#locators.get(r) ?? [])].map((l) => ` — ${e(l)}`).join('')}`).join('\n')}\n`;
  }
}

function checkPackage(p: InvestigationPackage): InvestigationPackage {
  invariant(p !== null && typeof p === 'object', 'invalid_input', 'Investigation package is required');
  text(p.title, 'package title', 300);
  const ids = new Set<string>();
  for (const f of list(p.findings, 'findings')) {
    text(f.id, 'finding id', 100); text(f.statement, 'finding statement');
    invariant(!ids.has(f.id), 'invalid_input', 'Duplicate finding id'); ids.add(f.id);
    invariant(['established', 'disputed', 'unknown'].includes(f.status), 'invalid_input', 'Finding status must be established, disputed or unknown');
    for (const s of list(f.sources, 'sources', 200)) ref(s.ref);
    invariant(f.status !== 'established' || list(f.sources, 'sources').length > 0, 'invalid_input', `Established finding ${f.id} has no source; it cannot be presented as established`);
    if (f.ref !== undefined) ref(f.ref);
  }
  for (const c of list(p.chronology, 'chronology')) {
    text(c.date, 'chronology date', 40); text(c.event, 'chronology event');
    invariant(['established', 'disputed', 'unknown'].includes(c.status), 'invalid_input', 'Chronology status must be established, disputed or unknown');
    for (const id of list(c.findingIds, 'findingIds')) invariant(ids.has(id), 'invalid_input', 'Chronology entry names an unknown finding');
    invariant(c.status !== 'established' || list(c.sources, 'sources').length + list(c.findingIds, 'findingIds').length > 0, 'invalid_input', 'Established chronology entry has no source');
  }
  for (const q of list(p.openQuestions, 'openQuestions')) { text(q.id, 'question id', 100); text(q.question, 'question'); }
  if (p.investigationRef !== undefined) ref(p.investigationRef);
  return p;
}
const packageRefs = (p: InvestigationPackage): string[] => [...(p.investigationRef === undefined ? [] : [p.investigationRef]), ...p.findings.flatMap((f) => (f.ref === undefined ? [] : [f.ref]))];
const LABEL: Readonly<Record<FindingStatus, string>> = { established: 'ESTABLISHED', disputed: 'DISPUTED', unknown: 'UNKNOWN' };

function findingsMarkdown(p: InvestigationPackage, notes: SourceNotes, statuses: readonly FindingStatus[]): string {
  const out: string[] = [];
  for (const status of statuses) {
    const fs = p.findings.filter((f) => f.status === status);
    out.push(`### ${status === 'established' ? 'Established' : status === 'disputed' ? 'Disputed' : 'Unknown or unresolved'}\n`);
    if (fs.length === 0) { out.push('None.\n'); continue; }
    for (const f of fs) {
      const cites = notes.citeAll(f.sources);
      out.push(`- **${e(f.id)}** (${LABEL[f.status]}) ${e(f.statement)} ${cites === '' ? '(no source cited)' : cites}`);
      for (const l of list(f.limitations, 'limitations', 50)) out.push(`    - Limitation: ${e(text(l, 'limitation'))}`);
    }
    out.push('');
  }
  return out.join('\n');
}
function chronologyRows(p: InvestigationPackage, notes: SourceNotes): string {
  const byId = new Map(p.findings.map((f) => [f.id, f]));
  const entries = [...list(p.chronology, 'chronology')].map((c, i) => ({ c, i })).sort((a, b) => (a.c.date < b.c.date ? -1 : a.c.date > b.c.date ? 1 : a.i - b.i));
  if (entries.length === 0) return 'No dated events were supplied.\n';
  const rows = entries.map(({ c }) => {
    const cites = [notes.citeAll(c.sources), ...list(c.findingIds, 'findingIds').map((id) => `${e(id)} ${notes.citeAll(byId.get(id)?.sources)}`)].filter((s) => s.trim() !== '').join('; ');
    return `| ${e(c.date)} | ${e(c.event)} | ${LABEL[c.status]} | ${cites === '' ? 'no source cited' : cites} |`;
  });
  return `| Date | Event | Status | Sources |\n|---|---|---|---|\n${rows.join('\n')}\n`;
}
function partyLines(p: Party, label: string): string {
  invariant(p !== null && typeof p === 'object', 'invalid_input', `${label} is required`);
  return [text(p.name, `${label} name`, 300), p.role, p.organization, p.address, p.contact].filter((v): v is string => typeof v === 'string' && v.trim() !== '').map((v) => e(v)).join('  \n');
}
const partyFields = (p: Party, prefix: string): Record<string, string> => Object.fromEntries(Object.entries(p).filter(([, v]) => typeof v === 'string').map(([k, v]) => [`${prefix}.${k}`, v as string]));

async function evidenceFiles(items: readonly EvidenceItem[], h: BuildHelpers, redactions: RedactionAction[]): Promise<{ files: DraftComponent[]; index: { item: EvidenceItem; path: string | null; cls: string }[] }> {
  const files: DraftComponent[] = []; const index: { item: EvidenceItem; path: string | null; cls: string }[] = [];
  for (const [i, item] of list(items, 'items', 500).entries()) {
    ref(item.ref); text(item.label, 'item label', 300);
    const n = String(i + 1).padStart(3, '0');
    let chosen: { file: ResolvedFile; cls: 'original' | 'redacted_derivative'; allowed: boolean } | null = null;
    if (item.includeOriginal === true && item.original !== undefined) {
      const allowed = await h.allowOriginal(item.ref);
      if (allowed || item.redacted === undefined) chosen = { file: await h.resolve(item.original), cls: 'original', allowed };
      else redactions.push({ path: `evidence/${n}`, action: 'original_excluded', detail: 'Original requested but not permitted for this audience; the redacted derivative is used' });
    }
    if (chosen === null && item.redacted !== undefined) chosen = { file: await h.resolve(item.redacted), cls: 'redacted_derivative', allowed: false };
    if (chosen === null && item.original !== undefined && item.includeOriginal !== true) redactions.push({ path: `evidence/${n}`, action: 'original_excluded', detail: 'Only an original was supplied and it was not requested for release; the item is listed without a file' });
    let path: string | null = null;
    if (chosen !== null) {
      path = `evidence/${n}-${safeName(chosen.file.filename)}`;
      files.push({ path, role: 'evidence', mediaType: chosen.file.mediaType, bytes: chosen.file.bytes, class: chosen.cls, sources: [item.ref], label: item.label, suppliedName: chosen.file.filename, subject: item.ref, ...(chosen.cls === 'original' ? { originalAllowed: chosen.allowed } : {}), ...(item.altText === undefined ? {} : { altText: item.altText }), ...(item.basis === undefined ? {} : { basis: item.basis }) });
    }
    if (item.thumbnail !== undefined) { const t = await h.resolve(item.thumbnail); files.push({ path: `supplied-thumbnails/${n}-${safeName(t.filename)}`, role: 'thumbnail', mediaType: t.mediaType, bytes: t.bytes, class: 'thumbnail', sources: [item.ref], suppliedName: t.filename }); }
    index.push({ item, path, cls: chosen?.cls ?? 'not_included' });
  }
  return { files, index };
}
function evidenceIndexMarkdown(index: readonly { item: EvidenceItem; path: string | null; cls: string }[], clean: readonly DraftComponent[]): string {
  if (index.length === 0) return 'No evidence items are included.\n';
  const rows = index.map(({ item, path, cls }, i) => {
    const c = path === null ? undefined : clean.find((f) => f.path === path);
    const custody = list(item.custody, 'custody', 200);
    const summary = custody.length === 0 ? 'no custody events supplied' : `${custody.length} event(s); first ${e(custody[0]?.at ?? '')} ${e(custody[0]?.action ?? '')}; last ${e(custody.at(-1)?.at ?? '')} ${e(custody.at(-1)?.action ?? '')}`;
    return `| ${i + 1} | ${e(item.label)}${item.description === undefined ? '' : ` — ${e(item.description)}`} | \`${item.ref}\` | ${c === undefined ? 'not included' : `\`${c.path}\` (${cls === 'original' ? 'original' : 'redacted derivative'})`} | ${c === undefined ? '—' : `\`${sha256(c.bytes)}\``} | ${summary} |`;
  });
  return `| # | Item | Reference | Released file | SHA-256 of released file | Custody summary |\n|---|---|---|---|---|---|\n${rows.join('\n')}\n`;
}
const custodyJson = (index: readonly { item: EvidenceItem; path: string | null; cls: string }[], clean: readonly DraftComponent[]): unknown => index.map(({ item, path, cls }) => {
  const c = path === null ? undefined : clean.find((f) => f.path === path);
  return { ref: item.ref, label: item.label, releasedFile: c?.path ?? null, releasedSha256: c === undefined ? null : sha256(c.bytes), released: cls, custody: list(item.custody, 'custody', 200).map((x) => ({ at: text(x.at, 'custody time', 40), actor: text(x.actor, 'custody actor', 200), action: text(x.action, 'custody action', 200), note: x.note ?? null })), rightsDecisionRefs: list(item.rightsDecisionRefs, 'rightsDecisionRefs').map(ref) };
});
const evidenceScan = (items: readonly EvidenceItem[]): Record<string, string> => Object.fromEntries(items.flatMap((it, i) => [[`items[${i}].label`, it.label], [`items[${i}].description`, it.description ?? ''], [`items[${i}].custody`, list(it.custody, 'custody', 200).map((c) => `${c.actor} ${c.action} ${c.note ?? ''}`).join('\n')]]));

// ───────────────────────────── Template engine for jurisdiction-configured documents ─────────────────────────────
function legalDocument(input: { pack: JurisdictionPack; documentType: string; type: PackDocumentType; title: string; pkg: InvestigationPackage | null; values: Readonly<Record<string, string>>; recordsSought: readonly string[]; requester?: Party; recipient?: Party; protectedRefs: readonly string[]; review: ProfessionalReview | null }): { markdown: string; contentDigest: string; extra: Record<string, Json>; sources: string[]; publicSources: string[]; stamp: string } {
  const { pack, type } = input;
  const notes = new SourceNotes(input.protectedRefs);
  const authorities = new Map(pack.authorities.map((a) => [a.id, a]));
  const unresolved: { id: string; reason: string; section: string }[] = []; const used = new Set<string>(); const missingValues = new Set<string>();
  for (const [k, v] of Object.entries(input.values)) { invariant(/^[a-z][a-z0-9_]*$/.test(k), 'invalid_input', 'Invalid value name'); text(v, `value ${k}`); }
  for (const p of list(type.placeholders, 'placeholders')) if (p.required === true && input.values[p.name] === undefined) missingValues.add(p.name);
  const authorityText = (id: string, section: string): string => {
    const a = authorities.get(id);
    if (a === undefined) { unresolved.push({ id, reason: 'not present in the jurisdiction pack', section }); return e(UNRESOLVED_AUTHORITY); }
    used.add(id);
    if (!a.reviewed) { unresolved.push({ id, reason: 'supplied by the deployment but marked unreviewed', section }); return `${e(a.citation)} *(unreviewed authority — to be confirmed by a qualified reviewer)*`; }
    return e(a.citation);
  };
  const facts = (which: string | undefined): string => {
    invariant(input.pkg !== null, 'invalid_input', 'This document type needs an investigation package');
    const statuses: FindingStatus[] = which === undefined || which === 'all' ? ['established', 'disputed', 'unknown'] : [which as FindingStatus];
    invariant(statuses.every((s) => ['established', 'disputed', 'unknown'].includes(s)), 'invalid_config', 'Invalid facts selector in template');
    const fs = input.pkg.findings.filter((f) => statuses.includes(f.status));
    if (fs.length === 0) return '*No findings with this status were supplied.*';
    return fs.map((f, i) => `${i + 1}. (${LABEL[f.status]}) ${e(f.statement)} ${notes.citeAll(f.sources) || '(no source cited)'}`).join('\n');
  };
  const sections = type.sections.map((s) => {
    const body = s.body.replace(TOKEN, (_m, name: string, arg: string | undefined) => {
      if (name === 'var') { const v = arg === undefined ? undefined : input.values[arg]; if (v === undefined) { missingValues.add(arg ?? ''); return e(`[to be completed: ${arg ?? ''}]`); } return e(v); }
      if (name === 'facts') return `\n\n${facts(arg)}\n\n`;
      if (name === 'authority') return authorityText(arg ?? '', s.id);
      if (name === 'authorities') return `\n\n${pack.authorities.length === 0 ? e(UNRESOLVED_AUTHORITY) : pack.authorities.map((a) => `- ${authorityText(a.id, s.id)}`).join('\n')}\n\n`;
      if (name === 'records_sought') return `\n\n${input.recordsSought.length === 0 ? '*No records were specified.*' : input.recordsSought.map((r, i) => `${i + 1}. ${e(r)}`).join('\n')}\n\n`;
      if (name === 'requester') return input.requester === undefined ? e('[to be completed: requester]') : partyLines(input.requester, 'requester');
      return input.recipient === undefined ? e('[to be completed: recipient]') : partyLines(input.recipient, 'recipient');
    });
    return `## ${e(s.heading)}\n\n> @@STAMP@@\n\n${body.trim()}\n`;
  });
  if (pack.authorities.length === 0 && unresolved.length === 0) unresolved.push({ id: '*', reason: 'the jurisdiction pack supplies no authorities', section: '*' });
  const assumptions = [`This draft assumes that jurisdiction pack "${pack.name}" (id ${pack.id}, version ${pack.version}) applies to the matter; that has not been verified.`, ...list(pack.assumptions, 'assumptions'), ...list(type.assumptions, 'assumptions')];
  const uniqueUnresolved = [...new Map(unresolved.map((u) => [`${u.id}|${u.reason}`, u])).values()];
  const body = [
    `# ${e(input.title)}\n\n> @@STAMP@@\n\n*Document type: ${e(type.title)}. Jurisdiction pack: ${e(pack.name)} (version ${pack.version}).*\n`,
    ...sections,
    `## Unresolved authorities\n\n> @@STAMP@@\n\n${uniqueUnresolved.length === 0 ? 'Every authority referenced by this template is present in the jurisdiction pack and marked reviewed by the deployment. That marking is the deployment\'s; this generator has not verified any authority.' : uniqueUnresolved.map((u) => `- ${u.id === '*' ? 'All authorities' : `\`${u.id}\``}: ${u.reason} — ${e(UNRESOLVED_AUTHORITY)}`).join('\n')}\n`,
    `## Jurisdictional assumptions\n\n> @@STAMP@@\n\n${assumptions.map((a) => `- ${e(a)}`).join('\n')}\n`,
    ...(missingValues.size === 0 ? [] : [`## Information still to be completed\n\n> @@STAMP@@\n\n${[...missingValues].sort().map((m) => `- ${e(m)}`).join('\n')}\n`]),
    `## Factual sources\n\n> @@STAMP@@\n\nEvery factual statement above is taken from the supplied investigation findings and cites its sources by number. No fact was added by the generator.\n\n${notes.section().replace('## Sources\n\n', '')}`,
  ].join('\n');
  const contentDigest = sha256(body);
  const r = input.review;
  invariant(r === null || r.contentDigest === contentDigest, 'approval_invalid', 'The recorded professional review is for different content; this exact version has not been reviewed');
  const stamp = r === null ? DRAFT_STAMP : `Generated draft — not legal advice; not filed. Professional review recorded for this exact content (${contentDigest.slice(0, 16)}): ${r.reviewerName}, ${r.reviewerRole}, ${r.reviewedOn}`;
  return {
    markdown: body.replaceAll('@@STAMP@@', `**${e(stamp)}**`), contentDigest, sources: notes.all, publicSources: notes.public, stamp,
    extra: { legal: { jurisdictionPack: { id: pack.id, name: pack.name, version: pack.version, digest: sha256(canonical(JSON.parse(JSON.stringify(pack)))) }, documentType: input.documentType, contentDigest, stamp, filed: false, legalAdvice: false,
      professionalReview: r === null ? null : { id: r.id, reviewerName: r.reviewerName, reviewerRole: r.reviewerRole, reviewedOn: r.reviewedOn },
      unresolved_authorities: uniqueUnresolved, jurisdictional_assumptions: assumptions, authorities_used: [...used].sort().map((id) => ({ id, citation: authorities.get(id)?.citation ?? '', reviewed: authorities.get(id)?.reviewed === true })), unresolved_placeholders: [...missingValues].sort() } },
  };
}
const NEUTRAL_RECORDS_REQUEST: PackDocumentType = { title: 'Records request', sections: [
  { id: 'parties', heading: 'Requester and recipient', body: 'From:\n\n{{requester}}\n\nTo:\n\n{{recipient}}' },
  { id: 'legal_basis', heading: 'Legal basis', body: 'The jurisdiction pack does not configure a records-request template, so no legal basis is stated: {{authority:legal-basis-not-configured}}' },
  { id: 'records', heading: 'Records sought', body: '{{records_sought}}' },
] };

// ───────────────────────────── Builders ─────────────────────────────
export async function buildDraft(input: BuildInput, h: BuildHelpers): Promise<Draft> {
  const protectedRefs = list(input.protectedSourceRefs, 'protectedSourceRefs').map(ref);
  const subjects = list(input.subjects, 'subjects').map(ref);
  const title = text(input.title, 'title', 300);
  const redactions: RedactionAction[] = [];
  const base = { redactions, subjects };
  const visible = (refs: readonly string[]): string[] => refs.filter((r) => !protectedRefs.includes(r));
  switch (input.kind) {
    case 'evidence_bundle': {
      const { files, index } = await evidenceFiles(input.items, h, redactions);
      invariant(index.length > 0, 'invalid_input', 'An evidence bundle needs at least one item');
      const refs = index.map((x) => x.item.ref);
      return { ...base, files, sources: refs, subjects: [...new Set([...subjects, ...refs])], extra: {}, scanFields: { title, note: input.note ?? '', ...evidenceScan(input.items) },
        finish: (clean) => ({ docs: [{ base: 'index', title, role: 'evidence_index', sources: visible(refs), markdown: `# ${e(title)}\n\n*Evidence bundle. Each row gives the SHA-256 of the file actually included in this package; originals are included only where stated.*\n\n${input.note === undefined ? '' : `${e(input.note)}\n\n`}## Evidence index\n\n${evidenceIndexMarkdown(index, clean)}` }], data: [json('custody.json', 'custody_summary', custodyJson(index, clean), visible(refs))] }) };
    }
    case 'investigation_report': case 'chronology': {
      const p = checkPackage(input.package); const notes = new SourceNotes(protectedRefs);
      const md = input.kind === 'investigation_report'
        ? `# ${e(title)}\n\n*Investigation report generated from the supplied investigation package${p.investigationRef === undefined ? '' : ` \`${p.investigationRef}\``}. Each finding is labelled ESTABLISHED, DISPUTED or UNKNOWN and cites its exact sources.*\n\n${p.summary === undefined ? '' : `## Summary\n\n${e(p.summary)}\n\n`}## Findings\n\n${findingsMarkdown(p, notes, ['established', 'disputed', 'unknown'])}\n## Chronology\n\n${chronologyRows(p, notes)}\n## Open questions\n\n${list(p.openQuestions, 'openQuestions').length === 0 ? 'None recorded.' : list(p.openQuestions, 'openQuestions').map((q) => `- **${e(q.id)}** ${e(q.question)}`).join('\n')}\n\n${p.methodology === undefined ? '' : `## Methodology\n\n${e(p.methodology)}\n\n`}## Limitations\n\n${list(p.limitations, 'limitations').length === 0 ? 'No general limitations were recorded in the package.' : list(p.limitations, 'limitations').map((l) => `- ${e(l)}`).join('\n')}\n\n${notes.section()}`
        : `# ${e(title)}\n\n*Factual chronology generated from the supplied investigation package. Each entry is labelled ESTABLISHED, DISPUTED or UNKNOWN and cites its sources.*\n\n${chronologyRows(p, notes)}\n${notes.section()}`;
      const sources = [...new Set([...notes.all, ...packageRefs(p)])];
      const dataPath = input.kind === 'investigation_report' ? 'findings.json' : 'chronology.json';
      const data = input.kind === 'investigation_report'
        ? p.findings.map((f) => ({ id: f.id, status: f.status, statement: f.statement, sources: list(f.sources, 'sources').filter((s) => !protectedRefs.includes(s.ref)), protectedSourceCount: list(f.sources, 'sources').filter((s) => protectedRefs.includes(s.ref)).length, limitations: f.limitations ?? [] }))
        : list(p.chronology, 'chronology').map((c) => ({ date: c.date, event: c.event, status: c.status, findingIds: c.findingIds ?? [], sources: list(c.sources, 'sources').filter((s) => !protectedRefs.includes(s.ref)) }));
      return { ...base, files: [], sources, extra: { basisLabels: { established: p.findings.filter((f) => f.status === 'established').length, disputed: p.findings.filter((f) => f.status === 'disputed').length, unknown: p.findings.filter((f) => f.status === 'unknown').length } }, scanFields: { title },
        finish: () => ({ docs: [{ base: input.kind === 'investigation_report' ? 'report' : 'chronology', title, role: input.kind, sources: visible(sources), markdown: md }], data: [json(dataPath, 'structured_data', data, visible(sources))] }) };
    }
    case 'referral_package': {
      const p = checkPackage(input.package); const notes = new SourceNotes(protectedRefs);
      const { files, index } = await evidenceFiles(input.items ?? [], h, redactions);
      const chron = `# ${e(title)} — chronology\n\n${chronologyRows(p, notes)}\n## Findings\n\n${findingsMarkdown(p, notes, ['established', 'disputed', 'unknown'])}\n${notes.section()}`;
      const refs = index.map((x) => x.item.ref);
      const sources = [...new Set([...notes.all, ...packageRefs(p), ...refs])];
      const cover = `# ${e(title)}\n\n*Referral package prepared for the recipient named below. It is a summary of sourced findings for the recipient's own assessment; it is not a determination of wrongdoing.*\n\n## Recipient\n\n${partyLines(input.recipient, 'recipient')}\n\n## Summary\n\n${e(text(input.coverSummary, 'coverSummary', 8000))}\n\n## Contents\n\n- Chronology and findings (\`chronology\`)\n- Evidence index (\`evidence-index\`) with ${index.length} item(s)\n\n## Contact for follow-up\n\n${partyLines(input.contact, 'contact')}\n`;
      return { ...base, files, sources, subjects: [...new Set([...subjects, ...refs])], extra: { recipient: { name: input.recipient.name, organization: input.recipient.organization ?? null } }, scanFields: { title, coverSummary: input.coverSummary, ...partyFields(input.recipient, 'recipient'), ...partyFields(input.contact, 'contact'), ...evidenceScan(input.items ?? []) },
        finish: (clean) => ({ docs: [
          { base: 'cover', title, role: 'cover_summary', sources: [], markdown: cover },
          { base: 'chronology', title: `${title} — chronology`, role: 'chronology', sources: visible([...notes.all, ...packageRefs(p)]), markdown: chron },
          { base: 'evidence-index', title: `${title} — evidence index`, role: 'evidence_index', sources: visible(refs), markdown: `# ${e(title)} — evidence index\n\n${evidenceIndexMarkdown(index, clean)}` },
        ], data: [json('custody.json', 'custody_summary', custodyJson(index, clean), visible(refs))] }) };
    }
    case 'records_request': case 'legal_draft': {
      const pack = h.pack(text(input.jurisdictionPackId, 'jurisdictionPackId', 80));
      const documentType = input.kind === 'records_request' ? 'records_request' : text(input.documentType, 'documentType', 80);
      const type = pack.documentTypes[documentType] ?? (input.kind === 'records_request' ? NEUTRAL_RECORDS_REQUEST : undefined);
      invariant(type !== undefined && Object.hasOwn(pack.documentTypes, documentType) === (type !== NEUTRAL_RECORDS_REQUEST), 'invalid_input', 'Document type is not configured in the jurisdiction pack');
      const pkg = input.package === undefined ? null : checkPackage(input.package);
      const recordsSought = input.kind === 'records_request' ? [...list(input.recordsSought, 'recordsSought', 200).map((r) => text(r, 'record sought')), ...list(pkg?.openQuestions, 'openQuestions').map((q) => q.recordsSought ?? `Records that answer: ${q.question}`)] : [];
      invariant(input.kind !== 'records_request' || recordsSought.length > 0, 'invalid_input', 'A records request needs records sought or open questions');
      const review = input.professionalReviewId === undefined ? null : await h.review(input.professionalReviewId);
      const doc = legalDocument({ pack, documentType, type, title, pkg, values: input.values ?? {}, recordsSought, protectedRefs, review, ...(input.kind === 'records_request' ? { requester: input.requester, recipient: input.recipient } : {}) });
      const sources = [...new Set([...doc.sources, ...(pkg === null ? [] : packageRefs(pkg))])];
      return { ...base, files: [], sources, extra: doc.extra, scanFields: { title, ...Object.fromEntries(Object.entries(input.values ?? {}).map(([k, v]) => [`values.${k}`, v])), ...(input.kind === 'records_request' ? { ...partyFields(input.requester, 'requester'), ...partyFields(input.recipient, 'recipient') } : {}) },
        finish: () => ({ docs: [{ base: input.kind === 'records_request' ? 'records-request' : 'draft', title, role: input.kind, sources: visible(sources), markdown: doc.markdown }], data: [json('legal-status.json', 'legal_status', doc.extra.legal, [])] }) };
    }
    case 'source_companion': {
      const srcs = list(input.sources, 'sources', 2000);
      invariant(srcs.length > 0, 'invalid_input', 'A source companion needs at least one source');
      let hidden = 0;
      const entries = srcs.map((s) => {
        ref(s.ref);
        const supports = list(s.supports, 'supports', 200).map((x) => text(x, 'supports'));
        invariant(supports.length > 0, 'invalid_input', 'Each source must state what it supports');
        const isProtected = s.protected === true || protectedRefs.includes(s.ref);
        if (isProtected) { hidden++; return { label: s.publicLabel === undefined ? `Protected source ${hidden}` : text(s.publicLabel, 'publicLabel', 200), protected: true, supports }; }
        if (s.url !== undefined) invariant(/^https?:\/\/[^\s<>"']{1,2000}$/.test(s.url), 'invalid_input', 'Source URL must be http(s)');
        return { label: s.title ?? s.ref, protected: false, ref: s.ref, publisher: s.publisher ?? null, date: s.date ?? null, url: s.url ?? null, supports };
      });
      const all = srcs.map((s) => s.ref);
      const pub = srcs.filter((s) => !(s.protected === true || protectedRefs.includes(s.ref))).map((s) => s.ref);
      const md = `# ${e(title)}\n\n*Source companion: the sources relied on and what each one supports. Sources whose identity is protected are listed without identifying detail.*\n\n${input.introduction === undefined ? '' : `${e(input.introduction)}\n\n`}${entries.map((s, i) => `## ${i + 1}. ${e(s.label)}\n\n${s.protected ? '*Identity withheld to protect the source.*' : [`Reference: \`${s.ref}\``, s.publisher == null ? '' : `Publisher: ${e(s.publisher)}`, s.date == null ? '' : `Date: ${e(s.date)}`, s.url == null ? '' : `Location: ${e(s.url)}`].filter((x) => x !== '').join('  \n')}\n\nSupports:\n\n${s.supports.map((x) => `- ${e(x)}`).join('\n')}\n`).join('\n')}`;
      return { ...base, files: [], sources: all, extra: { protectedSourceCount: hidden }, scanFields: { title, introduction: input.introduction ?? '' },
        finish: () => ({ docs: [{ base: 'sources', title, role: 'source_companion', sources: pub, markdown: md }], data: [json('sources.json', 'structured_data', entries, pub)] }) };
    }
    case 'media_package': {
      const renders = list(input.renders, 'renders', 200);
      invariant(renders.length > 0, 'invalid_input', 'A media package needs at least one render');
      const files: DraftComponent[] = []; const rows: { n: string; label: string; ref: string; path: string; captions: string[]; alt: string }[] = [];
      for (const [i, r] of renders.entries()) {
        ref(r.ref); text(r.label, 'render label', 300);
        const n = String(i + 1).padStart(3, '0');
        const f = await h.resolve(r.file);
        const srcs = [r.ref, ...list(r.sources, 'sources').map(ref)];
        const path = `media/${n}-${safeName(f.filename)}`;
        files.push({ path, role: 'render', mediaType: f.mediaType, bytes: f.bytes, class: 'render', sources: srcs, label: r.label, suppliedName: f.filename, subject: r.ref, ...(r.altText === undefined ? {} : { altText: r.altText }) });
        if (r.thumbnail !== undefined) { const t = await h.resolve(r.thumbnail); files.push({ path: `supplied-thumbnails/${n}-${safeName(t.filename)}`, role: 'thumbnail', mediaType: t.mediaType, bytes: t.bytes, class: 'thumbnail', sources: [r.ref], suppliedName: t.filename }); }
        if (r.manifest !== undefined) files.push(json(`render-manifests/${n}.json`, 'render_manifest', r.manifest, srcs));
        const caps: string[] = [];
        for (const c of list(r.captions, 'captions', 50)) {
          invariant(/^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$/.test(c.language) && (c.format === 'vtt' || c.format === 'srt'), 'invalid_input', 'Captions need a language tag and vtt or srt format');
          const cp = `captions/${n}.${c.language}.${c.format}`;
          files.push({ path: cp, role: 'captions', mediaType: c.format === 'vtt' ? 'text/vtt' : 'application/x-subrip', bytes: utf8(text(c.text, 'caption text', 2_000_000)), class: 'caption', sources: srcs }); caps.push(cp);
        }
        rows.push({ n, label: r.label, ref: r.ref, path, captions: caps, alt: r.altText ?? '' });
      }
      const credits = list(input.credits, 'credits', 500).map((c) => ({ role: text(c.role, 'credit role', 200), name: text(c.name, 'credit name', 300) }));
      const disclosures = list(input.disclosures, 'disclosures', 100).map((d) => text(d, 'disclosure'));
      const rights = list(input.rightsSummary, 'rightsSummary', 500).map((r) => ({ subject: ref(r.subject), holder: r.holder ?? null, license: r.license ?? null, terms: r.terms ?? null, decisionRef: r.decisionRef === undefined ? null : ref(r.decisionRef) }));
      const sources = [...new Set(files.flatMap((f) => f.sources))];
      return { ...base, files, sources, subjects: [...new Set([...subjects, ...renders.map((r) => r.ref), ...rights.map((r) => r.subject)])], extra: { credits, disclosures, rightsSummary: rights }, scanFields: { title, credits: credits.map((c) => `${c.role}: ${c.name}`).join('\n'), disclosures: disclosures.join('\n'), rights: rights.map((r) => `${r.holder ?? ''} ${r.license ?? ''} ${r.terms ?? ''}`).join('\n') },
        finish: (clean) => ({ docs: [{ base: 'index', title, role: 'media_index', sources: visible(sources), markdown: `# ${e(title)}\n\n## Media\n\n| # | Title | Render | File | SHA-256 | Captions | Alternative text |\n|---|---|---|---|---|---|---|\n${rows.map((r) => { const c = clean.find((f) => f.path === r.path); return `| ${r.n} | ${e(r.label)} | \`${r.ref}\` | ${c === undefined ? 'not included' : `\`${r.path}\``} | ${c === undefined ? '—' : `\`${sha256(c.bytes)}\``} | ${r.captions.length === 0 ? 'none supplied' : r.captions.map((x) => `\`${x}\``).join(' ')} | ${r.alt === '' ? 'none supplied' : e(r.alt)} |`; }).join('\n')}\n\n## Credits\n\n${credits.length === 0 ? 'No credits were supplied.' : credits.map((c) => `- ${e(c.role)}: ${e(c.name)}`).join('\n')}\n\n## Disclosures\n\n${disclosures.length === 0 ? 'No disclosures were supplied.' : disclosures.map((d) => `- ${e(d)}`).join('\n')}\n\n## Rights summary\n\n${rights.length === 0 ? 'No rights summary was supplied.' : rights.map((r) => `- \`${r.subject}\`: ${[r.holder, r.license, r.terms].filter((x): x is string => x !== null).map((x) => e(x)).join('; ') || 'no terms stated'}${r.decisionRef === null ? '' : ` (decision \`${r.decisionRef}\`)`}`).join('\n')}\n` }],
          data: [json('rights-summary.json', 'rights_summary', rights, []), json('credits.json', 'credits', { credits, disclosures }, [])] }) };
    }
    default: throw new DomainError("invalid_input", "Unknown package kind");
  }
}
