// E12 Packaging, Release and Correction — service layer.
// Candidates are immutable and content-addressed; approvals bind an exact candidate digest to one audience and one
// destination; nothing is released without a valid human approval, and nothing public without a recorded human
// accountability decision. No timer, job or agent can cause a release.
import { createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { canonical, digest, DomainError, invariant } from '../contracts.ts';
import type { Json } from '../contracts.ts';
import {
  appendAudit, emitEvent, enqueueJob, idempotent, listAudit, parseUref, readEvents, requireCapability, requireCompartment, runJobsOnce,
  runMigrations, standardRoutes, uref, urefMatches, SERVICE_KIT_VERSION,
} from '../service-kit.ts';
import type {
  AuditRecord, AuthorizationPort, EngineEvent, EngineManifestV1, EvidencePort, Inspection, Migration, ObjectStore, Route, SearchHit,
  ServiceContext, Sql, StandardEngine, UpstreamChange, UseAction, UseDecision, UseDecisionPort,
} from '../service-kit.ts';
import { buildDraft, PACKAGE_KINDS, validatePack } from './builders.ts';
import type { BuildInput, FileInput, JurisdictionPack, PackageKind, ProfessionalReview, ResolvedFile } from './builders.ts';
import { deliver, DESTINATION_KINDS, probe, unpublish, validateDestinationConfig } from './destinations.ts';
import type { DeliveryPayload, DeliveryResult, DestinationKind, DestinationRuntime } from './destinations.ts';
import { findingsJson, ProtectedTerms, sanitize, verifyStored } from './leak.ts';
import type { DraftComponent, Finding } from './leak.ts';
import { renderDocument, sha256, toolVersion, utf8, zipWrite } from './tools.ts';

export * from './builders.ts';
export type { DestinationKind, DestinationRuntime } from './destinations.ts';
export { ProtectedTerms } from './leak.ts';
export type { Finding } from './leak.ts';
export { zipRead, zipWrite } from './tools.ts';

export const SCHEMA = 'e12_release';
export const manifest: EngineManifestV1 = {
  id: 'E12', name: 'Packaging, Release and Correction', version: '1.0.0', kit: SERVICE_KIT_VERSION,
  capabilities: ['release:read', 'release:write', 'release:review', 'release:participant_review', 'release:legal_review', 'release:approve', 'release:publish', 'release:export', 'release:withdraw', 'release:admin', 'release:events', 'release:upstream'],
  emits: ['release.candidate_built', 'release.candidate_blocked', 'release.review_submitted', 'release.changes_requested', 'release.reviewed', 'release.accountability_decided', 'release.professional_review_recorded', 'release.approved', 'release.approval_invalidated', 'release.candidate_stale', 'release.released', 'release.delivery_uncertain', 'release.delivery_failed', 'release.distribution_needs_follow_up', 'release.follow_up_updated', 'release.correction_issued', 'release.superseded', 'release.withdrawal_requested', 'release.withdrawal_updated', 'release.destination_changed'],
  consumes: ['content_changed', 'render_changed', 'claim_changed', 'source_corrected', 'source_superseded', 'source_removed', 'permission_withdrawn', 'permission_changed', 'rights_changed', 'audience_changed'],
};

export const migrations: readonly Migration[] = [{ id: '001_release', sql: `
create table {s}.candidates (
  id uuid primary key, tenant_id text not null, project_id text not null,
  lineage_id uuid not null, version int not null, kind text not null, title text not null,
  audience text not null, audience_class text not null check (audience_class in ('private','restricted','public')),
  state text not null check (state in ('built','leak_blocked','in_review','changes_requested','reviewed','superseded','withdrawn')),
  digest text, manifest jsonb, compartment text,
  sources text[] not null default '{}', subjects text[] not null default '{}',
  stale boolean not null default false, blocked boolean not null default false, stale_reasons jsonb not null default '[]',
  supersedes uuid, superseded_by uuid,
  term_salt text not null, term_hashes text[] not null default '{}',
  leak_report jsonb not null, index_text text not null default '',
  zip_key text, zip_sha256 text, zip_size bigint, review jsonb not null default '{}',
  created_by text not null, created_at timestamptz not null,
  unique (tenant_id, project_id, lineage_id, version),
  check (state = 'leak_blocked' or (digest is not null and manifest is not null and zip_key is not null))
);
create index candidates_scope on {s}.candidates (tenant_id, project_id, created_at);
create table {s}.components (
  tenant_id text not null, project_id text not null, candidate_id uuid not null references {s}.candidates(id),
  path text not null, role text not null, class text not null, media_type text not null, sha256 text not null, size bigint not null,
  object_key text not null, sources text[] not null default '{}', label text, alt_text text,
  primary key (candidate_id, path)
);
create table {s}.review_events (
  id uuid primary key, tenant_id text not null, project_id text not null, candidate_id uuid not null references {s}.candidates(id),
  candidate_digest text not null, kind text not null check (kind in ('submitted','comment','changes_requested','reviewer_accepted','participant_accepted','participant_objected')),
  actor_id text not null, actor_kind text not null, body text not null default '', component_path text, at timestamptz not null
);
create index review_events_candidate on {s}.review_events (candidate_id, at);
create table {s}.accountability_decisions (
  id uuid primary key, tenant_id text not null, project_id text not null, candidate_id uuid not null references {s}.candidates(id),
  candidate_digest text not null, outcome text not null check (outcome in ('public_scrutiny_appropriate','not_appropriate')),
  assessment text not null check (length(btrim(assessment)) > 0), legal_routes jsonb not null, no_legal_route_reason text, policy text not null,
  decided_by text not null, decided_by_kind text not null check (decided_by_kind = 'human'), decided_at timestamptz not null
);
create table {s}.professional_reviews (
  id uuid primary key, tenant_id text not null, project_id text not null, candidate_id uuid not null references {s}.candidates(id),
  candidate_digest text not null, content_digest text not null, reviewer_name text not null, reviewer_role text not null, reviewed_on text not null,
  statement text, recorded_by text not null, recorded_by_kind text not null check (recorded_by_kind = 'human'), recorded_at timestamptz not null
);
create table {s}.destinations (
  id uuid primary key, tenant_id text not null, project_id text not null, name text not null, kind text not null,
  public boolean not null, licensed boolean not null default false, audiences text[] not null, config jsonb not null, revision int not null default 1,
  enabled boolean not null default true, updated_by text not null, updated_at timestamptz not null,
  unique (tenant_id, project_id, name), check (kind <> 'public_web' or public)
);
create table {s}.approvals (
  id uuid primary key, tenant_id text not null, project_id text not null, candidate_id uuid not null references {s}.candidates(id),
  candidate_digest text not null, audience text not null, destination_id uuid not null references {s}.destinations(id), destination_revision int not null,
  public boolean not null, rights jsonb not null, rights_digest text not null, permission_refs text[] not null default '{}', notices_digest text not null,
  accountability_decision_id uuid references {s}.accountability_decisions(id),
  approved_by text not null, approved_by_kind text not null check (approved_by_kind = 'human'), approved_at timestamptz not null, expires_at timestamptz not null,
  state text not null default 'valid' check (state in ('valid','invalid','used')), invalid_reason text,
  check (not public or accountability_decision_id is not null)
);
create index approvals_candidate on {s}.approvals (candidate_id);
create table {s}.releases (
  id uuid primary key, tenant_id text not null, project_id text not null, candidate_id uuid not null references {s}.candidates(id),
  candidate_digest text not null, approval_id uuid not null unique references {s}.approvals(id), destination_id uuid not null references {s}.destinations(id),
  audience text not null, public boolean not null, accountability_decision_id uuid references {s}.accountability_decisions(id),
  state text not null check (state in ('dispatching','delivered','failed','uncertain')), attempts int not null default 1,
  adapter_response jsonb, receipt jsonb, recipients jsonb not null default '[]', use_register jsonb,
  released_by text not null, released_by_kind text not null check (released_by_kind in ('human','service','agent')), started_at timestamptz not null, completed_at timestamptz,
  check (not public or (accountability_decision_id is not null and released_by_kind <> 'agent'))
);
create table {s}.distributions (
  id uuid primary key, tenant_id text not null, project_id text not null, release_id uuid not null references {s}.releases(id),
  candidate_id uuid not null, lineage_id uuid not null, destination_id uuid not null, recipient text not null,
  kind text not null check (kind in ('primary','downstream_copy')), parent_id uuid,
  state text not null check (state in ('delivered','uncertain','not_delivered','needs_follow_up','follow_up_done','withdrawn')),
  follow_up_status text not null default 'none', follow_up_reasons jsonb not null default '[]', history jsonb not null default '[]', created_at timestamptz not null
);
create index distributions_candidate on {s}.distributions (candidate_id);
create table {s}.corrections (
  id uuid primary key, tenant_id text not null, project_id text not null, lineage_id uuid not null,
  prior_candidate_id uuid not null references {s}.candidates(id), corrected_candidate_id uuid not null references {s}.candidates(id),
  corrected_version int not null, reason text not null, notice_text text not null, issued_by text not null, issued_at timestamptz not null,
  unique (prior_candidate_id)
);
create table {s}.withdrawals (
  id uuid primary key, tenant_id text not null, project_id text not null, candidate_id uuid not null references {s}.candidates(id),
  reason text not null, state text not null check (state in ('requested','in_progress','completed','partially_completed','not_possible')),
  history jsonb not null default '[]', requested_by text not null, requested_at timestamptz not null
);
create table {s}.download_links (
  id uuid primary key, tenant_id text not null, project_id text not null, release_id uuid not null, candidate_id uuid not null,
  expires_at timestamptz not null, revoked boolean not null default false, downloads int not null default 0
);
create table {s}.upstream_changes (
  tenant_id text not null, project_id text not null, event_id text not null, affected jsonb not null, at timestamptz not null,
  primary key (tenant_id, project_id, event_id)
);` }];
export function migrate(sql: Sql): Promise<string[]> { return runMigrations(sql, SCHEMA, migrations); }

// ───────────────────────────── Types ─────────────────────────────
export type AudienceClass = 'private' | 'restricted' | 'public';
export type AudiencePolicy = Readonly<{ class: AudienceClass; allowOriginals?: boolean }>;
export interface ProtectedTermsPort {
  /** Returns protected identity strings relevant to these refs. Terms are used in memory only and never stored. */
  termsFor(ctx: ServiceContext, request: { subjects: readonly string[]; sources: readonly string[] }): Promise<readonly string[]>;
}
export interface UseRegisterPort {
  /** E11 use register: lets a later withdrawal identify where a permission was relied on. */
  recordUse(ctx: ServiceContext, input: { decisionRef: string; subjects: readonly string[]; output: string; action: UseAction; audience?: string; destination?: string; idempotencyKey?: string }): Promise<unknown>;
}
export type ReleaseConfig = Readonly<{
  audiences?: Readonly<Record<string, AudiencePolicy>>;
  /** `legal_first` (default): a public release needs a human decision that assessed the legal-accountability route. */
  accountabilityPolicy?: 'legal_first' | 'human_decision';
  jurisdictionPacks?: readonly JurisdictionPack[];
  destinations?: DestinationRuntime;
  /** Without a UseDecisionPort the engine denies approval of anything with rights subjects unless this is set. */
  standaloneRights?: 'deny' | 'allow_without_port';
  professionalReviewCapability?: string;
  participantReviewRestriction?: string;
  maxApprovalSeconds?: number;
  maxFileBytes?: number;
}>;
export type ReleaseDeps = Readonly<{
  sql: Sql; objects?: ObjectStore;
  ports?: Readonly<{ useDecision?: UseDecisionPort; useRegister?: UseRegisterPort; authorization?: AuthorizationPort; evidence?: EvidencePort; protectedTerms?: ProtectedTermsPort }>;
  config?: ReleaseConfig;
}>;
export const DEFAULT_AUDIENCES: Readonly<Record<string, AudiencePolicy>> = {
  internal_review: { class: 'private' }, legal_counsel: { class: 'restricted' }, authority_referral: { class: 'restricted' },
  records_holder: { class: 'restricted' }, licensed_partner: { class: 'restricted' }, public: { class: 'public' },
};
export type ComponentView = Readonly<{ path: string; role: string; class: string; mediaType: string; sha256: string; size: number }>;
export type CandidateView = Readonly<{
  ref: string; id: string; lineageId: string; version: number; kind: PackageKind; title: string; audience: string; audienceClass: AudienceClass;
  state: 'built' | 'leak_blocked' | 'in_review' | 'changes_requested' | 'reviewed' | 'superseded' | 'withdrawn';
  digest: string | null; stale: boolean; blocked: boolean; staleReasons: Json[]; supersedes: string | null; supersededBy: string | null;
  components: ComponentView[]; leakReport: Json; review: Json; zipSha256: string | null; zipSize: number | null; createdBy: string; createdAt: string;
}>;
export type RightsSnapshot = Readonly<{ action: UseAction; decision: string; permissionRefs: string[]; restrictions: string[]; decisionRef: string | null; evaluated: boolean }>;
export type ApprovalView = Readonly<{ ref: string; id: string; candidateId: string; candidateDigest: string; audience: string; destinationId: string; destinationRevision: number; public: boolean; rights: RightsSnapshot[]; accountabilityDecisionId: string | null; approvedBy: string; approvedAt: string; expiresAt: string; state: 'valid' | 'invalid' | 'used'; invalidReason: string | null }>;
export type DestinationView = Readonly<{ ref: string; id: string; name: string; kind: DestinationKind; public: boolean; licensed: boolean; audiences: string[]; config: Json; revision: number; enabled: boolean }>;
export type ReleaseView = Readonly<{ ref: string; id: string; candidateId: string; candidateDigest: string; approvalId: string; destinationId: string; audience: string; public: boolean; state: 'dispatching' | 'delivered' | 'failed' | 'uncertain'; attempts: number; adapterResponse: Json; receipt: Json; replayed: boolean; releasedBy: string; startedAt: string; completedAt: string | null }>;
export type DistributionView = Readonly<{ ref: string; id: string; releaseId: string; candidateId: string; lineageId: string; destinationId: string; recipient: string; kind: 'primary' | 'downstream_copy'; state: string; followUpStatus: string; followUpReasons: Json[]; history: Json[]; createdAt: string }>;
export type CorrectionView = Readonly<{ ref: string; id: string; priorCandidateId: string; correctedCandidateId: string; reason: string; noticeText: string; issuedBy: string; issuedAt: string; followUps: DistributionView[] }>;
export type WithdrawalView = Readonly<{ ref: string; id: string; candidateId: string; reason: string; state: string; history: Json[]; requestedBy: string; requestedAt: string }>;
export type AccountabilityDecisionView = Readonly<{ ref: string; id: string; candidateId: string; candidateDigest: string; outcome: string; assessment: string; legalRoutesConsidered: Json[]; noLegalRouteReason: string | null; policy: string; decidedBy: string; decidedAt: string }>;
export type ReviewEventView = Readonly<{ id: string; kind: string; actorId: string; body: string; componentPath: string | null; candidateDigest: string; at: string }>;

type R = Record<string, unknown>;
const iso = (v: unknown): string => new Date(v as string | Date).toISOString();
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const id = (v: unknown): string => { if (typeof v !== 'string' || !UUID.test(v)) throw new DomainError('not_found', 'Not found'); return v; };
const str = (v: unknown, label: string, max = 4000): string => { invariant(typeof v === 'string' && v.trim() !== '' && v.length <= max, 'invalid_input', `${label} is required (at most ${max} characters)`); return v; };
const human = (ctx: ServiceContext, what: string): void => { if (ctx.actor.kind !== 'human') throw new DomainError('forbidden', `${what} requires an authenticated human; agents and services cannot hold this role`); };
const asJson = (v: unknown): Json => JSON.parse(JSON.stringify(v ?? null)) as Json;

const toComponent = (r: R): ComponentView => ({ path: r.path as string, role: r.role as string, class: r.class as string, mediaType: r.media_type as string, sha256: r.sha256 as string, size: Number(r.size) });
const toCandidate = (r: R, components: readonly R[]): CandidateView => ({
  ref: uref('E12', 'candidate', r.id as string, r.version as number), id: r.id as string, lineageId: r.lineage_id as string, version: r.version as number, kind: r.kind as PackageKind, title: r.title as string,
  audience: r.audience as string, audienceClass: r.audience_class as AudienceClass, state: r.state as CandidateView['state'], digest: (r.digest as string | null) ?? null,
  stale: r.stale as boolean, blocked: r.blocked as boolean, staleReasons: r.stale_reasons as Json[], supersedes: (r.supersedes as string | null) ?? null, supersededBy: (r.superseded_by as string | null) ?? null,
  components: components.map(toComponent), leakReport: r.leak_report as Json, review: r.review as Json, zipSha256: (r.zip_sha256 as string | null) ?? null, zipSize: r.zip_size == null ? null : Number(r.zip_size), createdBy: r.created_by as string, createdAt: iso(r.created_at),
});
const toApproval = (r: R): ApprovalView => ({ ref: uref('E12', 'approval', r.id as string), id: r.id as string, candidateId: r.candidate_id as string, candidateDigest: r.candidate_digest as string, audience: r.audience as string, destinationId: r.destination_id as string, destinationRevision: r.destination_revision as number, public: r.public as boolean, rights: r.rights as RightsSnapshot[], accountabilityDecisionId: (r.accountability_decision_id as string | null) ?? null, approvedBy: r.approved_by as string, approvedAt: iso(r.approved_at), expiresAt: iso(r.expires_at), state: r.state as ApprovalView['state'], invalidReason: (r.invalid_reason as string | null) ?? null });
const toDestination = (r: R): DestinationView => ({ ref: uref('E12', 'destination', r.id as string, r.revision as number), id: r.id as string, name: r.name as string, kind: r.kind as DestinationKind, public: r.public as boolean, licensed: r.licensed as boolean, audiences: r.audiences as string[], config: r.config as Json, revision: r.revision as number, enabled: r.enabled as boolean });
const toRelease = (r: R, replayed = false): ReleaseView => ({ ref: uref('E12', 'release', r.id as string), id: r.id as string, candidateId: r.candidate_id as string, candidateDigest: r.candidate_digest as string, approvalId: r.approval_id as string, destinationId: r.destination_id as string, audience: r.audience as string, public: r.public as boolean, state: r.state as ReleaseView['state'], attempts: r.attempts as number, adapterResponse: (r.adapter_response as Json) ?? null, receipt: (r.receipt as Json) ?? null, replayed, releasedBy: r.released_by as string, startedAt: iso(r.started_at), completedAt: r.completed_at == null ? null : iso(r.completed_at) });
const toDistribution = (r: R): DistributionView => ({ ref: uref('E12', 'distribution', r.id as string), id: r.id as string, releaseId: r.release_id as string, candidateId: r.candidate_id as string, lineageId: r.lineage_id as string, destinationId: r.destination_id as string, recipient: r.recipient as string, kind: r.kind as DistributionView['kind'], state: r.state as string, followUpStatus: r.follow_up_status as string, followUpReasons: r.follow_up_reasons as Json[], history: r.history as Json[], createdAt: iso(r.created_at) });
const toWithdrawal = (r: R): WithdrawalView => ({ ref: uref('E12', 'withdrawal', r.id as string), id: r.id as string, candidateId: r.candidate_id as string, reason: r.reason as string, state: r.state as string, history: r.history as Json[], requestedBy: r.requested_by as string, requestedAt: iso(r.requested_at) });
const toDecision = (r: R): AccountabilityDecisionView => ({ ref: uref('E12', 'accountability_decision', r.id as string), id: r.id as string, candidateId: r.candidate_id as string, candidateDigest: r.candidate_digest as string, outcome: r.outcome as string, assessment: r.assessment as string, legalRoutesConsidered: r.legal_routes as Json[], noLegalRouteReason: (r.no_legal_route_reason as string | null) ?? null, policy: r.policy as string, decidedBy: r.decided_by as string, decidedAt: iso(r.decided_at) });

export type ReleaseEngine = ReturnType<typeof createEngine>;

export function createEngine(deps: ReleaseDeps) {
  const { sql } = deps; const S = SCHEMA; const ports = deps.ports ?? {}; const config = deps.config ?? {};
  const audiences = config.audiences ?? DEFAULT_AUDIENCES;
  const packs = new Map((config.jurisdictionPacks ?? []).map((p) => { const v = validatePack(p); return [v.id, v] as const; }));
  const rt: DestinationRuntime = config.destinations ?? {};
  const policy = config.accountabilityPolicy ?? 'legal_first';
  const reviewCap = config.professionalReviewCapability ?? 'release:legal_review';
  const participantRestriction = config.participantReviewRestriction ?? 'participant_review';
  const maxFile = config.maxFileBytes ?? 256 * 1024 * 1024;
  const store = (): ObjectStore => { if (deps.objects === undefined) throw new DomainError('unavailable', 'Object storage is not configured'); return deps.objects; };
  const sc = (ctx: ServiceContext): [string, string] => [ctx.tenantId, ctx.projectId];

  async function candidateRow(q: Sql, ctx: ServiceContext, candidateId: unknown, lock = false): Promise<R> {
    const r = (await q.query(`select * from ${S}.candidates where id=$1 and tenant_id=$2 and project_id=$3${lock ? ' for update' : ''}`, [id(candidateId), ...sc(ctx)]))[0];
    if (r === undefined) throw new DomainError('not_found', 'Not found');
    requireCompartment(ctx, r.compartment as string | null);
    return r;
  }
  const componentRows = (q: Sql, candidateId: string): Promise<R[]> => q.query(`select * from ${S}.components where candidate_id=$1 order by path`, [candidateId]);
  async function view(q: Sql, ctx: ServiceContext, candidateId: unknown): Promise<CandidateView> { const r = await candidateRow(q, ctx, candidateId); return toCandidate(r, await componentRows(q, r.id as string)); }
  async function destinationRow(q: Sql, ctx: ServiceContext, destinationId: unknown): Promise<R> {
    const r = (await q.query(`select * from ${S}.destinations where id=$1 and tenant_id=$2 and project_id=$3`, [id(destinationId), ...sc(ctx)]))[0];
    if (r === undefined) throw new DomainError('not_found', 'Not found');
    return r;
  }
  async function authorize(ctx: ServiceContext, capability: string, resource: string): Promise<void> {
    if (ports.authorization === undefined) return;
    const d = await ports.authorization.authorize(ctx, { capability, resource });
    if (d.allowed !== true) throw new DomainError('forbidden', `Not authorized for ${capability}`);
  }
  async function terms(ctx: ServiceContext, supplied: readonly string[] | undefined, row: { subjects: readonly string[]; sources: readonly string[] }): Promise<ProtectedTerms> {
    invariant(supplied === undefined || (Array.isArray(supplied) && supplied.length <= 5000), 'invalid_input', 'Invalid protected terms');
    const fromPort = ports.protectedTerms === undefined ? [] : await ports.protectedTerms.termsFor(ctx, { subjects: row.subjects, sources: row.sources });
    return new ProtectedTerms([...(supplied ?? []), ...fromPort]);
  }
  /** Marks approvals invalid and emits one event each. Never deletes. */
  async function invalidateApprovals(tx: Sql, ctx: ServiceContext, where: string, params: unknown[], reason: string, cause: string | null): Promise<string[]> {
    const rows = await tx.query(`update ${S}.approvals set state='invalid', invalid_reason=$1 where tenant_id=$2 and project_id=$3 and state='valid' and ${where} returning id, candidate_id`, [reason, ...sc(ctx), ...params]);
    const out: string[] = [];
    for (const r of rows) {
      const ref = uref('E12', 'approval', r.id as string); out.push(ref);
      await emitEvent(tx, S, ctx, 'release.approval_invalidated', ref, { reason, cause, candidate: uref('E12', 'candidate', r.candidate_id as string) });
      await appendAudit(tx, S, ctx, 'approval.invalidated', ref, { reason, cause });
    }
    return out;
  }
  async function flagDistributions(tx: Sql, ctx: ServiceContext, candidateId: string, reason: string, cause: string | null): Promise<R[]> {
    const entry = JSON.stringify([{ reason, cause, at: ctx.now }]);
    const rows = await tx.query(`update ${S}.distributions set state='needs_follow_up', follow_up_status='pending', follow_up_reasons=follow_up_reasons || $4::jsonb, history=history || $5::jsonb
      where tenant_id=$1 and project_id=$2 and candidate_id=$3 and state in ('delivered','uncertain','needs_follow_up','follow_up_done') returning *`, [...sc(ctx), candidateId, entry, JSON.stringify([{ at: ctx.now, actorId: ctx.actor.id, action: 'needs_follow_up', reason }])]);
    for (const r of rows) await emitEvent(tx, S, ctx, 'release.distribution_needs_follow_up', uref('E12', 'distribution', r.id as string), { reason, cause, candidate: uref('E12', 'candidate', candidateId), recipient: r.recipient as string });
    return rows;
  }
  async function markCandidate(tx: Sql, ctx: ServiceContext, candidateId: string, blocked: boolean, reason: string, cause: string | null, kind: string): Promise<void> {
    await tx.query(`update ${S}.candidates set stale=true, blocked=blocked or $4, stale_reasons=stale_reasons || $5::jsonb where id=$1 and tenant_id=$2 and project_id=$3`, [candidateId, ...sc(ctx), blocked, JSON.stringify([{ kind, reason, cause, blocked, at: ctx.now }])]);
    await emitEvent(tx, S, ctx, 'release.candidate_stale', uref('E12', 'candidate', candidateId), { reason, cause, kind, blocked });
  }

  // ── rights ──
  async function rightsFor(ctx: ServiceContext, cand: R, audience: string, dest: { name: string; public: boolean; licensed: boolean } | null, strict: boolean): Promise<RightsSnapshot[]> {
    const subjects = cand.subjects as string[];
    const actions: UseAction[] = [(dest?.public === true || cand.audience_class === 'public') ? 'publish' : 'reproduce', ...(dest?.licensed === true ? ['license' as const] : [])];
    if (subjects.length === 0) return actions.map((action) => ({ action, decision: 'allow', permissionRefs: [], restrictions: [], decisionRef: null, evaluated: false }));
    if (ports.useDecision === undefined) {
      if (config.standaloneRights === 'allow_without_port' || !strict) return actions.map((action) => ({ action, decision: config.standaloneRights === 'allow_without_port' ? 'allow' : 'not_evaluated', permissionRefs: [], restrictions: [], decisionRef: null, evaluated: false }));
      throw new DomainError('consent_denied', 'No use-decision service is configured; rights for this package cannot be confirmed');
    }
    const out: RightsSnapshot[] = [];
    for (const action of actions) {
      const d = await ports.useDecision.decide(ctx, { subjects, action, purpose: ctx.purpose, audience, ...(dest === null ? {} : { destination: dest.name }) }) as UseDecision & { decisionRef?: string };
      if (strict && d.decision !== 'allow') throw new DomainError('consent_denied', d.decision === 'deny' ? `Use decision denies ${action}` : `Use decision for ${action} requires review before release`);
      out.push({ action, decision: d.decision, permissionRefs: [...d.permissionRefs].sort(), restrictions: [...d.restrictions].sort(), decisionRef: typeof d.decisionRef === 'string' ? d.decisionRef : null, evaluated: true });
    }
    return out;
  }
  const rightsDigest = (r: readonly RightsSnapshot[]): string => digest(r.map((x) => ({ action: x.action, decision: x.decision, permissionRefs: x.permissionRefs, restrictions: x.restrictions })));
  async function noticesFor(q: Sql, ctx: ServiceContext, cand: R): Promise<{ name: string; text: string }[]> {
    const rows = await q.query(`select corrected_version, notice_text from ${S}.corrections where tenant_id=$1 and project_id=$2 and lineage_id=$3 and corrected_version <= $4 order by corrected_version`, [...sc(ctx), cand.lineage_id, cand.version]);
    return rows.map((r) => ({ name: `correction-v${r.corrected_version as number}.txt`, text: r.notice_text as string }));
  }

  // ── build ──
  async function resolveFile(ctx: ServiceContext, f: FileInput): Promise<ResolvedFile> {
    invariant(f !== null && typeof f === 'object', 'invalid_input', 'Invalid file input');
    if ('evidenceRef' in f) {
      if (ports.evidence === undefined) throw new DomainError('unavailable', 'Evidence service is not configured; supply file bytes directly');
      const info = await ports.evidence.describe(ctx, f.evidenceRef);
      if (info === null || !info.available) throw new DomainError('not_found', 'Not found');
      invariant(info.size <= maxFile, 'payload_too_large', 'File too large');
      return { filename: f.filename ?? info.filename, mediaType: info.mediaType, bytes: await ports.evidence.getBytes(ctx, f.evidenceRef) };
    }
    str(f.filename, 'filename', 300); str(f.mediaType, 'mediaType', 200);
    invariant(typeof f.base64 === 'string' && /^[A-Za-z0-9+/]*={0,2}$/.test(f.base64) && f.base64.length <= maxFile * 1.4, 'invalid_input', 'File content must be base64');
    const bytes = new Uint8Array(Buffer.from(f.base64, 'base64'));
    invariant(bytes.byteLength > 0 && bytes.byteLength <= maxFile, 'payload_too_large', 'File is empty or too large');
    return { filename: f.filename, mediaType: f.mediaType, bytes };
  }
  async function professionalReview(ctx: ServiceContext, reviewId: string): Promise<ProfessionalReview> {
    const r = (await sql.query(`select * from ${S}.professional_reviews where id=$1 and tenant_id=$2 and project_id=$3`, [id(reviewId), ...sc(ctx)]))[0];
    if (r === undefined) throw new DomainError('not_found', 'Not found');
    return { id: r.id as string, reviewerName: r.reviewer_name as string, reviewerRole: r.reviewer_role as string, reviewedOn: r.reviewed_on as string, contentDigest: r.content_digest as string };
  }

  async function build(ctx: ServiceContext, input: BuildInput): Promise<CandidateView> {
    requireCapability(ctx, 'release:write');
    invariant(input !== null && typeof input === 'object' && PACKAGE_KINDS.includes(input.kind), 'invalid_input', 'Unknown package kind');
    requireCompartment(ctx, input.compartment);
    const audience = str(input.audience, 'audience', 100);
    const aud = Object.hasOwn(audiences, audience) ? audiences[audience] : undefined;
    invariant(aud !== undefined, 'invalid_input', 'Audience is not configured');
    const objects = store();
    if (input.idempotencyKey !== undefined) {
      const prior = (await sql.query<{ result: { id: string } | null }>(`select result from ${S}._idempotency where tenant_id=$1 and project_id=$2 and key=$3`, [...sc(ctx), `build:${input.idempotencyKey}`]))[0];
      if (prior?.result != null) return view(sql, ctx, prior.result.id);
    }
    const formats = input.formats ?? ['html', 'pdf'];
    invariant(Array.isArray(formats) && formats.every((f) => ['html', 'pdf', 'docx'].includes(f)), 'invalid_input', 'Invalid formats');
    const language = input.language ?? 'en';
    let lineageId: string = randomUUID(), version = 1, supersedes: string | null = null, supersedesDigest: string | null = null;
    if (input.supersedes !== undefined) {
      const prior = await candidateRow(sql, ctx, input.supersedes);
      invariant(prior.state !== 'leak_blocked' && prior.kind === input.kind, 'invalid_state', 'Only a built candidate of the same kind can be superseded');
      lineageId = prior.lineage_id as string; supersedes = prior.id as string; supersedesDigest = prior.digest as string;
      version = Number((await sql.query(`select max(version) as v from ${S}.candidates where lineage_id=$1 and tenant_id=$2 and project_id=$3`, [lineageId, ...sc(ctx)]))[0]?.v ?? 0) + 1;
    }
    const pseudo = { subjects: [] as string[], audience_class: aud.class };
    const draft = await buildDraft(input, {
      resolve: (f) => resolveFile(ctx, f),
      allowOriginal: async (subject) => {
        if (aud.allowOriginals !== true || ports.useDecision === undefined) return false;
        const d = await ports.useDecision.decide(ctx, { subjects: [subject], action: aud.class === 'public' ? 'publish' : 'reproduce', purpose: ctx.purpose, audience });
        return d.decision === 'allow';
      },
      pack: (packId) => { const p = packs.get(packId); if (p === undefined) throw new DomainError('invalid_input', 'Jurisdiction pack is not configured by this deployment'); return p; },
      review: (reviewId) => professionalReview(ctx, reviewId),
    });
    const matcher = await terms(ctx, input.protectedTerms, { subjects: draft.subjects, sources: draft.sources });
    const first = await sanitize(draft.files, matcher, draft.scanFields);
    const { docs, data } = draft.finish(first.components);
    const generated: DraftComponent[] = [...data];
    for (const d of docs) {
      generated.push({ path: `${d.base}.md`, role: d.role, mediaType: 'text/markdown', bytes: utf8(d.markdown), class: 'generated', sources: d.sources, label: d.title });
      const rendered = await renderDocument(d.markdown, d.title, language, formats);
      for (const f of ['html', 'pdf', 'docx'] as const) { const bytes = rendered[f]; if (bytes !== undefined) generated.push({ path: `${d.base}.${f}`, role: d.role, mediaType: f === 'html' ? 'text/html' : f === 'pdf' ? 'application/pdf' : 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', bytes, class: 'generated', sources: d.sources, label: d.title }); }
    }
    const second = await sanitize(generated, matcher);
    const findings: Finding[] = [...first.findings, ...second.findings];
    const redactions = [...draft.redactions, ...first.redactions, ...second.redactions].sort((a, b) => (a.path + a.action < b.path + b.action ? -1 : 1));
    const components = [...first.components, ...second.components].sort((a, b) => (a.path < b.path ? -1 : 1));
    const hidden = new Set((input.protectedSourceRefs ?? []) as string[]);
    const pub = (refs: readonly string[]): string[] => [...new Set(refs)].filter((r) => !hidden.has(r)).sort();
    const candidateId = randomUUID(); const salt = randomBytes(16).toString('hex');
    const leakReport = { passed: findings.length === 0, findings: findingsJson(findings), redactions: asJson(redactions), protectedTermCount: matcher.count };
    const participants = [...new Set(input.participantReviewers ?? [])].map((p) => str(p, 'participant', 200));
    const baseRow = { lineageId, version, supersedes, salt, hashes: matcher.hashes(salt), participants };

    if (findings.length > 0) {
      await sql.tx(async (tx) => idempotent(tx, S, ctx, input.idempotencyKey === undefined ? undefined : `build:${input.idempotencyKey}`, { kind: input.kind, title: input.title }, async () => {
        await tx.query(`insert into ${S}.candidates (id, tenant_id, project_id, lineage_id, version, kind, title, audience, audience_class, state, compartment, sources, subjects, supersedes, term_salt, term_hashes, leak_report, review, created_by, created_at, blocked, stale_reasons)
          values ($1,$2,$3,$4,$5,$6,$7,$8,$9,'leak_blocked',$10,$11,$12,$13,$14,$15,$16::jsonb,$17::jsonb,$18,$19,true,$20::jsonb)`,
          [candidateId, ...sc(ctx), lineageId, version, input.kind, input.title, audience, aud.class, input.compartment ?? null, draft.sources, draft.subjects, supersedes, salt, baseRow.hashes, JSON.stringify(leakReport), JSON.stringify({ participants }), ctx.actor.id, ctx.now, JSON.stringify([{ kind: 'leak_prevention', reason: `${findings.length} leak finding(s)`, blocked: true, at: ctx.now }])]);
        const ref = uref('E12', 'candidate', candidateId, version);
        await appendAudit(tx, S, ctx, 'candidate.leak_blocked', ref, { kind: input.kind, findings: findings.length, codes: [...new Set(findings.map((f) => f.code))] });
        await emitEvent(tx, S, ctx, 'release.candidate_blocked', ref, { reason: 'leak_prevention', findings: findings.length });
        return { id: candidateId };
      }));
      return view(sql, ctx, candidateId);
    }

    const rights = await rightsFor(ctx, { ...pseudo, subjects: draft.subjects }, audience, null, false);
    const tools: Record<string, string | null> = {};
    for (const t of ['exiftool', 'pandoc', 'soffice', 'pdftotext', 'pdftocairo', 'ffmpeg', 'convert']) tools[t] = await toolVersion(t);
    const manifestDoc = {
      schema: 'e12.manifest/1', kind: input.kind, title: input.title, language, audience, audienceClass: aud.class, version, supersedesDigest,
      components: components.map((c) => ({ path: c.path, role: c.role, class: c.class, mediaType: c.mediaType, sha256: sha256(c.bytes), size: c.bytes.byteLength, sources: pub(c.sources), basis: c.basis ?? null, label: c.label ?? null, altText: c.altText ?? null })),
      sources: pub(draft.sources), protectedSourceCount: new Set(draft.sources.filter((r) => hidden.has(r))).size, subjects: pub(draft.subjects),
      rightsDecisions: rights.map((r) => ({ action: r.action, decision: r.decision, permissionRefs: r.permissionRefs, restrictions: r.restrictions })),
      redactionManifest: redactions, leakScan: { passed: true, protectedTermCount: matcher.count, tools },
      generator: { engine: 'E12', version: manifest.version }, ...draft.extra,
    };
    const manifestBytes = utf8(`${JSON.stringify(JSON.parse(canonical(asJson(manifestDoc))), null, 2)}\n`);
    const candidateDigest = sha256(manifestBytes);
    const zip = zipWrite([...components.map((c) => ({ path: c.path, bytes: c.bytes })), { path: 'manifest.json', bytes: manifestBytes }]);
    const prefix = `${ctx.tenantId}/${ctx.projectId}/candidates/${candidateId}`;
    for (const c of components) await objects.put(`${prefix}/files/${c.path}`, c.bytes);
    await objects.put(`${prefix}/manifest.json`, manifestBytes);
    await objects.put(`${prefix}/package.zip`, zip);
    const indexText = `${first.indexText}\n${second.indexText}`.slice(0, 2_000_000);
    await sql.tx(async (tx) => idempotent(tx, S, ctx, input.idempotencyKey === undefined ? undefined : `build:${input.idempotencyKey}`, { kind: input.kind, title: input.title }, async () => {
      await tx.query(`insert into ${S}.candidates (id, tenant_id, project_id, lineage_id, version, kind, title, audience, audience_class, state, digest, manifest, compartment, sources, subjects, supersedes, term_salt, term_hashes, leak_report, index_text, zip_key, zip_sha256, zip_size, review, created_by, created_at)
        values ($1,$2,$3,$4,$5,$6,$7,$8,$9,'built',$10,$11::jsonb,$12,$13,$14,$15,$16,$17,$18::jsonb,$19,$20,$21,$22,$23::jsonb,$24,$25)`,
        [candidateId, ...sc(ctx), lineageId, version, input.kind, input.title, audience, aud.class, candidateDigest, JSON.stringify(manifestDoc), input.compartment ?? null, [...new Set(draft.sources)], [...new Set(draft.subjects)], supersedes, salt, baseRow.hashes, JSON.stringify(leakReport), indexText, `${prefix}/package.zip`, sha256(zip), zip.byteLength, JSON.stringify({ participants }), ctx.actor.id, ctx.now]);
      for (const c of components) await tx.query(`insert into ${S}.components (tenant_id, project_id, candidate_id, path, role, class, media_type, sha256, size, object_key, sources, label, alt_text) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
        [...sc(ctx), candidateId, c.path, c.role, c.class, c.mediaType, sha256(c.bytes), c.bytes.byteLength, `${prefix}/files/${c.path}`, [...c.sources], c.label ?? null, c.altText ?? null]);
      const ref = uref('E12', 'candidate', candidateId, version);
      await appendAudit(tx, S, ctx, 'candidate.built', ref, { kind: input.kind, digest: candidateDigest, components: components.length, supersedes });
      await emitEvent(tx, S, ctx, 'release.candidate_built', ref, { kind: input.kind, digest: candidateDigest, audience, lineage: lineageId, supersedes });
      return { id: candidateId };
    }));
    return view(sql, ctx, candidateId);
  }

  // ── stored bytes ──
  async function loadPackage(ctx: ServiceContext, cand: R): Promise<{ files: { path: string; bytes: Uint8Array; sha256: string; label?: string; altText?: string }[]; manifestBytes: Uint8Array; zip: Uint8Array }> {
    const objects = store();
    const prefix = `${ctx.tenantId}/${ctx.projectId}/candidates/${cand.id as string}`;
    const files = [];
    for (const c of await componentRows(sql, cand.id as string)) files.push({ path: c.path as string, bytes: await objects.get(c.object_key as string), sha256: c.sha256 as string, ...(c.label == null ? {} : { label: c.label as string }), ...(c.alt_text == null ? {} : { altText: c.alt_text as string }) });
    return { files, manifestBytes: await objects.get(`${prefix}/manifest.json`), zip: await objects.get(cand.zip_key as string) };
  }
  const usable = (cand: R): void => {
    invariant(cand.state !== 'leak_blocked', 'invalid_state', 'Candidate failed leak prevention and holds no package');
    invariant(cand.state !== 'superseded' && cand.state !== 'withdrawn', 'approval_invalid', `Candidate is ${cand.state as string}`);
    invariant(cand.stale !== true && cand.blocked !== true, 'approval_invalid', 'Candidate is stale or blocked; build and approve a new version');
  };
  const sign = (linkId: string, exp: number): string => { if (rt.downloadSecret === undefined || rt.downloadSecret.length < 16) throw new DomainError('unavailable', 'Download link signing secret is not configured'); return createHmac('sha256', rt.downloadSecret).update(`${linkId}.${exp}`).digest('base64url'); };

  // ── release internals ──
  async function finalize(tx: Sql, ctx: ServiceContext, release: R, cand: R, dest: R, result: DeliveryResult, recipients: readonly string[]): Promise<R> {
    const ref = uref('E12', 'release', release.id as string);
    const candRef = uref('E12', 'candidate', cand.id as string, cand.version as number);
    if (result.outcome === 'delivered') {
      const body = { releaseId: release.id as string, candidate: candRef, candidateDigest: release.candidate_digest as string, zipSha256: cand.zip_sha256 as string, audience: release.audience as string, public: release.public as boolean,
        destination: { id: dest.id as string, name: dest.name as string, kind: dest.kind as string, revision: dest.revision as number }, approvalId: release.approval_id as string, accountabilityDecisionId: (release.accountability_decision_id as string | null) ?? null,
        releasedBy: release.released_by as string, releasedAt: ctx.now, recordedBy: ctx.actor.id, adapterResponse: result.response, recipients: [...recipients] };
      const receipt = { ...body, receiptDigest: digest(body) };
      const row = (await tx.query(`update ${S}.releases set state='delivered', adapter_response=$2::jsonb, receipt=$3::jsonb, completed_at=$4 where id=$1 and state in ('dispatching','uncertain') returning *`, [release.id, JSON.stringify(result.response), JSON.stringify(receipt), ctx.now]))[0];
      invariant(row !== undefined, 'invalid_state', 'Release is not awaiting an outcome');
      await tx.query(`update ${S}.approvals set state='used' where id=$1 and state='valid'`, [release.approval_id]);
      const existing = await tx.query(`update ${S}.distributions set state='delivered', history=history || $2::jsonb where release_id=$1 and state='uncertain' returning id`, [release.id, JSON.stringify([{ at: ctx.now, actorId: ctx.actor.id, action: 'delivery_confirmed' }])]);
      if (existing.length === 0) for (const recipient of recipients) await tx.query(`insert into ${S}.distributions (id, tenant_id, project_id, release_id, candidate_id, lineage_id, destination_id, recipient, kind, state, history, created_at) values ($1,$2,$3,$4,$5,$6,$7,$8,'primary','delivered',$9::jsonb,$10)`,
        [randomUUID(), ...sc(ctx), release.id, cand.id, cand.lineage_id, dest.id, recipient, JSON.stringify([{ at: ctx.now, actorId: ctx.actor.id, action: 'delivered' }]), ctx.now]);
      await appendAudit(tx, S, ctx, 'release.delivered', ref, { candidateDigest: release.candidate_digest as string, destination: dest.id as string, receiptDigest: receipt.receiptDigest });
      await emitEvent(tx, S, ctx, 'release.released', ref, { candidate: candRef, digest: release.candidate_digest as string, destination: uref('E12', 'destination', dest.id as string), audience: release.audience as string, public: release.public as boolean });
      return row;
    }
    const state = result.outcome === 'uncertain' ? 'uncertain' : 'failed';
    const row = (await tx.query(`update ${S}.releases set state=$2, adapter_response=$3::jsonb, completed_at=$4 where id=$1 and state in ('dispatching','uncertain') returning *`, [release.id, state, JSON.stringify(result.response), ctx.now]))[0];
    invariant(row !== undefined, 'invalid_state', 'Release is not awaiting an outcome');
    if (state === 'uncertain') {
      const have = await tx.query(`select 1 from ${S}.distributions where release_id=$1`, [release.id]);
      if (have.length === 0) for (const recipient of recipients) await tx.query(`insert into ${S}.distributions (id, tenant_id, project_id, release_id, candidate_id, lineage_id, destination_id, recipient, kind, state, history, created_at) values ($1,$2,$3,$4,$5,$6,$7,$8,'primary','uncertain',$9::jsonb,$10)`,
        [randomUUID(), ...sc(ctx), release.id, cand.id, cand.lineage_id, dest.id, recipient, JSON.stringify([{ at: ctx.now, actorId: ctx.actor.id, action: 'delivery_uncertain' }]), ctx.now]);
      await enqueueJob(tx, S, ctx, { kind: 'release.reconcile', payload: { releaseId: release.id as string }, dedupeKey: `reconcile:${release.id as string}`, runAt: new Date(new Date(ctx.now).getTime() + 30_000), maxAttempts: 8 });
    } else await tx.query(`update ${S}.distributions set state='not_delivered', history=history || $2::jsonb where release_id=$1 and state='uncertain'`, [release.id, JSON.stringify([{ at: ctx.now, actorId: ctx.actor.id, action: 'not_delivered' }])]);
    await appendAudit(tx, S, ctx, `release.${state}`, ref, { destination: dest.id as string });
    await emitEvent(tx, S, ctx, state === 'uncertain' ? 'release.delivery_uncertain' : 'release.delivery_failed', ref, { candidate: candRef, destination: uref('E12', 'destination', dest.id as string) });
    return row;
  }
  async function releaseRow(q: Sql, ctx: ServiceContext, releaseId: unknown): Promise<{ release: R; cand: R; dest: R }> {
    const release = (await q.query(`select * from ${S}.releases where id=$1 and tenant_id=$2 and project_id=$3`, [id(releaseId), ...sc(ctx)]))[0];
    if (release === undefined) throw new DomainError('not_found', 'Not found');
    return { release, cand: await candidateRow(q, ctx, release.candidate_id), dest: await destinationRow(q, ctx, release.destination_id) };
  }
  async function probeRelease(ctx: ServiceContext, releaseId: string): Promise<ReleaseView> {
    const { release, cand, dest } = await releaseRow(sql, ctx, releaseId);
    if (release.state !== 'uncertain') return toRelease(release, true);
    const outcome = await probe(dest.kind as DestinationKind, rt, dest.config as Record<string, unknown>, { scope: { tenantId: ctx.tenantId, projectId: ctx.projectId }, lineageId: cand.lineage_id as string, version: cand.version as number, digest: cand.digest as string, zipSize: Number(cand.zip_size), zipSha256: cand.zip_sha256 as string });
    if (outcome === 'unknown') return toRelease(release);
    const recipients = (release.recipients as string[]);
    return toRelease(await sql.tx((tx) => finalize(tx, ctx, release, cand, dest, { outcome: outcome === 'delivered' ? 'delivered' : 'failed', response: { reconciledBy: 'destination_probe', probe: outcome, previous: release.adapter_response as Json } }, recipients)));
  }

  const engine = {
    manifest,

    // ── builders ──
    buildPackage: build,
    buildEvidenceBundle: (ctx: ServiceContext, input: Omit<Extract<BuildInput, { kind: 'evidence_bundle' }>, 'kind'>) => build(ctx, { ...input, kind: 'evidence_bundle' }),
    buildInvestigationReport: (ctx: ServiceContext, input: Omit<Extract<BuildInput, { kind: 'investigation_report' }>, 'kind'>) => build(ctx, { ...input, kind: 'investigation_report' }),
    buildChronology: (ctx: ServiceContext, input: Omit<Extract<BuildInput, { kind: 'chronology' }>, 'kind'>) => build(ctx, { ...input, kind: 'chronology' }),
    buildReferralPackage: (ctx: ServiceContext, input: Omit<Extract<BuildInput, { kind: 'referral_package' }>, 'kind'>) => build(ctx, { ...input, kind: 'referral_package' }),
    buildRecordsRequest: (ctx: ServiceContext, input: Omit<Extract<BuildInput, { kind: 'records_request' }>, 'kind'>) => build(ctx, { ...input, kind: 'records_request' }),
    buildLegalDraft: (ctx: ServiceContext, input: Omit<Extract<BuildInput, { kind: 'legal_draft' }>, 'kind'>) => build(ctx, { ...input, kind: 'legal_draft' }),
    buildSourceCompanion: (ctx: ServiceContext, input: Omit<Extract<BuildInput, { kind: 'source_companion' }>, 'kind'>) => build(ctx, { ...input, kind: 'source_companion' }),
    buildMediaPackage: (ctx: ServiceContext, input: Omit<Extract<BuildInput, { kind: 'media_package' }>, 'kind'>) => build(ctx, { ...input, kind: 'media_package' }),
    listJurisdictionPacks(ctx: ServiceContext): { id: string; name: string; version: number; documentTypes: string[]; authorities: { id: string; reviewed: boolean }[] }[] {
      requireCapability(ctx, 'release:read');
      return [...packs.values()].map((p) => ({ id: p.id, name: p.name, version: p.version, documentTypes: Object.keys(p.documentTypes), authorities: p.authorities.map((a) => ({ id: a.id, reviewed: a.reviewed })) }));
    },

    // ── candidates ──
    async getCandidate(ctx: ServiceContext, candidateId: string): Promise<CandidateView> { requireCapability(ctx, 'release:read'); return view(sql, ctx, candidateId); },
    async listCandidates(ctx: ServiceContext, options: { kind?: string; state?: string; lineageId?: string; limit?: number } = {}): Promise<CandidateView[]> {
      requireCapability(ctx, 'release:read');
      const rows = await sql.query(`select * from ${S}.candidates where tenant_id=$1 and project_id=$2 and ($3::text is null or kind=$3) and ($4::text is null or state=$4) and ($5::uuid is null or lineage_id=$5) and (compartment is null or compartment = any($6)) order by created_at desc, version desc limit ${Math.min(Math.max(options.limit ?? 100, 1), 500)}`,
        [...sc(ctx), options.kind ?? null, options.state ?? null, options.lineageId === undefined ? null : id(options.lineageId), [...ctx.compartments]]);
      return rows.map((r) => toCandidate(r, []));
    },
    async getManifest(ctx: ServiceContext, candidateId: string): Promise<Json> { requireCapability(ctx, 'release:read'); const r = await candidateRow(sql, ctx, candidateId); invariant(r.manifest !== null, 'invalid_state', 'Candidate failed leak prevention and has no manifest'); return r.manifest as Json; },
    async getComponent(ctx: ServiceContext, candidateId: string, path: string): Promise<{ bytes: Uint8Array; mediaType: string; sha256: string }> {
      requireCapability(ctx, 'release:read');
      const cand = await candidateRow(sql, ctx, candidateId);
      const c = (await sql.query(`select * from ${S}.components where candidate_id=$1 and path=$2`, [cand.id, String(path)]))[0];
      if (c === undefined) throw new DomainError('not_found', 'Not found');
      return { bytes: await store().get(c.object_key as string), mediaType: c.media_type as string, sha256: c.sha256 as string };
    },
    /** Private export of the package archive for review. This is not a release and creates no distribution record. */
    async exportCandidateZip(ctx: ServiceContext, candidateId: string): Promise<{ bytes: Uint8Array; sha256: string; filename: string }> {
      requireCapability(ctx, 'release:export');
      const cand = await candidateRow(sql, ctx, candidateId);
      invariant(cand.state !== 'leak_blocked', 'invalid_state', 'Candidate failed leak prevention and holds no package');
      await authorize(ctx, 'release:export', uref('E12', 'candidate', cand.id as string));
      const bytes = await store().get(cand.zip_key as string);
      await sql.tx((tx) => appendAudit(tx, S, ctx, 'candidate.exported_for_review', uref('E12', 'candidate', cand.id as string, cand.version as number), { zipSha256: cand.zip_sha256 as string }));
      return { bytes, sha256: cand.zip_sha256 as string, filename: `${cand.kind as string}-v${cand.version as number}-${(cand.digest as string).slice(0, 12)}.zip` };
    },

    // ── private review ──
    async submitForReview(ctx: ServiceContext, candidateId: string, input: { reviewers: readonly string[]; participantReviewers?: readonly string[] }): Promise<CandidateView> {
      requireCapability(ctx, 'release:write');
      invariant(Array.isArray(input?.reviewers) && input.reviewers.length > 0 && input.reviewers.length <= 50, 'invalid_input', 'At least one reviewer is required');
      const reviewers = [...new Set(input.reviewers.map((r) => str(r, 'reviewer', 200)))];
      const pre = await candidateRow(sql, ctx, candidateId);
      const restricted = pre.state === 'leak_blocked' ? false : (await rightsFor(ctx, pre, pre.audience as string, null, false)).some((r) => r.restrictions.includes(participantRestriction));
      await sql.tx(async (tx) => {
        const cand = await candidateRow(tx, ctx, candidateId, true);
        usable(cand); invariant(cand.state === 'built', 'invalid_state', 'Only a newly built candidate can be submitted for review');
        const participants = [...new Set([...((cand.review as { participants?: string[] }).participants ?? []), ...(input.participantReviewers ?? []).map((p) => str(p, 'participant', 200))])];
        invariant(!restricted || participants.length > 0, 'invalid_input', 'A consent restriction requires participant review; name the participant reviewers');
        const review = { reviewers, participants, participantRequired: restricted || participants.length > 0, submittedBy: ctx.actor.id, submittedAt: ctx.now };
        await tx.query(`update ${S}.candidates set state='in_review', review=$2::jsonb where id=$1`, [cand.id, JSON.stringify(review)]);
        await tx.query(`insert into ${S}.review_events (id, tenant_id, project_id, candidate_id, candidate_digest, kind, actor_id, actor_kind, at) values ($1,$2,$3,$4,$5,'submitted',$6,$7,$8)`, [randomUUID(), ...sc(ctx), cand.id, cand.digest, ctx.actor.id, ctx.actor.kind, ctx.now]);
        const ref = uref('E12', 'candidate', cand.id as string, cand.version as number);
        await appendAudit(tx, S, ctx, 'review.submitted', ref, { reviewers, participants });
        await emitEvent(tx, S, ctx, 'release.review_submitted', ref, { digest: cand.digest as string, participantRequired: review.participantRequired });
      });
      return view(sql, ctx, candidateId);
    },
    async addReviewComment(ctx: ServiceContext, candidateId: string, input: { body: string; componentPath?: string }): Promise<ReviewEventView> {
      requireCapability(ctx, 'release:review');
      const cand = await candidateRow(sql, ctx, candidateId);
      invariant(cand.state !== 'leak_blocked', 'invalid_state', 'Candidate holds no package');
      const row = { id: randomUUID(), kind: 'comment', actorId: ctx.actor.id, body: str(input?.body, 'comment', 10000), componentPath: input.componentPath ?? null, candidateDigest: cand.digest as string, at: ctx.now };
      await sql.tx(async (tx) => {
        await tx.query(`insert into ${S}.review_events (id, tenant_id, project_id, candidate_id, candidate_digest, kind, actor_id, actor_kind, body, component_path, at) values ($1,$2,$3,$4,$5,'comment',$6,$7,$8,$9,$10)`, [row.id, ...sc(ctx), cand.id, cand.digest, ctx.actor.id, ctx.actor.kind, row.body, row.componentPath, ctx.now]);
        await appendAudit(tx, S, ctx, 'review.commented', uref('E12', 'candidate', cand.id as string, cand.version as number), { commentId: row.id });
      });
      return row;
    },
    /** A reviewer's verdict on the exact digest. Requested changes are resolved by building a superseding candidate. */
    async recordReview(ctx: ServiceContext, candidateId: string, input: { candidateDigest: string; outcome: 'accepted' | 'changes_requested'; body?: string }): Promise<CandidateView> {
      requireCapability(ctx, 'release:review'); human(ctx, 'Review');
      invariant(input?.outcome === 'accepted' || input?.outcome === 'changes_requested', 'invalid_input', 'Invalid review outcome');
      await sql.tx(async (tx) => {
        const cand = await candidateRow(tx, ctx, candidateId, true);
        invariant(cand.state === 'in_review' || cand.state === 'reviewed', 'invalid_state', 'Candidate is not in review');
        invariant(input.candidateDigest === cand.digest, 'approval_invalid', 'Review must name the exact candidate digest');
        const review = cand.review as { reviewers: string[]; participants: string[]; participantRequired: boolean };
        invariant(review.reviewers.includes(ctx.actor.id), 'forbidden', 'Only a named reviewer can record a review');
        const kind = input.outcome === 'accepted' ? 'reviewer_accepted' : 'changes_requested';
        await tx.query(`insert into ${S}.review_events (id, tenant_id, project_id, candidate_id, candidate_digest, kind, actor_id, actor_kind, body, at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, [randomUUID(), ...sc(ctx), cand.id, cand.digest, kind, ctx.actor.id, ctx.actor.kind, input.outcome === 'changes_requested' ? str(input.body, 'requested changes', 10000) : (input.body ?? ''), ctx.now]);
        await settleReview(tx, ctx, cand, kind === 'changes_requested');
      });
      return view(sql, ctx, candidateId);
    },
    /** A participant's own review where a consent restriction (or the builder) requires it. */
    async recordParticipantReview(ctx: ServiceContext, candidateId: string, input: { candidateDigest: string; outcome: 'accepted' | 'objected'; note?: string }): Promise<CandidateView> {
      requireCapability(ctx, 'release:participant_review'); human(ctx, 'Participant review');
      invariant(input?.outcome === 'accepted' || input?.outcome === 'objected', 'invalid_input', 'Invalid participant outcome');
      await sql.tx(async (tx) => {
        const cand = await candidateRow(tx, ctx, candidateId, true);
        invariant(cand.state === 'in_review' || cand.state === 'reviewed', 'invalid_state', 'Candidate is not in review');
        invariant(input.candidateDigest === cand.digest, 'approval_invalid', 'Review must name the exact candidate digest');
        invariant(((cand.review as { participants?: string[] }).participants ?? []).includes(ctx.actor.id), 'forbidden', 'Only a named participant can record this review');
        await tx.query(`insert into ${S}.review_events (id, tenant_id, project_id, candidate_id, candidate_digest, kind, actor_id, actor_kind, body, at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, [randomUUID(), ...sc(ctx), cand.id, cand.digest, input.outcome === 'accepted' ? 'participant_accepted' : 'participant_objected', ctx.actor.id, ctx.actor.kind, input.note ?? '', ctx.now]);
        await settleReview(tx, ctx, cand, input.outcome === 'objected');
      });
      return view(sql, ctx, candidateId);
    },
    async listReviewEvents(ctx: ServiceContext, candidateId: string): Promise<ReviewEventView[]> {
      requireCapability(ctx, 'release:read');
      const cand = await candidateRow(sql, ctx, candidateId);
      return (await sql.query(`select * from ${S}.review_events where candidate_id=$1 order by at, id`, [cand.id])).map((r) => ({ id: r.id as string, kind: r.kind as string, actorId: r.actor_id as string, body: r.body as string, componentPath: (r.component_path as string | null) ?? null, candidateDigest: r.candidate_digest as string, at: iso(r.at) }));
    },

    // ── human decisions ──
    /** The recorded human decision that public scrutiny is appropriate, made after assessing the legal-accountability route. */
    async recordAccountabilityDecision(ctx: ServiceContext, candidateId: string, input: { candidateDigest: string; outcome: 'public_scrutiny_appropriate' | 'not_appropriate'; assessment: string; legalRoutesConsidered?: readonly Readonly<{ ref?: string; description: string; status: string }>[]; noLegalRouteReason?: string }): Promise<AccountabilityDecisionView> {
      requireCapability(ctx, 'release:approve'); human(ctx, 'The accountability decision');
      invariant(input?.outcome === 'public_scrutiny_appropriate' || input?.outcome === 'not_appropriate', 'invalid_input', 'Invalid outcome');
      const assessment = str(input.assessment, 'assessment', 20000);
      const routes = (input.legalRoutesConsidered ?? []).map((r) => { if (r.ref !== undefined) parseUref(r.ref); return { ref: r.ref ?? null, description: str(r.description, 'legal route description'), status: str(r.status, 'legal route status', 200) }; });
      invariant(routes.length <= 200, 'invalid_input', 'Too many legal routes');
      if (policy === 'legal_first') invariant(routes.length > 0 || (typeof input.noLegalRouteReason === 'string' && input.noLegalRouteReason.trim() !== ''), 'invalid_input', 'Under the legal-first policy the decision must record the legal-route records considered, or state why no legal route exists');
      return sql.tx(async (tx) => {
        const cand = await candidateRow(tx, ctx, candidateId, true);
        usable(cand); invariant(input.candidateDigest === cand.digest, 'approval_invalid', 'Decision must name the exact candidate digest');
        await authorize(ctx, 'release:approve', uref('E12', 'candidate', cand.id as string));
        const row = (await tx.query(`insert into ${S}.accountability_decisions (id, tenant_id, project_id, candidate_id, candidate_digest, outcome, assessment, legal_routes, no_legal_route_reason, policy, decided_by, decided_by_kind, decided_at) values ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11,$12,$13) returning *`,
          [randomUUID(), ...sc(ctx), cand.id, cand.digest, input.outcome, assessment, JSON.stringify(routes), input.noLegalRouteReason ?? null, policy, ctx.actor.id, ctx.actor.kind, ctx.now]))[0] as R;
        const v = toDecision(row);
        await appendAudit(tx, S, ctx, 'accountability.decided', v.ref, { candidate: cand.id as string, digest: cand.digest as string, outcome: input.outcome, legalRoutes: routes.length });
        await emitEvent(tx, S, ctx, 'release.accountability_decided', v.ref, { candidate: uref('E12', 'candidate', cand.id as string, cand.version as number), outcome: input.outcome });
        return v;
      });
    },
    async listAccountabilityDecisions(ctx: ServiceContext, candidateId: string): Promise<AccountabilityDecisionView[]> {
      requireCapability(ctx, 'release:read'); const cand = await candidateRow(sql, ctx, candidateId);
      return (await sql.query(`select * from ${S}.accountability_decisions where candidate_id=$1 order by decided_at`, [cand.id])).map(toDecision);
    },
    /** Records that a named legal professional actually reviewed this exact draft. Only then may a rebuild drop the "not reviewed" stamp. */
    async recordProfessionalReview(ctx: ServiceContext, candidateId: string, input: { candidateDigest: string; reviewerName: string; reviewerRole: string; reviewedOn: string; statement?: string }): Promise<ProfessionalReview & { candidateId: string }> {
      requireCapability(ctx, reviewCap); human(ctx, 'Recording a professional review');
      if (!ctx.capabilities.includes(reviewCap)) throw new DomainError('forbidden', `Missing capability ${reviewCap}`);
      invariant(typeof input?.reviewedOn === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(input.reviewedOn) && Date.parse(input.reviewedOn) <= Date.parse(ctx.now), 'invalid_input', 'reviewedOn must be a past date (YYYY-MM-DD)');
      return sql.tx(async (tx) => {
        const cand = await candidateRow(tx, ctx, candidateId, true);
        invariant(cand.kind === 'legal_draft' || cand.kind === 'records_request', 'invalid_state', 'Professional review applies to legal-support documents');
        usable(cand); invariant(input.candidateDigest === cand.digest, 'approval_invalid', 'Review must name the exact candidate digest');
        const contentDigest = ((cand.manifest as { legal?: { contentDigest?: string } }).legal?.contentDigest) ?? '';
        const row = { id: randomUUID(), reviewerName: str(input.reviewerName, 'reviewerName', 300), reviewerRole: str(input.reviewerRole, 'reviewerRole', 300), reviewedOn: input.reviewedOn, contentDigest };
        await tx.query(`insert into ${S}.professional_reviews (id, tenant_id, project_id, candidate_id, candidate_digest, content_digest, reviewer_name, reviewer_role, reviewed_on, statement, recorded_by, recorded_by_kind, recorded_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
          [row.id, ...sc(ctx), cand.id, cand.digest, contentDigest, row.reviewerName, row.reviewerRole, row.reviewedOn, input.statement ?? null, ctx.actor.id, ctx.actor.kind, ctx.now]);
        const ref = uref('E12', 'professional_review', row.id);
        await appendAudit(tx, S, ctx, 'professional_review.recorded', ref, { candidate: cand.id as string, digest: cand.digest as string });
        await emitEvent(tx, S, ctx, 'release.professional_review_recorded', ref, { candidate: uref('E12', 'candidate', cand.id as string, cand.version as number) });
        return { ...row, candidateId: cand.id as string };
      });
    },

    // ── destinations ──
    async createDestination(ctx: ServiceContext, input: { name: string; kind: DestinationKind; audiences: readonly string[]; public?: boolean; licensed?: boolean; config?: Record<string, unknown> }): Promise<DestinationView> {
      requireCapability(ctx, 'release:admin'); human(ctx, 'Configuring a destination');
      const v = checkDestination(input);
      return sql.tx(async (tx) => {
        const dup = await tx.query(`select 1 from ${S}.destinations where tenant_id=$1 and project_id=$2 and name=$3`, [...sc(ctx), v.name]);
        invariant(dup.length === 0, 'conflict', 'A destination with this name exists');
        const row = (await tx.query(`insert into ${S}.destinations (id, tenant_id, project_id, name, kind, public, licensed, audiences, config, updated_by, updated_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11) returning *`, [randomUUID(), ...sc(ctx), v.name, v.kind, v.public, v.licensed, v.audiences, JSON.stringify(v.config), ctx.actor.id, ctx.now]))[0] as R;
        const d = toDestination(row);
        await appendAudit(tx, S, ctx, 'destination.created', d.ref, { kind: v.kind, public: v.public, audiences: v.audiences });
        await emitEvent(tx, S, ctx, 'release.destination_changed', d.ref, { revision: 1 });
        return d;
      });
    },
    /** Any change bumps the revision and invalidates approvals bound to the previous one. */
    async updateDestination(ctx: ServiceContext, destinationId: string, input: { audiences?: readonly string[]; public?: boolean; licensed?: boolean; config?: Record<string, unknown>; enabled?: boolean }): Promise<DestinationView> {
      requireCapability(ctx, 'release:admin'); human(ctx, 'Configuring a destination');
      return sql.tx(async (tx) => {
        const cur = (await tx.query(`select * from ${S}.destinations where id=$1 and tenant_id=$2 and project_id=$3 for update`, [id(destinationId), ...sc(ctx)]))[0];
        if (cur === undefined) throw new DomainError('not_found', 'Not found');
        const v = checkDestination({ name: cur.name as string, kind: cur.kind as DestinationKind, audiences: input.audiences ?? (cur.audiences as string[]), public: input.public ?? (cur.public as boolean), licensed: input.licensed ?? (cur.licensed as boolean), config: input.config ?? (cur.config as Record<string, unknown>) });
        const row = (await tx.query(`update ${S}.destinations set public=$2, licensed=$3, audiences=$4, config=$5::jsonb, enabled=$6, revision=revision+1, updated_by=$7, updated_at=$8 where id=$1 returning *`, [cur.id, v.public, v.licensed, v.audiences, JSON.stringify(v.config), input.enabled ?? (cur.enabled as boolean), ctx.actor.id, ctx.now]))[0] as R;
        const d = toDestination(row);
        await invalidateApprovals(tx, ctx, 'destination_id=$4', [cur.id], 'destination_changed', d.ref);
        await appendAudit(tx, S, ctx, 'destination.updated', d.ref, { revision: d.revision, enabled: d.enabled });
        await emitEvent(tx, S, ctx, 'release.destination_changed', d.ref, { revision: d.revision });
        return d;
      });
    },
    async listDestinations(ctx: ServiceContext): Promise<DestinationView[]> { requireCapability(ctx, 'release:read'); return (await sql.query(`select * from ${S}.destinations where tenant_id=$1 and project_id=$2 order by name`, sc(ctx))).map(toDestination); },

    // ── approval ──
    async approve(ctx: ServiceContext, candidateId: string, input: { candidateDigest: string; audience: string; destinationId: string; expiresAt: string; accountabilityDecisionId?: string; idempotencyKey?: string }): Promise<ApprovalView> {
      requireCapability(ctx, 'release:approve'); human(ctx, 'Approval');
      invariant(input !== null && typeof input === 'object' && typeof input.candidateDigest === 'string', 'invalid_input', 'candidateDigest is required');
      const exp = Date.parse(String(input.expiresAt)), now = Date.parse(ctx.now);
      invariant(Number.isFinite(exp) && exp > now && exp - now <= (config.maxApprovalSeconds ?? 86400) * 1000, 'invalid_input', `Approval must expire within ${config.maxApprovalSeconds ?? 86400} seconds`);
      const pre = await candidateRow(sql, ctx, candidateId);
      usable(pre);
      const dest = await destinationRow(sql, ctx, input.destinationId);
      await authorize(ctx, 'release:approve', uref('E12', 'candidate', pre.id as string));
      // Consent is decided outside the transaction (it is another service) and re-checked at release.
      const rights = await rightsFor(ctx, pre, String(input.audience), { name: dest.name as string, public: dest.public as boolean, licensed: dest.licensed as boolean }, true);
      return sql.tx(async (tx) => idempotent(tx, S, ctx, input.idempotencyKey === undefined ? undefined : `approve:${input.idempotencyKey}`, { candidateId, ...input }, async () => {
        const cand = await candidateRow(tx, ctx, candidateId, true);
        usable(cand);
        invariant(input.candidateDigest === cand.digest, 'approval_invalid', 'Approval must name the exact candidate digest; the candidate you reviewed is not this one');
        invariant(cand.state === 'reviewed', 'invalid_state', 'Candidate has not completed private review');
        invariant(input.audience === cand.audience, 'approval_invalid', 'The candidate was built for a different audience; build a candidate for this audience');
        invariant(dest.enabled === true && (dest.audiences as string[]).includes(cand.audience as string), 'invalid_state', 'Destination is disabled or does not serve this audience');
        const review = cand.review as { participantRequired?: boolean; participants?: string[] };
        const needParticipant = review.participantRequired === true || rights.some((r) => r.restrictions.includes(participantRestriction));
        if (needParticipant) {
          const ok = await tx.query(`select distinct actor_id from ${S}.review_events where candidate_id=$1 and candidate_digest=$2 and kind='participant_accepted'`, [cand.id, cand.digest]);
          invariant(ok.length > 0 && (review.participants ?? []).every((p) => ok.some((o) => o.actor_id === p)), 'consent_denied', 'A consent restriction requires participant review of this exact version before approval');
        }
        const isPublic = dest.public === true || cand.audience_class === 'public';
        let decisionId: string | null = null;
        if (isPublic) {
          invariant(input.accountabilityDecisionId !== undefined, 'forbidden', 'Public release requires a recorded human accountability decision');
          const d = (await tx.query(`select * from ${S}.accountability_decisions where id=$1 and tenant_id=$2 and project_id=$3 and candidate_id=$4`, [id(input.accountabilityDecisionId), ...sc(ctx), cand.id]))[0];
          invariant(d !== undefined && d.candidate_digest === cand.digest && d.decided_by_kind === 'human' && d.outcome === 'public_scrutiny_appropriate', 'forbidden', 'No human decision that public scrutiny is appropriate exists for this exact version');
          invariant(policy !== 'legal_first' || (d.legal_routes as unknown[]).length > 0 || d.no_legal_route_reason !== null, 'forbidden', 'The accountability decision does not record the legal route assessment required by policy');
          decisionId = d.id as string;
        }
        const notices = await noticesFor(tx, ctx, cand);
        const row = (await tx.query(`insert into ${S}.approvals (id, tenant_id, project_id, candidate_id, candidate_digest, audience, destination_id, destination_revision, public, rights, rights_digest, permission_refs, notices_digest, accountability_decision_id, approved_by, approved_by_kind, approved_at, expires_at)
          values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12,$13,$14,$15,$16,$17,$18) returning *`,
          [randomUUID(), ...sc(ctx), cand.id, cand.digest, cand.audience, dest.id, dest.revision, isPublic, JSON.stringify(rights), rightsDigest(rights), [...new Set(rights.flatMap((r) => [...r.permissionRefs, ...(r.decisionRef === null ? [] : [r.decisionRef])]))], digest(notices), decisionId, ctx.actor.id, ctx.actor.kind, ctx.now, new Date(exp).toISOString()]))[0] as R;
        const v = toApproval(row);
        await appendAudit(tx, S, ctx, 'approval.granted', v.ref, { candidate: cand.id as string, digest: cand.digest as string, audience: v.audience, destination: v.destinationId, public: isPublic, accountabilityDecisionId: decisionId });
        await emitEvent(tx, S, ctx, 'release.approved', v.ref, { candidate: uref('E12', 'candidate', cand.id as string, cand.version as number), digest: cand.digest as string, audience: v.audience, destination: uref('E12', 'destination', dest.id as string), public: isPublic });
        return v as unknown as Json;
      }) as unknown as Promise<ApprovalView>);
    },
    async listApprovals(ctx: ServiceContext, candidateId: string): Promise<ApprovalView[]> {
      requireCapability(ctx, 'release:read'); const cand = await candidateRow(sql, ctx, candidateId);
      return (await sql.query(`select * from ${S}.approvals where candidate_id=$1 order by approved_at`, [cand.id])).map(toApproval);
    },

    // ── release ──
    /**
     * Releases the exact approved digest to the approved destination. Everything is re-checked first. A retry never
     * distributes twice: a delivered release is returned as-is, an uncertain one must be reconciled.
     */
    async release(ctx: ServiceContext, candidateId: string, input: { approvalId: string; audience: string; destinationId: string; recipients?: readonly string[]; protectedTerms?: readonly string[] }): Promise<ReleaseView> {
      requireCapability(ctx, 'release:publish');
      invariant(input !== null && typeof input === 'object', 'invalid_input', 'Release input is required');
      const cand = await candidateRow(sql, ctx, candidateId);
      const approval = (await sql.query(`select * from ${S}.approvals where id=$1 and tenant_id=$2 and project_id=$3 and candidate_id=$4`, [id(input.approvalId), ...sc(ctx), cand.id]))[0];
      if (approval === undefined) throw new DomainError('approval_invalid', 'No approval exists for this candidate with that identifier');
      const existing = (await sql.query(`select * from ${S}.releases where approval_id=$1`, [approval.id]))[0];
      if (existing !== undefined && existing.state === 'delivered') return toRelease(existing, true);
      if (existing !== undefined && (existing.state === 'uncertain' || existing.state === 'dispatching')) {
        // A previous attempt may have reached the destination. Never send again; record and reconcile.
        if (existing.state === 'dispatching') {
          const dest0 = await destinationRow(sql, ctx, existing.destination_id);
          return toRelease(await sql.tx((tx) => finalize(tx, ctx, existing, cand, dest0, { outcome: 'uncertain', response: { error: 'interrupted_before_outcome_was_recorded' } }, existing.recipients as string[])), true);
        }
        return toRelease(existing, true);
      }
      const fail = async (reason: string, message: string, block: boolean): Promise<never> => {
        await sql.tx(async (tx) => {
          await invalidateApprovals(tx, ctx, block ? 'candidate_id=$4' : 'id=$4', [block ? cand.id : approval.id], reason, null);
          if (block) await markCandidate(tx, ctx, cand.id as string, true, message, null, reason);
        });
        throw new DomainError('approval_invalid', message);
      };
      invariant(approval.state === 'valid', 'approval_invalid', `Approval is ${approval.state as string}${approval.invalid_reason == null ? '' : ` (${approval.invalid_reason as string})`}; a new approval of the current version is required`);
      if (Date.parse(ctx.now) >= new Date(approval.expires_at as string).getTime() || Date.now() >= new Date(approval.expires_at as string).getTime()) await fail('expired', 'Approval has expired', false);
      invariant(input.audience === approval.audience && input.destinationId === approval.destination_id, 'approval_invalid', 'Approval is bound to a different audience or destination');
      usable(cand);
      invariant(cand.digest === approval.candidate_digest, 'approval_invalid', 'Approval is bound to a different candidate digest');
      const dest = await destinationRow(sql, ctx, approval.destination_id);
      if (dest.revision !== approval.destination_revision || dest.enabled !== true || !(dest.audiences as string[]).includes(cand.audience as string)) await fail('destination_changed', 'Destination changed since approval', false);
      const isPublic = dest.public === true || cand.audience_class === 'public';
      if (isPublic) {
        if (ctx.actor.kind === 'agent') throw new DomainError('forbidden', 'An agent cannot release to a public destination');
        invariant(approval.public === true && approval.accountability_decision_id !== null && approval.approved_by_kind === 'human', 'forbidden', 'Public release requires a human accountability decision and a human approval of this exact version');
        const d = (await sql.query(`select * from ${S}.accountability_decisions where id=$1 and candidate_id=$2`, [approval.accountability_decision_id, cand.id]))[0];
        invariant(d !== undefined && d.candidate_digest === cand.digest && d.decided_by_kind === 'human' && d.outcome === 'public_scrutiny_appropriate', 'forbidden', 'Public release requires a human accountability decision for this exact version');
      }
      await authorize(ctx, 'release:publish', uref('E12', 'candidate', cand.id as string));
      if (digest(await noticesFor(sql, ctx, cand)) !== approval.notices_digest) await fail('content_changed', 'Correction notices attached to this version changed since approval', false);
      // Rights are re-decided now: a withdrawal since approval blocks the release.
      let rights: RightsSnapshot[];
      try { rights = await rightsFor(ctx, cand, cand.audience as string, { name: dest.name as string, public: dest.public as boolean, licensed: dest.licensed as boolean }, true); }
      catch (error) {
        if (error instanceof DomainError && error.code === 'consent_denied') { await sql.tx((tx) => invalidateApprovals(tx, ctx, 'id=$4', [approval.id], 'rights_changed', null)); }
        throw error;
      }
      if (rightsDigest(rights) !== approval.rights_digest) await fail('rights_changed', 'Rights decision changed since approval', false);
      // Leak prevention is run again on the stored bytes.
      const matcher = await terms(ctx, input.protectedTerms, { subjects: cand.subjects as string[], sources: cand.sources as string[] });
      const supplied = new Set(matcher.hashes(cand.term_salt as string));
      invariant((cand.term_hashes as string[]).every((h) => supplied.has(h)), 'invalid_state', 'The protected terms this candidate was checked against must be supplied again (or through the protected-terms port) for the release-time leak check');
      const pkg = await loadPackage(ctx, cand);
      const manifestDoc = cand.manifest as { title: string; components: { label: string | null; altText: string | null }[] };
      const findings = await verifyStored(pkg.files, matcher, { title: manifestDoc.title, manifest: new TextDecoder().decode(pkg.manifestBytes) });
      if (sha256(pkg.manifestBytes) !== cand.digest) findings.push({ code: 'content_changed', path: 'manifest.json', field: 'bytes', detail: 'Stored manifest no longer matches the approved digest' });
      if (sha256(pkg.zip) !== cand.zip_sha256) findings.push({ code: 'content_changed', path: 'package.zip', field: 'bytes', detail: 'Stored archive no longer matches the approved digest' });
      if (findings.length > 0) await fail(findings.some((f) => f.code === 'content_changed') ? 'content_changed' : 'leak_prevention', `Release-time verification failed: ${[...new Set(findings.map((f) => `${f.code} at ${f.path}`))].slice(0, 5).join('; ')}`, true);
      const recipients = [...new Set((input.recipients ?? [dest.name as string]).map((r) => str(r, 'recipient', 300)))];
      invariant(recipients.length > 0 && recipients.length <= 500, 'invalid_input', 'Invalid recipients');
      for (const r of recipients) invariant(matcher.scan(r).length === 0, 'invalid_input', 'A recipient label contains a protected term');

      const releaseId = (existing?.id as string | undefined) ?? randomUUID();
      const kind = dest.kind as DestinationKind;
      let downloadUrl: string | undefined, expiresAt: string | undefined;
      const claimed = await sql.tx(async (tx) => {
        const row = existing === undefined
          ? (await tx.query(`insert into ${S}.releases (id, tenant_id, project_id, candidate_id, candidate_digest, approval_id, destination_id, audience, public, accountability_decision_id, state, recipients, released_by, released_by_kind, started_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'dispatching',$11::jsonb,$12,$13,$14) on conflict (approval_id) do nothing returning *`,
            [releaseId, ...sc(ctx), cand.id, cand.digest, approval.id, dest.id, cand.audience, isPublic, approval.accountability_decision_id, JSON.stringify(recipients), ctx.actor.id, ctx.actor.kind, ctx.now]))[0]
          : (await tx.query(`update ${S}.releases set state='dispatching', attempts=attempts+1, released_by=$2, released_by_kind=$3, started_at=$4, recipients=$5::jsonb where id=$1 and state='failed' returning *`, [releaseId, ctx.actor.id, ctx.actor.kind, ctx.now, JSON.stringify(recipients)]))[0];
        if (row === undefined) return null;
        if (kind === 'signed_download' || kind === 'email') {
          const ttl = Number((dest.config as { ttlSeconds?: number }).ttlSeconds ?? 86400);
          const linkId = randomUUID(); const exp = Math.floor(Date.parse(ctx.now) / 1000) + ttl;
          const base = rt.publicBaseUrl; if (base === undefined) throw new DomainError('unavailable', 'Public base URL for download links is not configured');
          downloadUrl = `${base.replace(/\/$/, '')}/v1/downloads/${linkId}.${exp}.${sign(linkId, exp)}`; expiresAt = new Date(exp * 1000).toISOString();
          await tx.query(`insert into ${S}.download_links (id, tenant_id, project_id, release_id, candidate_id, expires_at) values ($1,$2,$3,$4,$5,$6)`, [linkId, ...sc(ctx), releaseId, cand.id, expiresAt]);
        }
        await appendAudit(tx, S, ctx, 'release.dispatching', uref('E12', 'release', releaseId), { candidateDigest: cand.digest as string, destination: dest.id as string, attempt: row.attempts as number });
        return row;
      });
      if (claimed === null) return toRelease((await sql.query(`select * from ${S}.releases where approval_id=$1`, [approval.id]))[0] as R, true);
      const payload: DeliveryPayload = { releaseId, candidateId: cand.id as string, lineageId: cand.lineage_id as string, version: cand.version as number, digest: cand.digest as string, title: manifestDoc.title, kind: cand.kind as string, audience: cand.audience as string,
        zip: pkg.zip, zipSha256: cand.zip_sha256 as string, files: [...pkg.files.map((f) => ({ path: f.path, bytes: f.bytes })), { path: 'manifest.json', bytes: pkg.manifestBytes }], notices: await noticesFor(sql, ctx, cand), searchText: cand.index_text as string,
        scope: { tenantId: ctx.tenantId, projectId: ctx.projectId }, ...(downloadUrl === undefined ? {} : { downloadUrl }), ...(expiresAt === undefined ? {} : { expiresAt }) };
      let result: DeliveryResult; let unavailable: DomainError | null = null;
      try { result = await deliver(kind, rt, dest.config as Record<string, unknown>, payload); }
      catch (error) {
        // `unavailable` and validation errors are raised before any side effect; anything else has an unknown outcome.
        if (error instanceof DomainError) { unavailable = error; result = { outcome: 'failed', response: { error: error.code, message: error.message } }; }
        else result = { outcome: 'uncertain', response: { error: 'adapter_error' } };
      }
      const done = await sql.tx((tx) => finalize(tx, ctx, claimed, cand, dest, result, recipients));
      if (unavailable !== null) throw unavailable;
      if (done.state === 'delivered' && ports.useRegister !== undefined) {
        // Tell the consent engine where each decision was relied on, so a later withdrawal can find this distribution.
        const outcomes: Json[] = [];
        for (const r of rights) if (r.decisionRef !== null) {
          try { await ports.useRegister.recordUse(ctx, { decisionRef: r.decisionRef, subjects: cand.subjects as string[], output: uref('E12', 'release', releaseId), action: r.action, audience: cand.audience as string, destination: dest.name as string, idempotencyKey: `e12-release:${releaseId}:${r.action}` }); outcomes.push({ action: r.action, decisionRef: r.decisionRef, recorded: true }); }
          catch (error) { outcomes.push({ action: r.action, decisionRef: r.decisionRef, recorded: false, error: error instanceof DomainError ? error.code : 'error' }); }
        }
        await sql.query(`update ${S}.releases set use_register=$2::jsonb where id=$1`, [releaseId, JSON.stringify(outcomes)]);
      }
      return toRelease(done);
    },
    /** A human records what actually happened to an uncertain delivery. `not_delivered` permits a fresh attempt. */
    async reconcileRelease(ctx: ServiceContext, releaseId: string, input: { outcome: 'delivered' | 'not_delivered'; evidence: string }): Promise<ReleaseView> {
      requireCapability(ctx, 'release:publish'); human(ctx, 'Reconciling a delivery');
      invariant(input?.outcome === 'delivered' || input?.outcome === 'not_delivered', 'invalid_input', 'Invalid outcome');
      const evidence = str(input.evidence, 'evidence', 4000);
      const { release, cand, dest } = await releaseRow(sql, ctx, releaseId);
      invariant(release.state === 'uncertain', 'invalid_state', 'Only an uncertain release can be reconciled');
      return toRelease(await sql.tx((tx) => finalize(tx, ctx, release, cand, dest, { outcome: input.outcome === 'delivered' ? 'delivered' : 'failed', response: { reconciledBy: ctx.actor.id, evidence, previous: release.adapter_response as Json } }, release.recipients as string[])));
    },
    /** Asks the destination adapter whether an uncertain delivery arrived (where the adapter can tell). */
    async probeRelease(ctx: ServiceContext, releaseId: string): Promise<ReleaseView> { requireCapability(ctx, 'release:publish'); return probeRelease(ctx, releaseId); },
    async getRelease(ctx: ServiceContext, releaseId: string): Promise<ReleaseView> { requireCapability(ctx, 'release:read'); return toRelease((await releaseRow(sql, ctx, releaseId)).release); },
    async listReleases(ctx: ServiceContext, options: { candidateId?: string } = {}): Promise<ReleaseView[]> {
      requireCapability(ctx, 'release:read');
      const rows = await sql.query(`select r.* from ${S}.releases r join ${S}.candidates c on c.id=r.candidate_id where r.tenant_id=$1 and r.project_id=$2 and ($3::uuid is null or r.candidate_id=$3) and (c.compartment is null or c.compartment = any($4)) order by r.started_at desc limit 500`, [...sc(ctx), options.candidateId === undefined ? null : id(options.candidateId), [...ctx.compartments]]);
      return rows.map((r) => toRelease(r));
    },
    /** Public route handler: serves the archive for an unexpired, unrevoked signed link. All failures are `not_found`. */
    async download(token: string, now: Date = new Date()): Promise<{ bytes: Uint8Array; sha256: string; filename: string }> {
      const nf = (): never => { throw new DomainError('not_found', 'Not found'); };
      const parts = String(token).split('.');
      if (parts.length !== 3 || !UUID.test(parts[0] as string) || !/^\d{1,12}$/.test(parts[1] as string)) nf();
      const [linkId, expText, sig] = parts as [string, string, string];
      let expected: Buffer; try { expected = Buffer.from(sign(linkId, Number(expText))); } catch { return nf(); }
      const given = Buffer.from(sig);
      if (given.byteLength !== expected.byteLength || !timingSafeEqual(given, expected)) nf();
      if (Number(expText) * 1000 <= now.getTime()) nf();
      const row = (await sql.query(`update ${S}.download_links l set downloads=downloads+1 from ${S}.candidates c, ${S}.releases r where l.id=$1 and c.id=l.candidate_id and r.id=l.release_id and not l.revoked and l.expires_at > $2 and c.state not in ('withdrawn','leak_blocked') and not c.blocked and r.state='delivered' returning c.zip_key, c.zip_sha256, c.kind, c.version, c.digest`, [linkId, now.toISOString()]))[0];
      if (row === undefined) return nf();
      return { bytes: await store().get(row.zip_key as string), sha256: row.zip_sha256 as string, filename: `${row.kind as string}-v${row.version as number}-${(row.digest as string).slice(0, 12)}.zip` };
    },

    // ── distribution history ──
    async distributionHistory(ctx: ServiceContext, options: { candidateId?: string; lineageId?: string; needsFollowUp?: boolean } = {}): Promise<DistributionView[]> {
      requireCapability(ctx, 'release:read');
      const rows = await sql.query(`select d.* from ${S}.distributions d join ${S}.candidates c on c.id=d.candidate_id where d.tenant_id=$1 and d.project_id=$2 and ($3::uuid is null or d.candidate_id=$3) and ($4::uuid is null or d.lineage_id=$4) and ($5::boolean is not true or d.state='needs_follow_up') and (c.compartment is null or c.compartment = any($6)) order by d.created_at, d.id limit 2000`,
        [...sc(ctx), options.candidateId === undefined ? null : id(options.candidateId), options.lineageId === undefined ? null : id(options.lineageId), options.needsFollowUp ?? null, [...ctx.compartments]]);
      return rows.map(toDistribution);
    },
    /** Records a copy known to have been passed on by a recipient, so corrections can reach it. */
    async recordDownstreamCopy(ctx: ServiceContext, distributionId: string, input: { holder: string; note?: string }): Promise<DistributionView> {
      requireCapability(ctx, 'release:write');
      return sql.tx(async (tx) => {
        const parent = (await tx.query(`select * from ${S}.distributions where id=$1 and tenant_id=$2 and project_id=$3`, [id(distributionId), ...sc(ctx)]))[0];
        if (parent === undefined) throw new DomainError('not_found', 'Not found');
        await candidateRow(tx, ctx, parent.candidate_id);
        const follow = parent.state === 'needs_follow_up';
        const row = (await tx.query(`insert into ${S}.distributions (id, tenant_id, project_id, release_id, candidate_id, lineage_id, destination_id, recipient, kind, parent_id, state, follow_up_status, follow_up_reasons, history, created_at) values ($1,$2,$3,$4,$5,$6,$7,$8,'downstream_copy',$9,$10,$11,$12::jsonb,$13::jsonb,$14) returning *`,
          [randomUUID(), ...sc(ctx), parent.release_id, parent.candidate_id, parent.lineage_id, parent.destination_id, str(input?.holder, 'holder', 300), parent.id, follow ? 'needs_follow_up' : 'delivered', follow ? 'pending' : 'none', JSON.stringify(parent.follow_up_reasons), JSON.stringify([{ at: ctx.now, actorId: ctx.actor.id, action: 'downstream_copy_recorded', note: input.note ?? null }]), ctx.now]))[0] as R;
        await appendAudit(tx, S, ctx, 'distribution.downstream_copy', uref('E12', 'distribution', row.id as string), { parent: parent.id as string });
        return toDistribution(row);
      });
    },
    async updateFollowUp(ctx: ServiceContext, distributionId: string, input: { status: 'pending' | 'notified' | 'acknowledged' | 'replaced' | 'unreachable' | 'not_required'; note?: string }): Promise<DistributionView> {
      requireCapability(ctx, 'release:write');
      invariant(['pending', 'notified', 'acknowledged', 'replaced', 'unreachable', 'not_required'].includes(input?.status), 'invalid_input', 'Invalid follow-up status');
      return sql.tx(async (tx) => {
        const cur = (await tx.query(`select * from ${S}.distributions where id=$1 and tenant_id=$2 and project_id=$3 for update`, [id(distributionId), ...sc(ctx)]))[0];
        if (cur === undefined) throw new DomainError('not_found', 'Not found');
        await candidateRow(tx, ctx, cur.candidate_id);
        invariant(cur.state === 'needs_follow_up' || cur.state === 'follow_up_done', 'invalid_state', 'Distribution has no follow-up to track');
        const done = ['acknowledged', 'replaced', 'not_required', 'unreachable'].includes(input.status);
        const row = (await tx.query(`update ${S}.distributions set follow_up_status=$2, state=$3, history=history || $4::jsonb where id=$1 returning *`, [cur.id, input.status, done ? 'follow_up_done' : 'needs_follow_up', JSON.stringify([{ at: ctx.now, actorId: ctx.actor.id, action: `follow_up:${input.status}`, note: input.note ?? null }])]))[0] as R;
        const ref = uref('E12', 'distribution', cur.id as string);
        await appendAudit(tx, S, ctx, 'distribution.follow_up', ref, { status: input.status });
        await emitEvent(tx, S, ctx, 'release.follow_up_updated', ref, { status: input.status });
        return toDistribution(row);
      });
    },

    // ── correction, supersession, withdrawal ──
    /** Issues a correction: the corrected candidate supersedes the prior one, which is retained and marked superseded. */
    async issueCorrection(ctx: ServiceContext, input: { priorCandidateId: string; correctedCandidateId: string; reason: string; protectedTerms?: readonly string[] }): Promise<CorrectionView> {
      requireCapability(ctx, 'release:approve'); human(ctx, 'Issuing a correction notice');
      const reason = str(input?.reason, 'reason', 4000);
      const pre = await candidateRow(sql, ctx, input.priorCandidateId);
      const matcher = await terms(ctx, input.protectedTerms, { subjects: pre.subjects as string[], sources: pre.sources as string[] });
      const supplied = new Set(matcher.hashes(pre.term_salt as string));
      invariant((pre.term_hashes as string[]).every((h) => supplied.has(h)), 'invalid_state', 'The protected terms of the prior candidate must be supplied so the notice can be leak-checked');
      invariant(matcher.scan(reason).length === 0, 'invalid_input', 'The correction reason contains a protected term');
      return sql.tx(async (tx) => {
        const prior = await candidateRow(tx, ctx, input.priorCandidateId, true);
        const next = await candidateRow(tx, ctx, input.correctedCandidateId, true);
        invariant(next.supersedes === prior.id && next.lineage_id === prior.lineage_id, 'invalid_state', 'The corrected candidate must have been built as superseding the prior candidate');
        invariant(prior.state !== 'superseded' && prior.state !== 'leak_blocked' && next.state !== 'leak_blocked' && next.state !== 'withdrawn', 'invalid_state', 'Candidates are not in a state that allows correction');
        const a = new Map(((prior.manifest as { components: { path: string; sha256: string }[] }).components).map((c) => [c.path, c.sha256]));
        const b = new Map(((next.manifest as { components: { path: string; sha256: string }[] }).components).map((c) => [c.path, c.sha256]));
        const changed = [...b.keys()].filter((p) => a.has(p) && a.get(p) !== b.get(p)), added = [...b.keys()].filter((p) => !a.has(p)), removed = [...a.keys()].filter((p) => !b.has(p));
        const noticeText = [`CORRECTION NOTICE`, ``, `"${prior.title as string}" version ${prior.version as number} (package digest ${prior.digest as string}) has been superseded by version ${next.version as number} (package digest ${next.digest as string}).`, `Issued: ${ctx.now}`, ``, `Reason: ${reason}`, ``, `Changed files: ${changed.length === 0 ? 'none' : changed.join(', ')}`, `Added files: ${added.length === 0 ? 'none' : added.join(', ')}`, `Removed files: ${removed.length === 0 ? 'none' : removed.join(', ')}`, ``, `Version ${prior.version as number} should no longer be relied on or redistributed. Copies already distributed are being followed up.`].join('\n');
        const cid = randomUUID();
        await tx.query(`insert into ${S}.corrections (id, tenant_id, project_id, lineage_id, prior_candidate_id, corrected_candidate_id, corrected_version, reason, notice_text, issued_by, issued_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, [cid, ...sc(ctx), prior.lineage_id, prior.id, next.id, next.version, reason, noticeText, ctx.actor.id, ctx.now]);
        await tx.query(`update ${S}.candidates set state='superseded', superseded_by=$2 where id=$1`, [prior.id, next.id]);
        const ref = uref('E12', 'correction', cid); const priorRef = uref('E12', 'candidate', prior.id as string, prior.version as number);
        // The notice is new outgoing content: approvals of either version given before it existed no longer match.
        await invalidateApprovals(tx, ctx, 'candidate_id = any($4::uuid[])', [[prior.id, next.id]], 'superseded_or_notice_added', ref);
        const followUps = await flagDistributions(tx, ctx, prior.id as string, 'superseded_by_correction', ref);
        await appendAudit(tx, S, ctx, 'correction.issued', ref, { prior: prior.id as string, corrected: next.id as string, followUps: followUps.length });
        await emitEvent(tx, S, ctx, 'release.correction_issued', ref, { prior: priorRef, corrected: uref('E12', 'candidate', next.id as string, next.version as number), followUps: followUps.length });
        await emitEvent(tx, S, ctx, 'release.superseded', priorRef, { supersededBy: uref('E12', 'candidate', next.id as string, next.version as number), correction: ref });
        return { ref, id: cid, priorCandidateId: prior.id as string, correctedCandidateId: next.id as string, reason, noticeText, issuedBy: ctx.actor.id, issuedAt: ctx.now, followUps: followUps.map(toDistribution) };
      });
    },
    async listCorrections(ctx: ServiceContext, lineageId: string): Promise<Omit<CorrectionView, 'followUps'>[]> {
      requireCapability(ctx, 'release:read');
      const rows = await sql.query(`select k.* from ${S}.corrections k join ${S}.candidates c on c.id=k.prior_candidate_id where k.tenant_id=$1 and k.project_id=$2 and k.lineage_id=$3 and (c.compartment is null or c.compartment = any($4)) order by k.corrected_version`, [...sc(ctx), id(lineageId), [...ctx.compartments]]);
      return rows.map((r) => ({ ref: uref('E12', 'correction', r.id as string), id: r.id as string, priorCandidateId: r.prior_candidate_id as string, correctedCandidateId: r.corrected_candidate_id as string, reason: r.reason as string, noticeText: r.notice_text as string, issuedBy: r.issued_by as string, issuedAt: iso(r.issued_at) }));
    },
    /** Tracks a withdrawal/unpublish request. Copies already taken by recipients cannot be recalled; they are flagged for follow-up. */
    async requestWithdrawal(ctx: ServiceContext, input: { candidateId: string; reason: string; unpublish?: boolean }): Promise<WithdrawalView> {
      requireCapability(ctx, 'release:withdraw');
      const reason = str(input?.reason, 'reason', 4000);
      const pre = await candidateRow(sql, ctx, input.candidateId);
      invariant(pre.state !== 'leak_blocked', 'invalid_state', 'Candidate holds no package');
      const history: Json[] = [{ at: ctx.now, actorId: ctx.actor.id, action: 'requested', reason }];
      if (input.unpublish === true) {
        for (const r of await sql.query(`select r.id, d.kind, d.config, d.name from ${S}.releases r join ${S}.destinations d on d.id=r.destination_id where r.candidate_id=$1 and r.state in ('delivered','uncertain')`, [pre.id])) {
          let removed = false; let error: string | null = null;
          try { removed = await unpublish(r.kind as DestinationKind, rt, r.config as Record<string, unknown>, { scope: { tenantId: ctx.tenantId, projectId: ctx.projectId }, lineageId: pre.lineage_id as string, version: pre.version as number, digest: pre.digest as string, title: pre.title as string }, `This material was withdrawn on ${ctx.now}.`); }
          catch (e) { error = e instanceof DomainError ? e.code : 'error'; }
          history.push({ at: ctx.now, actorId: ctx.actor.id, action: removed ? 'unpublished' : 'manual_removal_required', release: r.id as string, destination: r.name as string, error });
        }
      }
      return sql.tx(async (tx) => {
        const cand = await candidateRow(tx, ctx, input.candidateId, true);
        const wid = randomUUID(); const ref = uref('E12', 'withdrawal', wid);
        const row = (await tx.query(`insert into ${S}.withdrawals (id, tenant_id, project_id, candidate_id, reason, state, history, requested_by, requested_at) values ($1,$2,$3,$4,$5,'requested',$6::jsonb,$7,$8) returning *`, [wid, ...sc(ctx), cand.id, reason, JSON.stringify(history), ctx.actor.id, ctx.now]))[0] as R;
        await tx.query(`update ${S}.candidates set state='withdrawn', blocked=true, stale_reasons=stale_reasons || $2::jsonb where id=$1`, [cand.id, JSON.stringify([{ kind: 'withdrawal', reason: 'withdrawal requested', cause: ref, blocked: true, at: ctx.now }])]);
        await tx.query(`update ${S}.download_links set revoked=true where candidate_id=$1`, [cand.id]);
        await invalidateApprovals(tx, ctx, 'candidate_id=$4', [cand.id], 'withdrawn', ref);
        const flagged = await flagDistributions(tx, ctx, cand.id as string, 'withdrawal_requested', ref);
        await appendAudit(tx, S, ctx, 'withdrawal.requested', ref, { candidate: cand.id as string, distributions: flagged.length });
        await emitEvent(tx, S, ctx, 'release.withdrawal_requested', ref, { candidate: uref('E12', 'candidate', cand.id as string, cand.version as number), distributions: flagged.length });
        return toWithdrawal(row);
      });
    },
    async updateWithdrawal(ctx: ServiceContext, withdrawalId: string, input: { state: 'in_progress' | 'completed' | 'partially_completed' | 'not_possible'; note: string }): Promise<WithdrawalView> {
      requireCapability(ctx, 'release:withdraw');
      invariant(['in_progress', 'completed', 'partially_completed', 'not_possible'].includes(input?.state), 'invalid_input', 'Invalid withdrawal state');
      return sql.tx(async (tx) => {
        const row = (await tx.query(`update ${S}.withdrawals set state=$4, history=history || $5::jsonb where id=$1 and tenant_id=$2 and project_id=$3 returning *`, [id(withdrawalId), ...sc(ctx), input.state, JSON.stringify([{ at: ctx.now, actorId: ctx.actor.id, action: input.state, note: str(input.note, 'note') }])]))[0];
        if (row === undefined) throw new DomainError('not_found', 'Not found');
        await candidateRow(tx, ctx, row.candidate_id);
        const v = toWithdrawal(row);
        await appendAudit(tx, S, ctx, 'withdrawal.updated', v.ref, { state: input.state });
        await emitEvent(tx, S, ctx, 'release.withdrawal_updated', v.ref, { state: input.state });
        return v;
      });
    },
    async listWithdrawals(ctx: ServiceContext, candidateId: string): Promise<WithdrawalView[]> {
      requireCapability(ctx, 'release:read'); const cand = await candidateRow(sql, ctx, candidateId);
      return (await sql.query(`select * from ${S}.withdrawals where candidate_id=$1 order by requested_at`, [cand.id])).map(toWithdrawal);
    },

    // ── standard surface ──
    async inspect(ctx: ServiceContext, ref: string): Promise<Inspection | null> {
      requireCapability(ctx, 'release:read');
      let p; try { p = parseUref(ref); } catch { return null; }
      if (p.engine !== 'E12' || !UUID.test(p.id)) return null;
      try {
        const audit = async (subject: string): Promise<Inspection['history']> => (await listAudit(sql, S, ctx, { subject, limit: 200 })).map((a) => ({ at: a.at, actorId: a.actorId, action: a.action, detail: a.detail }));
        if (p.kind === 'candidate') {
          const r = await candidateRow(sql, ctx, p.id);
          const c = toCandidate(r, await componentRows(sql, p.id));
          const approvals = (await sql.query(`select * from ${S}.approvals where candidate_id=$1 order by approved_at`, [p.id])).map(toApproval);
          const releases = await sql.query(`select id from ${S}.releases where candidate_id=$1`, [p.id]);
          const dists = await sql.query(`select id from ${S}.distributions where candidate_id=$1`, [p.id]);
          const decisions = (await sql.query(`select * from ${S}.accountability_decisions where candidate_id=$1 order by decided_at`, [p.id])).map(toDecision);
          const lineage = await sql.query(`select id, version, created_at, created_by, state from ${S}.candidates where lineage_id=$1 and tenant_id=$2 and project_id=$3 order by version`, [r.lineage_id, ...sc(ctx)]);
          return { ref: c.ref, kind: 'candidate', title: c.title, state: c.state, stale: c.stale, blocked: c.blocked, staleReasons: c.staleReasons.map((x) => `${(x as { kind: string }).kind}: ${(x as { reason: string }).reason}`),
            versions: lineage.map((l) => ({ revision: l.version as number, at: iso(l.created_at), actorId: l.created_by as string, summary: l.state as string })), sources: r.sources as string[],
            dependents: [...approvals.map((a) => a.ref), ...releases.map((x) => uref('E12', 'release', x.id as string)), ...dists.map((x) => uref('E12', 'distribution', x.id as string))],
            permissions: approvals.flatMap((a) => a.rights as unknown as Json[]), decisions: [...approvals, ...decisions] as unknown as Json[], history: await audit(c.ref),
            data: asJson({ digest: c.digest, kind: c.kind, audience: c.audience, audienceClass: c.audienceClass, components: c.components, leakReport: c.leakReport, review: c.review, supersedes: c.supersedes, supersededBy: c.supersededBy, subjects: r.subjects }) };
        }
        const simple = async (table: string, title: (r: R) => string, state: (r: R) => string, data: (r: R) => unknown, candidateCol: string | null): Promise<Inspection | null> => {
          const r = (await sql.query(`select * from ${S}.${table} where id=$1 and tenant_id=$2 and project_id=$3`, [p.id, ...sc(ctx)]))[0];
          if (r === undefined) return null;
          const cand = candidateCol === null ? null : await candidateRow(sql, ctx, r[candidateCol]);
          const subject = uref('E12', p.kind, p.id);
          return { ref: subject, kind: p.kind, title: title(r), state: state(r), stale: cand?.stale === true, blocked: cand?.blocked === true, staleReasons: [], versions: [], sources: cand === null ? [] : [uref('E12', 'candidate', cand.id as string, cand.version as number)], dependents: [], permissions: [], decisions: [], history: await audit(subject), data: asJson(data(r)) };
        };
        if (p.kind === 'approval') return await simple('approvals', () => 'Approval', (r) => r.state as string, toApproval, 'candidate_id');
        if (p.kind === 'release') return await simple('releases', () => 'Release', (r) => r.state as string, (r) => toRelease(r), 'candidate_id');
        if (p.kind === 'distribution') return await simple('distributions', (r) => `Distribution to ${r.recipient as string}`, (r) => r.state as string, toDistribution, 'candidate_id');
        if (p.kind === 'withdrawal') return await simple('withdrawals', () => 'Withdrawal request', (r) => r.state as string, toWithdrawal, 'candidate_id');
        if (p.kind === 'accountability_decision') return await simple('accountability_decisions', () => 'Accountability decision', (r) => r.outcome as string, toDecision, 'candidate_id');
        if (p.kind === 'correction') return await simple('corrections', () => 'Correction notice', () => 'issued', (r) => ({ reason: r.reason, noticeText: r.notice_text, prior: r.prior_candidate_id, corrected: r.corrected_candidate_id }), 'prior_candidate_id');
        if (p.kind === 'destination') return await simple('destinations', (r) => r.name as string, (r) => (r.enabled === true ? 'enabled' : 'disabled'), toDestination, null);
        return null;
      } catch (error) { if (error instanceof DomainError && error.code === 'not_found') return null; throw error; }
    },
    /** Searches candidate titles and the text of sanitized components only. */
    async search(ctx: ServiceContext, query: { q: string; limit?: number }): Promise<SearchHit[]> {
      requireCapability(ctx, 'release:read');
      const q = String(query?.q ?? '').trim().slice(0, 200);
      if (q === '') return [];
      const like = `%${q.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
      const rows = await sql.query(`select id, version, kind, title, state, index_text from ${S}.candidates where tenant_id=$1 and project_id=$2 and (compartment is null or compartment = any($3)) and (title ilike $4 or index_text ilike $4) order by created_at desc limit ${Math.min(Math.max(query.limit ?? 20, 1), 100)}`, [...sc(ctx), [...ctx.compartments], like]);
      return rows.map((r) => { const t = r.index_text as string; const at = t.toLowerCase().indexOf(q.toLowerCase()); return { ref: uref('E12', 'candidate', r.id as string, r.version as number), kind: r.kind as string, title: r.title as string, snippet: at < 0 ? '' : t.slice(Math.max(0, at - 60), at + q.length + 60).replace(/\s+/g, ' '), state: r.state as string }; });
    },
    async audit(ctx: ServiceContext, options: { after?: string; limit?: number; subject?: string } = {}): Promise<AuditRecord[]> { requireCapability(ctx, 'release:read'); return listAudit(sql, S, ctx, options); },
    async events(ctx: ServiceContext, options: { after?: string; limit?: number } = {}): Promise<EngineEvent[]> {
      requireCapability(ctx, 'release:events');
      return (await readEvents(sql, S, { ...options, tenantId: ctx.tenantId })).map((e) => ({ ...e, engine: 'E12' }));
    },
    /** Marks dependents stale or blocked, invalidates approvals and flags distributions. Never deletes; idempotent by eventId. */
    async applyUpstreamChange(ctx: ServiceContext, change: UpstreamChange): Promise<{ affected: string[] }> {
      if (!ctx?.capabilities?.includes('release:upstream')) requireCapability(ctx, 'release:write');
      invariant(change !== null && typeof change === 'object' && typeof change.eventId === 'string' && change.eventId.length > 0 && change.eventId.length <= 200 && manifest.consumes.includes(change.kind) && Array.isArray(change.refs) && change.refs.length <= 1000, 'invalid_input', 'Invalid upstream change');
      const refs = change.refs.map((r) => { parseUref(r); return r; });
      const reason = typeof change.reason === 'string' ? change.reason.slice(0, 500) : '';
      return sql.tx(async (tx) => {
        const first = await tx.query(`insert into ${S}.upstream_changes (tenant_id, project_id, event_id, affected, at) values ($1,$2,$3,'[]'::jsonb,$4) on conflict do nothing returning event_id`, [...sc(ctx), change.eventId, ctx.now]);
        if (first.length === 0) return { affected: ((await tx.query(`select affected from ${S}.upstream_changes where tenant_id=$1 and project_id=$2 and event_id=$3`, [...sc(ctx), change.eventId]))[0]?.affected ?? []) as string[] };
        const blocked = change.kind === 'permission_withdrawn' || change.kind === 'source_removed';
        const affected: string[] = [];
        const cands = await tx.query(`select c.id, c.version, c.sources, c.subjects, coalesce((select array_agg(distinct x) from ${S}.approvals a, unnest(a.permission_refs) x where a.candidate_id=c.id), '{}') as permission_refs,
          coalesce((select array_agg(distinct a.destination_id::text) from ${S}.approvals a where a.candidate_id=c.id and a.state='valid'), '{}') as destinations
          from ${S}.candidates c where c.tenant_id=$1 and c.project_id=$2 and c.state <> 'leak_blocked' for update of c`, sc(ctx));
        for (const c of cands) {
          const own = [uref('E12', 'candidate', c.id as string), ...(c.destinations as string[]).map((d) => uref('E12', 'destination', d))];
          const deps = [...(c.sources as string[]), ...(c.subjects as string[]), ...(c.permission_refs as string[]), ...own];
          if (!refs.some((r) => deps.some((d) => urefMatches(r, d)))) continue;
          const candRef = uref('E12', 'candidate', c.id as string, c.version as number);
          await markCandidate(tx, ctx, c.id as string, blocked, reason, change.eventId, change.kind);
          affected.push(candRef, ...await invalidateApprovals(tx, ctx, 'candidate_id=$4', [c.id], change.kind, change.eventId));
          affected.push(...(await flagDistributions(tx, ctx, c.id as string, change.kind, change.eventId)).map((d) => uref('E12', 'distribution', d.id as string)));
          if (blocked) await tx.query(`update ${S}.download_links set revoked=true where candidate_id=$1`, [c.id]);
          await appendAudit(tx, S, ctx, 'candidate.upstream_change', candRef, { kind: change.kind, cause: change.eventId, blocked });
        }
        await tx.query(`update ${S}.upstream_changes set affected=$4::jsonb where tenant_id=$1 and project_id=$2 and event_id=$3`, [...sc(ctx), change.eventId, JSON.stringify(affected)]);
        return { affected };
      });
    },
    async health(): Promise<{ ok: boolean; detail: Json }> {
      const tools: Record<string, string | null> = {};
      for (const t of ['exiftool', 'pandoc', 'soffice', 'pdftotext', 'pdftocairo', 'ffmpeg', 'convert']) tools[t] = await toolVersion(t);
      let db = true; try { await sql.query('select 1'); } catch { db = false; }
      const missing = Object.entries(tools).filter(([, v]) => v === null).map(([k]) => k);
      return { ok: db && deps.objects !== undefined && missing.length === 0, detail: { database: db, objectStore: deps.objects !== undefined, tools, missingTools: missing, useDecisionPort: ports.useDecision !== undefined, accountabilityPolicy: policy, jurisdictionPacks: [...packs.keys()], downloadLinks: rt.downloadSecret !== undefined && rt.publicBaseUrl !== undefined } };
    },
    /** Worker pass. Jobs only reconcile uncertain deliveries by probing the destination; no job can start a release. */
    runJobsOnce(worker: string): Promise<number> {
      return runJobsOnce(sql, S, { 'release.reconcile': async (job) => {
        const out = await probeRelease(job.ctx, (job.payload as { releaseId: string }).releaseId);
        if (out.state === 'uncertain') throw new Error('delivery outcome still unknown; a human must reconcile if the destination cannot tell');
        return { state: out.state };
      } }, { worker });
    },
  };

  function checkDestination(input: { name: string; kind: DestinationKind; audiences: readonly string[]; public?: boolean; licensed?: boolean; config?: Record<string, unknown> }): { name: string; kind: DestinationKind; audiences: string[]; public: boolean; licensed: boolean; config: Record<string, unknown> } {
    invariant(input !== null && typeof input === 'object' && typeof input.name === 'string' && /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,99}$/.test(input.name), 'invalid_input', 'Invalid destination name');
    invariant(DESTINATION_KINDS.includes(input.kind), 'invalid_input', 'Unknown destination kind');
    invariant(Array.isArray(input.audiences) && input.audiences.length > 0 && input.audiences.every((a) => typeof a === 'string' && Object.hasOwn(audiences, a)), 'invalid_input', 'Destination audiences must be configured audiences');
    const classes = input.audiences.map((a) => (audiences[a] as AudiencePolicy).class);
    const isPublic = input.kind === 'public_web' || input.public === true || classes.includes('public');
    invariant(!isPublic || classes.every((c) => c === 'public'), 'invalid_input', 'A public destination can serve only public audiences');
    const cfg = input.config ?? {};
    invariant(cfg !== null && typeof cfg === 'object' && !Array.isArray(cfg), 'invalid_input', 'Invalid destination settings');
    validateDestinationConfig(input.kind, cfg, rt);
    return { name: input.name, kind: input.kind, audiences: [...new Set(input.audiences)], public: isPublic, licensed: input.licensed === true, config: cfg };
  }
  async function settleReview(tx: Sql, ctx: ServiceContext, cand: R, negative: boolean): Promise<void> {
    const ref = uref('E12', 'candidate', cand.id as string, cand.version as number);
    if (negative) {
      await tx.query(`update ${S}.candidates set state='changes_requested' where id=$1`, [cand.id]);
      await invalidateApprovals(tx, ctx, 'candidate_id=$4', [cand.id], 'changes_requested', null);
      await appendAudit(tx, S, ctx, 'review.changes_requested', ref, {});
      await emitEvent(tx, S, ctx, 'release.changes_requested', ref, { digest: cand.digest as string });
      return;
    }
    const review = cand.review as { reviewers: string[]; participants: string[]; participantRequired: boolean };
    const ev = await tx.query(`select kind, actor_id from ${S}.review_events where candidate_id=$1 and candidate_digest=$2`, [cand.id, cand.digest]);
    const has = (kind: string, actor: string): boolean => ev.some((e) => e.kind === kind && e.actor_id === actor);
    const complete = review.reviewers.every((r) => has('reviewer_accepted', r)) && (!review.participantRequired || (review.participants.length > 0 && review.participants.every((p) => has('participant_accepted', p))));
    await appendAudit(tx, S, ctx, 'review.accepted', ref, { complete });
    if (complete && cand.state !== 'reviewed') {
      await tx.query(`update ${S}.candidates set state='reviewed' where id=$1`, [cand.id]);
      await emitEvent(tx, S, ctx, 'release.reviewed', ref, { digest: cand.digest as string });
    }
  }
  return engine satisfies StandardEngine;
}

// ───────────────────────────── HTTP ─────────────────────────────
export function routes(engine: ReleaseEngine): Route[] {
  const b = <T>(r: { body: unknown }): T => { invariant(r.body !== null && typeof r.body === 'object' && !Array.isArray(r.body), 'invalid_input', 'JSON object body required'); return r.body as T; };
  const j = (v: unknown): Json => v as Json;
  type B = Record<string, never>;
  return [
    ...standardRoutes(engine),
    { method: 'POST', path: '/v1/packages', handler: async (r) => ({ status: 201, json: await engine.buildPackage(r.ctx, b(r)) }) },
    { method: 'GET', path: '/v1/jurisdiction-packs', handler: async (r) => j(engine.listJurisdictionPacks(r.ctx)) },
    { method: 'GET', path: '/v1/candidates', handler: async (r) => j(await engine.listCandidates(r.ctx, { ...(r.query.get('kind') === null ? {} : { kind: r.query.get('kind') as string }), ...(r.query.get('state') === null ? {} : { state: r.query.get('state') as string }), ...(r.query.get('lineageId') === null ? {} : { lineageId: r.query.get('lineageId') as string }) })) },
    { method: 'GET', path: '/v1/candidates/:id', handler: async (r) => j(await engine.getCandidate(r.ctx, r.params.id as string)) },
    { method: 'GET', path: '/v1/candidates/:id/manifest', handler: async (r) => engine.getManifest(r.ctx, r.params.id as string) },
    { method: 'GET', path: '/v1/candidates/:id/component', handler: async (r) => { const c = await engine.getComponent(r.ctx, r.params.id as string, r.query.get('path') ?? ''); return { bytes: c.bytes, headers: { 'content-type': 'application/octet-stream', 'content-disposition': 'attachment', 'x-content-sha256': c.sha256 } }; } },
    { method: 'GET', path: '/v1/candidates/:id/package.zip', handler: async (r) => { const z = await engine.exportCandidateZip(r.ctx, r.params.id as string); return { bytes: z.bytes, headers: { 'content-type': 'application/zip', 'content-disposition': `attachment; filename="${z.filename}"`, 'x-content-sha256': z.sha256 } }; } },
    { method: 'POST', path: '/v1/candidates/:id/review', handler: async (r) => j(await engine.submitForReview(r.ctx, r.params.id as string, b(r))) },
    { method: 'GET', path: '/v1/candidates/:id/review', handler: async (r) => j(await engine.listReviewEvents(r.ctx, r.params.id as string)) },
    { method: 'POST', path: '/v1/candidates/:id/review/comments', handler: async (r) => ({ status: 201, json: await engine.addReviewComment(r.ctx, r.params.id as string, b(r)) }) },
    { method: 'POST', path: '/v1/candidates/:id/review/verdict', handler: async (r) => j(await engine.recordReview(r.ctx, r.params.id as string, b(r))) },
    { method: 'POST', path: '/v1/candidates/:id/review/participant', handler: async (r) => j(await engine.recordParticipantReview(r.ctx, r.params.id as string, b(r))) },
    { method: 'POST', path: '/v1/candidates/:id/accountability-decisions', handler: async (r) => ({ status: 201, json: await engine.recordAccountabilityDecision(r.ctx, r.params.id as string, b(r)) }) },
    { method: 'GET', path: '/v1/candidates/:id/accountability-decisions', handler: async (r) => j(await engine.listAccountabilityDecisions(r.ctx, r.params.id as string)) },
    { method: 'POST', path: '/v1/candidates/:id/professional-reviews', handler: async (r) => ({ status: 201, json: await engine.recordProfessionalReview(r.ctx, r.params.id as string, b(r)) }) },
    { method: 'POST', path: '/v1/releases/candidates', handler: async (r) => ({ status: 201, json: await engine.buildPackage(r.ctx, b(r)) }) },
    { method: 'POST', path: '/v1/releases/:id/authorize', handler: async (r) => ({ status: 201, json: await engine.approve(r.ctx, r.params.id as string, { ...b<B>(r), ...(typeof r.headers['idempotency-key'] === 'string' ? { idempotencyKey: r.headers['idempotency-key'] } : {}) } as never) }) },
    { method: 'GET', path: '/v1/releases/:id/approvals', handler: async (r) => j(await engine.listApprovals(r.ctx, r.params.id as string)) },
    { method: 'POST', path: '/v1/releases/:id/dispatch', handler: async (r) => { try { return j(await engine.release(r.ctx, r.params.id as string, b(r))); } catch (e) { if (e instanceof DomainError && e.code === 'unavailable') return { status: 503, json: { error: { code: 'unavailable', message: e.message } } }; throw e; } } },
    { method: 'POST', path: '/v1/releases/:id/withdraw', handler: async (r) => ({ status: 201, json: await engine.requestWithdrawal(r.ctx, { ...b<B>(r), candidateId: r.params.id as string } as never) }) },
    { method: 'GET', path: '/v1/releases/:id/withdrawals', handler: async (r) => j(await engine.listWithdrawals(r.ctx, r.params.id as string)) },
    { method: 'POST', path: '/v1/withdrawals/:id', handler: async (r) => j(await engine.updateWithdrawal(r.ctx, r.params.id as string, b(r))) },
    { method: 'GET', path: '/v1/dispatches', handler: async (r) => j(await engine.listReleases(r.ctx, r.query.get('candidateId') === null ? {} : { candidateId: r.query.get('candidateId') as string })) },
    { method: 'GET', path: '/v1/dispatches/:id', handler: async (r) => j(await engine.getRelease(r.ctx, r.params.id as string)) },
    { method: 'POST', path: '/v1/dispatches/:id/reconcile', handler: async (r) => j(await engine.reconcileRelease(r.ctx, r.params.id as string, b(r))) },
    { method: 'POST', path: '/v1/dispatches/:id/probe', handler: async (r) => j(await engine.probeRelease(r.ctx, r.params.id as string)) },
    { method: 'GET', path: '/v1/distributions', handler: async (r) => j(await engine.distributionHistory(r.ctx, { ...(r.query.get('candidateId') === null ? {} : { candidateId: r.query.get('candidateId') as string }), ...(r.query.get('lineageId') === null ? {} : { lineageId: r.query.get('lineageId') as string }), ...(r.query.get('needsFollowUp') === 'true' ? { needsFollowUp: true } : {}) })) },
    { method: 'POST', path: '/v1/distributions/:id/follow-up', handler: async (r) => j(await engine.updateFollowUp(r.ctx, r.params.id as string, b(r))) },
    { method: 'POST', path: '/v1/distributions/:id/downstream-copies', handler: async (r) => ({ status: 201, json: await engine.recordDownstreamCopy(r.ctx, r.params.id as string, b(r)) }) },
    { method: 'POST', path: '/v1/corrections', handler: async (r) => ({ status: 201, json: await engine.issueCorrection(r.ctx, b(r)) }) },
    { method: 'GET', path: '/v1/lineages/:id/corrections', handler: async (r) => j(await engine.listCorrections(r.ctx, r.params.id as string)) },
    { method: 'POST', path: '/v1/destinations', handler: async (r) => ({ status: 201, json: await engine.createDestination(r.ctx, b(r)) }) },
    { method: 'GET', path: '/v1/destinations', handler: async (r) => j(await engine.listDestinations(r.ctx)) },
    { method: 'POST', path: '/v1/destinations/:id', handler: async (r) => j(await engine.updateDestination(r.ctx, r.params.id as string, b(r))) },
    { method: 'GET', path: '/v1/downloads/:token', public: true, handler: async (r) => { const z = await engine.download(r.params.token as string); return { bytes: z.bytes, headers: { 'content-type': 'application/zip', 'content-disposition': `attachment; filename="${z.filename}"`, 'x-content-sha256': z.sha256 } }; } },
  ];
}
