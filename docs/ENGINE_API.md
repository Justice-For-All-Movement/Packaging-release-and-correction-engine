# E12 Packaging, Release and Correction — engine API

Service layer in `src/engine/` (package exports `./engine`, `./serve`, `./service-kit`). PostgreSQL schema `e12_release`.
Kit: `src/service-kit.ts` v1.0.1, sha256 `95475a907267ba1fdd54b557aabe5645c37add9788a5b2d0854d9accfd5d8ea5`;
`src/contracts.ts` is byte-identical to Identity's. The service layer imports no other engine's package.
The earlier library (`src/index.ts`, `store.ts`, `private-html.ts`, `identity-private-html-http.ts`) is kept unchanged
with its tests; the service layer does not build on it (it is bound to the Evidence package's database abstraction).

## Entry points

```ts
import { SCHEMA, manifest, migrations, migrate, createEngine, routes } from '@accountability/packaging-release/engine';
createEngine({ sql, objects?, ports?: { useDecision?, useRegister?, authorization?, evidence?, protectedTerms? }, config?: ReleaseConfig })
```

| Port | Type | Absent ⇒ |
|---|---|---|
| `useDecision` | kit `UseDecisionPort` (E11 `decide`; `decisionRef` used when returned) | approval/release of any candidate with rights subjects is **denied** (`consent_denied`) unless `config.standaloneRights: 'allow_without_port'`; originals are never included |
| `useRegister` | `{ recordUse(ctx, { decisionRef, subjects, output, action, audience?, destination?, idempotencyKey? }) }` (E11) | uses are not registered; outcome per decision is stored on the release (`use_register`) |
| `authorization` | kit `AuthorizationPort` | capability check on the token only; when present it is re-checked before export, accountability decision, approval and release |
| `evidence` | kit `EvidencePort` | `{ evidenceRef }` file inputs answer `unavailable`; supply `{ filename, mediaType, base64 }` |
| `protectedTerms` | `{ termsFor(ctx, { subjects, sources }): Promise<string[]> }` | callers pass `protectedTerms` on build and again on release |
| `objects` | kit `ObjectStore` | builds answer `unavailable` |

`ReleaseConfig`: `audiences` (name → `{ class: 'private'|'restricted'|'public', allowOriginals? }`; default
`internal_review` private; `legal_counsel`, `authority_referral`, `records_holder`, `licensed_partner` restricted; `public`
public), `accountabilityPolicy` (`'legal_first'` default | `'human_decision'`), `jurisdictionPacks`, `destinations`
(`DestinationRuntime`: `roots`, `httpHosts`, `allowInsecureHttp`, `secrets`, `smtp`, `sftp`, `downloadSecret`,
`publicBaseUrl`, `httpTimeoutMs`), `standaloneRights`, `professionalReviewCapability` (default `release:legal_review`),
`participantReviewRestriction` (default `participant_review`), `maxApprovalSeconds` (default 86400), `maxFileBytes`.

### Server

`npm run serve` (`src/engine/serve.ts`). Env: `DATABASE_URL`, `PORT` (8112), `HOST`, `IDENTITY_PUBLIC_KEYS` (JSON kid→PEM)
or `IDENTITY_JWKS_FILE`, `IDENTITY_ISSUER`, `OBJECT_STORE` / `OBJECT_STORE_PATH` / `S3_*`, `RELEASE_CONFIG_FILE` (JSON:
`audiences`, `accountabilityPolicy`, `destinations.{roots,httpHosts,smtp,sftp}`), `RELEASE_JURISDICTION_PACKS_DIR`,
`RELEASE_DESTINATION_ROOTS` (JSON name→directory), `RELEASE_HTTP_HOSTS` (comma-separated `host:port`),
`RELEASE_SECRET_<NAME>` (secret values; destinations reference `<name>` lower-cased), `RELEASE_DOWNLOAD_SECRET`,
`RELEASE_PUBLIC_BASE_URL`, `RELEASE_ACCOUNTABILITY_POLICY`, `RELEASE_STANDALONE_RIGHTS`, `RELEASE_MAX_APPROVAL_SECONDS`,
`RELEASE_MAX_BODY_BYTES`, `RELEASE_JOB_INTERVAL_MS`. The standalone server wires no ports (see table above).

Tools (spawned with argument arrays and timeouts, never a shell): `pandoc`, `soffice` (LibreOffice), `exiftool`,
`pdftotext`, `pdftocairo`, `convert` (ImageMagick), `ffmpeg`; `sftp` only for SFTP destinations. A missing tool yields
`unavailable`; `health()` lists `missingTools`.

## Capabilities

`release:read`, `release:write` (build, submit for review, follow-up, downstream copies), `release:review`,
`release:participant_review`, `release:legal_review` (exact match required, never via `release:*`), and the sensitive
`release:approve` (approval, accountability decision, correction notice), `release:publish` (release, reconcile, probe),
`release:export` (private archive download), `release:withdraw`, `release:admin` (destinations), `release:events`,
`release:upstream` (or `release:write`) for `applyUpstreamChange`.

Human-only (`actor.kind === 'human'`; agents and services get `forbidden`): `approve`, `recordAccountabilityDecision`,
`recordProfessionalReview`, `recordReview`, `recordParticipantReview`, `issueCorrection`, `reconcileRelease`,
`createDestination`, `updateDestination`. An `agent` actor can never call `release` for a public release. The database
enforces the same with CHECK constraints: an approval's `approved_by_kind` and a decision's `decided_by_kind` must be
`human`; a public approval or release row must reference an accountability decision; a public release row cannot have
`released_by_kind = 'agent'`.

## Service methods

```ts
buildPackage(ctx, input: BuildInput): Promise<CandidateView>            // input.kind selects the builder
buildEvidenceBundle | buildInvestigationReport | buildChronology | buildReferralPackage | buildRecordsRequest
  | buildLegalDraft | buildSourceCompanion | buildMediaPackage (ctx, input without `kind`): Promise<CandidateView>
listJurisdictionPacks(ctx): { id; name; version; documentTypes: string[]; authorities: { id; reviewed }[] }[]
getCandidate(ctx, candidateId): Promise<CandidateView>
listCandidates(ctx, { kind?, state?, lineageId?, limit? }?): Promise<CandidateView[]>      // components omitted
getManifest(ctx, candidateId): Promise<Json>
getComponent(ctx, candidateId, path): Promise<{ bytes; mediaType; sha256 }>
exportCandidateZip(ctx, candidateId): Promise<{ bytes; sha256; filename }>                   // private review export, audited; not a release
submitForReview(ctx, candidateId, { reviewers: string[]; participantReviewers?: string[] }): Promise<CandidateView>
addReviewComment(ctx, candidateId, { body; componentPath? }): Promise<ReviewEventView>
recordReview(ctx, candidateId, { candidateDigest; outcome: 'accepted'|'changes_requested'; body? }): Promise<CandidateView>
recordParticipantReview(ctx, candidateId, { candidateDigest; outcome: 'accepted'|'objected'; note? }): Promise<CandidateView>
listReviewEvents(ctx, candidateId): Promise<ReviewEventView[]>
recordAccountabilityDecision(ctx, candidateId, { candidateDigest; outcome: 'public_scrutiny_appropriate'|'not_appropriate'; assessment;
    legalRoutesConsidered?: { ref?; description; status }[]; noLegalRouteReason? }): Promise<AccountabilityDecisionView>
listAccountabilityDecisions(ctx, candidateId): Promise<AccountabilityDecisionView[]>
recordProfessionalReview(ctx, candidateId, { candidateDigest; reviewerName; reviewerRole; reviewedOn: 'YYYY-MM-DD'; statement? }): Promise<ProfessionalReview & { candidateId }>
createDestination(ctx, { name; kind; audiences: string[]; public?; licensed?; config? }): Promise<DestinationView>
updateDestination(ctx, destinationId, { audiences?; public?; licensed?; config?; enabled? }): Promise<DestinationView>
listDestinations(ctx): Promise<DestinationView[]>
approve(ctx, candidateId, { candidateDigest; audience; destinationId; expiresAt; accountabilityDecisionId?; idempotencyKey? }): Promise<ApprovalView>
listApprovals(ctx, candidateId): Promise<ApprovalView[]>
release(ctx, candidateId, { approvalId; audience; destinationId; recipients?: string[]; protectedTerms?: string[] }): Promise<ReleaseView>
reconcileRelease(ctx, releaseId, { outcome: 'delivered'|'not_delivered'; evidence }): Promise<ReleaseView>
probeRelease(ctx, releaseId): Promise<ReleaseView>
getRelease(ctx, releaseId): Promise<ReleaseView>;  listReleases(ctx, { candidateId? }?): Promise<ReleaseView[]>
download(token, now?): Promise<{ bytes; sha256; filename }>                                  // no ctx: signed link is the credential
distributionHistory(ctx, { candidateId?; lineageId?; needsFollowUp? }?): Promise<DistributionView[]>
recordDownstreamCopy(ctx, distributionId, { holder; note? }): Promise<DistributionView>
updateFollowUp(ctx, distributionId, { status: 'pending'|'notified'|'acknowledged'|'replaced'|'unreachable'|'not_required'; note? }): Promise<DistributionView>
issueCorrection(ctx, { priorCandidateId; correctedCandidateId; reason; protectedTerms? }): Promise<CorrectionView>   // includes followUps
listCorrections(ctx, lineageId): Promise<Omit<CorrectionView,'followUps'>[]>
requestWithdrawal(ctx, { candidateId; reason; unpublish? }): Promise<WithdrawalView>
updateWithdrawal(ctx, withdrawalId, { state: 'in_progress'|'completed'|'partially_completed'|'not_possible'; note }): Promise<WithdrawalView>
listWithdrawals(ctx, candidateId): Promise<WithdrawalView[]>
inspect | search | audit | events | applyUpstreamChange | health                             // StandardEngine
runJobsOnce(worker): Promise<number>                                                          // only `release.reconcile` (probe); never releases
```

Refs: `E12:candidate:<id>@<version>`, `E12:approval:<id>`, `E12:release:<id>`, `E12:distribution:<id>`,
`E12:correction:<id>`, `E12:withdrawal:<id>`, `E12:accountability_decision:<id>`, `E12:destination:<id>@<revision>`,
`E12:professional_review:<id>`. `inspect` supports all but the last.

### Builders (`BuildInput`, see `src/engine/builders.ts` for exact types)

Common fields: `title`, `audience`, `language?` (`en`), `formats?` (`['html','pdf']`; also `'docx'`),
`protectedTerms?`, `protectedSourceRefs?` (cited as "protected source", never written to documents or manifest),
`subjects?` (rights subjects, urefs), `participantReviewers?`, `supersedes?` (candidate id → same lineage, version+1),
`compartment?`, `idempotencyKey?`. Files are `{ filename, mediaType, base64 }` or `{ evidenceRef }`.

| kind | input | output components |
|---|---|---|
| `evidence_bundle` | `items[]` (`ref`, `label`, `custody[]`, `redacted?`, `original?`, `includeOriginal?`, `thumbnail?`, `altText?`) | `index.{md,html,pdf}` with the SHA-256 of each **released** file and a custody summary, `custody.json`, `evidence/NNN-name`, regenerated `thumbnails/` |
| `investigation_report`, `chronology` | `package` (E08 package JSON supplied by the caller: `findings[]` with `status` established/disputed/unknown, `sources[]`, `limitations[]`; `chronology[]`; `openQuestions[]`) | `report.*` + `findings.json`, or `chronology.*` + `chronology.json`. An established finding or entry without a source is refused |
| `referral_package` | `recipient`, `contact`, `coverSummary`, `package`, `items?` | `cover.*`, `chronology.*`, `evidence-index.*`, `custody.json`, evidence files |
| `records_request` | `jurisdictionPackId`, `requester`, `recipient`, `package?` (open questions → records sought), `recordsSought?`, `values?`, `professionalReviewId?` | `records-request.*`, `legal-status.json` |
| `legal_draft` | `jurisdictionPackId`, `documentType`, `package`, `values?`, `professionalReviewId?` | `draft.*`, `legal-status.json` |
| `source_companion` | `sources[]` (`ref`, `supports[]`, `title?`, `publisher?`, `date?`, `url?`, `protected?`, `publicLabel?`) | `sources.*`, `sources.json` |
| `media_package` | `renders[]` (E10 render `ref`, `file`, `manifest?`, `captions[]`, `altText?`), `credits?`, `disclosures?`, `rightsSummary?` | `media/`, `captions/NNN.<lang>.<vtt|srt>`, `render-manifests/`, `index.*`, `credits.json`, `rights-summary.json`, thumbnails |

Every candidate has `manifest.json` (schema `e12.manifest/1`): each component's path, role, class, media type,
SHA-256, size, source urefs, basis and labels; all sources; rights decisions as evaluated at build; the redaction
manifest; leak-scan summary and tool versions; builder-specific data (`legal`, `basisLabels`, credits …). The candidate
digest is the SHA-256 of `manifest.json`. The archive is a ZIP written by `zipWrite` (deflate, sorted entries, fixed
timestamps). Bytes live in the object store under `<tenant>/<project>/candidates/<id>/…`.

Determinism: Markdown, HTML, DOCX, JSON, manifest and ZIP are byte-reproducible for the same input and tool versions
(tested). **PDF output from LibreOffice is not byte-reproducible**, so two builds that include PDF have different digests.

Jurisdiction packs (deployment data; `validatePack`): `id`, `name`, `version`, `assumptions[]`, `authorities[]`
(`id`, `citation`, `reviewed`, …), `documentTypes{}` (`title`, `placeholders[]`, `assumptions[]`, `sections[]` with
`body` templates). Tokens: `{{var:name}}`, `{{facts}}` / `{{facts:established|disputed|unknown}}`, `{{authority:id}}`,
`{{authorities}}`, `{{records_sought}}`, `{{requester}}`, `{{recipient}}`. An authority id not in the pack renders
`[authority to be identified by a qualified reviewer]` and is listed in `legal.unresolved_authorities`; an unreviewed
one is rendered with an "unreviewed" marker and also listed. Every section carries the stamp
`DRAFT — generated for review; not legal advice; not filed; not reviewed by a legal professional` unless
`professionalReviewId` names a recorded review whose content digest equals this build's content digest; the stamp then
names the reviewer, role and date and still says "not legal advice; not filed". The stamp is per section and at the
top of the document; **it is not a page header/footer**. `values` are caller-supplied text and are not vetted: a caller
could type a citation into a value. Only `examples/jurisdiction-packs/example-republic.json` (fictional) ships.

### Leak prevention (build time, and again at release)

1. Allow-list: file kind is taken from content sniffing and must match the extension (text/markdown/html/json/csv/vtt/srt,
   PDF, JPEG/PNG/GIF/WebP, MP4/MOV/M4A/WebM/MKV/MP3/WAV/OGG; DOCX only when generated here). Originals are dropped unless
   the audience has `allowOriginals` **and** the consent port allows it. Caller-supplied thumbnails are always discarded.
2. Metadata: supplied PDFs are re-rendered with `pdftocairo` (exiftool's PDF edits are reversible), then all metadata is
   removed with `exiftool`; images with `exiftool -all=`; media by `ffmpeg` stream copy without metadata/chapters. Each
   file is read back with `exiftool` and any residual identifying tag or protected term fails the candidate.
3. Thumbnails are regenerated from the sanitized bytes (`convert` / `ffmpeg`).
4. Protected terms are matched (case-, punctuation- and whitespace-insensitive; compact match for file names) against
   file names, labels, alt text, manifest fields, document text (`pdftotext` in two orders, DOCX XML, HTML, captions) and
   raw bytes (UTF-8/UTF-16). Any hit fails the candidate: state `leak_blocked`, located findings (path, field, line,
   term ordinal — never the term), **no bytes stored**. Terms are kept only as salted hashes.
5. At release the stored bytes are re-hashed against the manifest and re-scanned; the caller (or the port) must supply
   terms covering the stored hashes. Any finding blocks the candidate and invalidates its approvals.
6. Search: `index_text` (engine search) and the public site's `search-index.json` hold only text of sanitized components.

Not covered: text visible only in image or video pixels (no OCR), audio content, steganography, and terms the caller did
not supply. PDF tagging/links of *supplied* PDFs are lost by the rewrite. EXIF orientation is removed with the rest.

### Workflow and invalidation

`built` → `submitForReview` → `in_review` → every named reviewer (and every named participant when a consent
restriction or the builder requires it) accepts the exact digest → `reviewed` → `approve` → `release`.
`changes_requested`/objection is resolved by building a superseding candidate (candidates are immutable).

`approve` binds candidate digest + audience + destination id and revision + rights decisions (`publish` for public,
`reproduce` otherwise, plus `license` for licensed destinations, for all subjects) + correction notices, with an expiry.
`release` re-checks all of it, re-decides consent, re-runs leak verification, then performs one delivery.
`approval_invalid` is returned (and the approval marked invalid where it is the approval that is wrong) when: digest
differs, stored bytes changed, candidate stale/blocked/superseded/withdrawn, audience or destination differs or the
destination changed, rights decision changed, notices changed, or the approval expired. Consent deny ⇒ `consent_denied`.

Public release (destination `public`/`public_web` or audience class public) additionally requires a
`recordAccountabilityDecision` for the exact digest with outcome `public_scrutiny_appropriate`; under `legal_first` it
must list the legal-route records considered or state why no legal route exists. Both policies require the human record.

Idempotency: one release row per approval. Delivered ⇒ a retry returns it (`replayed: true`). Adapter outcome unknown ⇒
`uncertain` (distribution `uncertain`, reconcile job queued); a retry never re-sends; `probeRelease` / the job asks the
destination where it can tell, otherwise a human calls `reconcileRelease`. `failed` (nothing left the system) may be
retried with the same approval. Two concurrent `release` calls for one approval: the second marks the in-flight attempt
`uncertain` rather than sending again (conservative; the first call's result then stands).

`issueCorrection`: the corrected candidate (built with `supersedes`) replaces the prior one, which is retained and marked
`superseded`; a notice is generated (versions, digests, reason, changed/added/removed files), stored, and delivered as
`correction-notices/` with later releases of the lineage; approvals of both versions are invalidated (the notice is new
outgoing content); every distribution of the prior version becomes `needs_follow_up` and is returned. The corrected
version still needs its own review, decision (if public) and approval.

`requestWithdrawal`: candidate `withdrawn`, approvals invalid, download links revoked, distributions flagged; with
`unpublish: true` the version folder is removed from `local_directory`/`public_web` destinations (public site shows a
withdrawal notice); other destinations are recorded as `manual_removal_required`. Copies already taken cannot be recalled.

### Destinations

| kind | config | status |
|---|---|---|
| `local_directory` (review portal) | `{ root }` (name from `destinations.roots`) | implemented, tested |
| `signed_download` | `{ ttlSeconds? }`; link `GET /v1/downloads/<id>.<exp>.<hmac>` | implemented, tested (HTTP, expiry, tamper, revocation) |
| `http_put` | `{ url, secretRef? }`; host must be in `httpHosts`; https unless `allowInsecureHttp`; no redirects | implemented, tested against a controlled local server only |
| `webhook` | `{ url, secretRef? }` POST JSON with base64 archive | implemented, tested against a controlled local server only |
| `email` | `{ smtp, to[], ttlSeconds? }`; sends a signed link, never the package (nodemailer 6.9.16) | implemented, tested against a controlled local SMTP sink; not verified against a live provider |
| `sftp` | `{ server }` (from `destinations.sftp`; system `sftp` client, strict host keys) | implemented, **not tested, not verified** (no client/server on the build machine) |
| `public_web` | `{ root }`; writes `<root>/<tenant>/<project>/<lineage>/v<N>-<digest16>/`, `index.html`, `search-index.json` | implemented, tested on a local directory; serving that directory is the deployment's job |

## HTTP routes (bearer token; `routes(engine)`)

Standard: `GET /healthz`, `GET /v1/manifest`, `GET /v1/inspect?ref=`, `GET /v1/search?q=`, `GET /v1/audit`,
`GET /v1/events`, `POST /v1/upstream-changes`.

`POST /v1/packages` and `POST /v1/releases/candidates` (build; 201) · `GET /v1/jurisdiction-packs` ·
`GET /v1/candidates` · `GET /v1/candidates/:id` · `GET …/manifest` · `GET …/component?path=` · `GET …/package.zip` ·
`POST|GET /v1/candidates/:id/review` · `POST …/review/comments` · `POST …/review/verdict` · `POST …/review/participant` ·
`POST|GET /v1/candidates/:id/accountability-decisions` · `POST /v1/candidates/:id/professional-reviews` ·
`POST /v1/releases/:id/authorize` (approve; `Idempotency-Key` header) · `GET /v1/releases/:id/approvals` ·
`POST /v1/releases/:id/dispatch` (release; 503 when an adapter is unavailable) · `POST /v1/releases/:id/withdraw` ·
`GET /v1/releases/:id/withdrawals` · `POST /v1/withdrawals/:id` · `GET /v1/dispatches` · `GET /v1/dispatches/:id` ·
`POST /v1/dispatches/:id/reconcile` · `POST /v1/dispatches/:id/probe` · `GET /v1/distributions` ·
`POST /v1/distributions/:id/follow-up` · `POST /v1/distributions/:id/downstream-copies` · `POST /v1/corrections` ·
`GET /v1/lineages/:id/corrections` · `POST|GET /v1/destinations` · `POST /v1/destinations/:id` ·
`GET /v1/downloads/:token` (public; signed link). In `/v1/releases/:id/…`, `:id` is the candidate id.

## Events (outbox; subject)

`release.candidate_built`, `release.candidate_blocked`, `release.candidate_stale`, `release.review_submitted`,
`release.changes_requested`, `release.reviewed`, `release.superseded` → candidate · `release.accountability_decided` →
accountability_decision · `release.professional_review_recorded` → professional_review · `release.approved`,
`release.approval_invalidated` → approval · `release.released`, `release.delivery_uncertain`, `release.delivery_failed` →
release · `release.distribution_needs_follow_up`, `release.follow_up_updated` → distribution ·
`release.correction_issued` → correction · `release.withdrawal_requested`, `release.withdrawal_updated` → withdrawal ·
`release.destination_changed` → destination. Payloads carry ids, digests, `reason` and `cause`, never content.
(The catalog names `package.created`, `release.authorized`, `release.dispatched`, `withdrawal.requested`; the names above
are the ones emitted.)

`applyUpstreamChange` (idempotent by `eventId`; kinds `content_changed`, `render_changed`, `claim_changed`,
`source_corrected`, `source_superseded`, `source_removed`, `permission_withdrawn`, `permission_changed`, `rights_changed`,
`audience_changed`): a candidate matches when a ref matches (`urefMatches`) any of its sources (including protected
ones), rights subjects, the permission/decision refs of its approvals, its own uref, or the destination of one of its
valid approvals. Matched candidates become `stale` (`blocked` too for `permission_withdrawn` / `source_removed`, which
also revokes download links); valid approvals become invalid; delivered/uncertain distributions become
`needs_follow_up`. Nothing is deleted. Returns the urefs of affected candidates, approvals and distributions.

## Tests

`tests/engine*.test.ts` run on real PostgreSQL (`TEST_DATABASE_URL`; skipped visibly when unset) with real files and
tools: openable outputs (`pdfinfo`, `pdftotext`, `unzip -t`, `pandoc`, `ffprobe`), determinism, exact-version approval,
public gate (human decision, human approval, agents refused, DB constraints, expiry, worker does not release), consent
deny / release-time re-check / participant review / use register, leak tests (PDF metadata, EXIF, caption, file name,
alt text, title, document text, PDF body, disguised type, thumbnail source, originals, release-time tamper),
legal drafts (unresolved authorities, no authority outside the pack, stamp, professional review bound to content),
upstream invalidation for every kind, correction/supersession/follow-up, withdrawal, adapters (uncertain, probe,
human reconcile, refused connection, webhook, email sink), tenant/project/compartment isolation, HTTP end to end
including signed-link expiry, and the standalone server.

## Not implemented / not verified

- No live provider verified: HTTP, webhook and email adapters ran only against controlled local servers; SFTP not run.
- PDF bytes are not reproducible; the draft stamp is per section, not a page header.
- No OCR of images/video frames and no audio transcription in the leak scan; no DOCX/ODT/XLSX input files accepted.
- Engine search covers every sanitized candidate in scope (released or not); only the `public_web` search index is
  restricted to the released version.
- Public-site hosting, TLS and takedown at third parties are outside this engine; `unpublish` only removes files from
  directories this engine wrote.
- Release dispatch is synchronous in the calling request (durable intent row + reconciliation), not a queued job.
- Catalog items not built: redaction-diff/preview UI data beyond the manifest and redaction manifest; "licensed
  delivery" is a destination flag that adds a `license` use decision, with no licence-term enforcement.
- No independent security review.
