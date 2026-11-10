import test from 'node:test';
import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { zipRead } from '../src/engine/index.ts';
import type { ReleaseEngine } from '../src/engine/index.ts';
import type { ServiceContext } from '../src/service-kit.ts';
import { as, code, ctx, events, FakeConsent, needsPg, PKG, PROTECTED, reviewed, soon, withEngine } from './helpers/engine.ts';

const companion = (engine: ReleaseEngine, c: ServiceContext = ctx(), extra: Record<string, unknown> = {}) => engine.buildSourceCompanion(c, {
  title: 'Sources for the harbour story', audience: 'public', formats: ['html'], protectedTerms: [PROTECTED], protectedSourceRefs: ['E05:evidence_version:witness-9@1'],
  sources: [
    { ref: 'E05:evidence_version:doc-1@1', title: 'Dredging contract signature page', publisher: 'Harbour authority', date: '2025-03-03', url: 'https://records.example.org/contract', supports: ['The contract was signed on 3 March 2025.'] },
    { ref: 'E05:evidence_version:witness-9@1', title: `Interview with ${PROTECTED}`, supports: ['A delivery took place at night.'], publicLabel: 'A dock worker who asked not to be named' },
  ], ...extra,
});

test('public release needs a recorded human accountability decision and an exact-version human approval; agents and timers cannot publish', needsPg, async () => {
  await withEngine(async (h) => {
    const { engine } = h;
    const c = await companion(engine);
    assert.equal(c.state, 'built', JSON.stringify(c.leakReport));
    // protected source: no title, no reference, in documents, manifest or search
    const zip = zipRead((await engine.exportCandidateZip(ctx(), c.id)).bytes);
    for (const e of zip) { const t = Buffer.from(e.bytes).toString('utf8'); assert.doesNotMatch(t, /Quenby|witness-9/i, e.path); }
    const md = Buffer.from(zip.find((e) => e.path === 'sources.md')?.bytes as Uint8Array).toString('utf8');
    assert.match(md, /A dock worker who asked not to be named/); assert.match(md, /Identity withheld/); assert.match(md, /E05:evidence_version:doc-1@1/); assert.match(md, /contract was signed/);
    const site = await engine.createDestination(ctx(), { name: 'public site', kind: 'public_web', audiences: ['public'], config: { root: 'site' } });
    assert.equal(site.public, true);
    assert.equal(await code(engine.createDestination(ctx(), { name: 'mixed', kind: 'public_web', audiences: ['public', 'legal_counsel'], config: { root: 'site' } })), 'invalid_input');
    assert.equal(await code(engine.createDestination(ctx(), { name: 'escape', kind: 'local_directory', audiences: ['legal_counsel'], config: { root: '../../etc' } })), 'invalid_input');
    assert.equal(await code(engine.createDestination(ctx({ actor: { id: 'bot', kind: 'agent', roles: [] } }), { name: 'bot site', kind: 'public_web', audiences: ['public'], config: { root: 'site' } })), 'forbidden');
    const digest = await reviewed(engine, c.id);
    const approveInput = { candidateDigest: digest, audience: 'public', destinationId: site.id, expiresAt: soon() };
    assert.equal(await code(engine.approve(ctx(), c.id, approveInput)), 'forbidden', 'no decision');
    const decision = { candidateDigest: digest, outcome: 'public_scrutiny_appropriate' as const, assessment: 'The complaint to the oversight body was lodged in March and closed without examination; the referral was declined. Public scrutiny is now appropriate.', legalRoutesConsidered: [{ ref: 'E03:thread:oversight-1', description: 'Complaint to the oversight body', status: 'closed without examination' }, { description: 'Referral to the prosecutor', status: 'declined' }] };
    for (const kind of ['agent', 'service'] as const) assert.equal(await code(engine.recordAccountabilityDecision(ctx({ actor: { id: 'bot', kind, roles: ['owner'] } }), c.id, decision)), 'forbidden');
    assert.equal(await code(engine.recordAccountabilityDecision(ctx({ capabilities: ['release:*', 'release:publish'] }), c.id, decision)), 'forbidden');
    assert.equal(await code(engine.recordAccountabilityDecision(ctx(), c.id, { ...decision, legalRoutesConsidered: [] })), 'invalid_input', 'legal-first policy needs the legal route assessment');
    assert.equal(await code(engine.recordAccountabilityDecision(ctx(), c.id, { ...decision, assessment: '  ' })), 'invalid_input');
    assert.equal(await code(engine.recordAccountabilityDecision(ctx(), c.id, { ...decision, candidateDigest: 'a'.repeat(64) })), 'approval_invalid');
    const no = await engine.recordAccountabilityDecision(ctx(), c.id, { ...decision, outcome: 'not_appropriate', assessment: 'The oversight complaint is still pending.' });
    assert.equal(await code(engine.approve(ctx(), c.id, { ...approveInput, accountabilityDecisionId: no.id })), 'forbidden');
    const other = await companion(engine, ctx(), { title: 'Another companion' });
    const otherDigest = await reviewed(engine, other.id);
    const otherYes = await engine.recordAccountabilityDecision(ctx(), other.id, { ...decision, candidateDigest: otherDigest });
    assert.equal(await code(engine.approve(ctx(), c.id, { ...approveInput, accountabilityDecisionId: otherYes.id })), 'forbidden', 'decision for another candidate');
    const yes = await engine.recordAccountabilityDecision(as('editor-in-chief'), c.id, decision);
    assert.equal(yes.decidedBy, 'editor-in-chief'); assert.equal(yes.legalRoutesConsidered.length, 2); assert.equal(yes.policy, 'legal_first'); assert.ok(Date.parse(yes.decidedAt) > 0);
    for (const kind of ['agent', 'service'] as const) assert.equal(await code(engine.approve(ctx({ actor: { id: 'bot', kind, roles: ['owner'] } }), c.id, { ...approveInput, accountabilityDecisionId: yes.id })), 'forbidden', `${kind} cannot approve`);
    const approval = await engine.approve(ctx(), c.id, { ...approveInput, accountabilityDecisionId: yes.id });
    assert.equal(approval.public, true); assert.equal(approval.accountabilityDecisionId, yes.id);
    // nothing but an explicit release call publishes: the worker loop does nothing, and an agent cannot dispatch
    assert.equal(await engine.runJobsOnce('w'), 0);
    assert.deepEqual(await engine.listReleases(ctx()), []); assert.equal(existsSync(join(h.dir, 'site')), false);
    assert.equal(await code(engine.release(ctx({ actor: { id: 'bot', kind: 'agent', roles: ['owner'] } }), c.id, { approvalId: approval.id, audience: 'public', destinationId: site.id, protectedTerms: [PROTECTED] })), 'forbidden');
    // the database itself refuses a public release or approval without the human records
    await assert.rejects(h.sql.query(`insert into e12_release.releases (id, tenant_id, project_id, candidate_id, candidate_digest, approval_id, destination_id, audience, public, state, released_by, released_by_kind, started_at) values (gen_random_uuid(),'t1','p1',$1,$2,$3,$4,'public',true,'delivered','x','human',now())`, [c.id, digest, approval.id, site.id]), /check/);
    await assert.rejects(h.sql.query(`insert into e12_release.approvals (id, tenant_id, project_id, candidate_id, candidate_digest, audience, destination_id, destination_revision, public, rights, rights_digest, notices_digest, approved_by, approved_by_kind, approved_at, expires_at, accountability_decision_id) values (gen_random_uuid(),'t1','p1',$1,$2,'public',$3,1,true,'[]','x','x','bot','agent',now(),now(),$4)`, [c.id, digest, site.id, yes.id]), /check/);
    await assert.rejects(h.sql.query(`insert into e12_release.accountability_decisions (id, tenant_id, project_id, candidate_id, candidate_digest, outcome, assessment, legal_routes, policy, decided_by, decided_by_kind, decided_at) values (gen_random_uuid(),'t1','p1',$1,$2,'public_scrutiny_appropriate','x','[]','legal_first','bot','agent',now())`, [c.id, digest]), /check/);
    // expired approval never releases
    const expired = ctx({ now: new Date(Date.now() + 2 * 3600 * 1000).toISOString() });
    const c2 = await companion(engine, ctx(), { title: 'Expiring companion' }); const d2 = await reviewed(engine, c2.id);
    const y2 = await engine.recordAccountabilityDecision(ctx(), c2.id, { ...decision, candidateDigest: d2 });
    const a2 = await engine.approve(ctx(), c2.id, { candidateDigest: d2, audience: 'public', destinationId: site.id, expiresAt: soon(600), accountabilityDecisionId: y2.id });
    assert.equal(await code(engine.release(expired, c2.id, { approvalId: a2.id, audience: 'public', destinationId: site.id, protectedTerms: [PROTECTED] })), 'approval_invalid');
    assert.equal((await engine.listApprovals(ctx(), c2.id))[0]?.invalidReason, 'expired');

    const rel = await engine.release(ctx(), c.id, { approvalId: approval.id, audience: 'public', destinationId: site.id, protectedTerms: [PROTECTED] });
    assert.equal(rel.state, 'delivered'); assert.equal((rel.receipt as { accountabilityDecisionId: string }).accountabilityDecisionId, yes.id);
    const base = join(h.dir, 'site', 't1', 'p1', c.lineageId);
    assert.deepEqual((await readdir(base)).sort(), ['index.html', 'search-index.json', `v1-${digest.slice(0, 16)}`]);
    const searchIndex = JSON.parse(await readFile(join(base, 'search-index.json'), 'utf8')) as { text: string; digest: string };
    assert.equal(searchIndex.digest, digest); assert.match(searchIndex.text, /contract was signed/); assert.doesNotMatch(searchIndex.text, /Quenby|witness-9/i);
    for (const f of await readdir(join(base, `v1-${digest.slice(0, 16)}`))) assert.doesNotMatch(await readFile(join(base, `v1-${digest.slice(0, 16)}`, f), 'latin1'), /Quenby|witness-9/i);
    // a non-public candidate can never reach a public destination
    const priv = await engine.buildChronology(ctx(), { title: 'Private chronology', audience: 'internal_review', package: PKG, formats: ['html'] });
    const pd = await reviewed(engine, priv.id);
    assert.equal(await code(engine.approve(ctx(), priv.id, { candidateDigest: pd, audience: 'internal_review', destinationId: site.id, expiresAt: soon(), accountabilityDecisionId: yes.id })), 'invalid_state');
    // withdrawal: unpublished from the controlled site, tracked, approvals void
    const w = await engine.requestWithdrawal(ctx(), { candidateId: c.id, reason: 'Subject of the story asked for a legal review.', unpublish: true });
    assert.equal(w.state, 'requested'); assert.ok(w.history.some((x) => (x as { action: string }).action === 'unpublished'));
    assert.equal(existsSync(join(base, `v1-${digest.slice(0, 16)}`)), false); assert.match(await readFile(join(base, 'index.html'), 'utf8'), /Withdrawn/);
    assert.equal((await engine.getCandidate(ctx(), c.id)).state, 'withdrawn');
    assert.equal((await engine.distributionHistory(ctx(), { candidateId: c.id }))[0]?.state, 'needs_follow_up');
    assert.equal((await engine.updateWithdrawal(ctx(), w.id, { state: 'completed', note: 'Site copy removed; no other copies known.' })).state, 'completed');
    assert.equal(await code(engine.requestWithdrawal(ctx({ capabilities: ['release:*'] }), { candidateId: c.id, reason: 'x' })), 'forbidden');
    // human_decision policy still needs the human decision record
    const lax = h.make({ ...h.baseConfig, accountabilityPolicy: 'human_decision' });
    const c3 = await companion(lax, ctx(), { title: 'Third companion' }); const d3 = await reviewed(lax, c3.id);
    assert.equal(await code(lax.approve(ctx(), c3.id, { candidateDigest: d3, audience: 'public', destinationId: site.id, expiresAt: soon() })), 'forbidden');
    const y3 = await lax.recordAccountabilityDecision(ctx(), c3.id, { candidateDigest: d3, outcome: 'public_scrutiny_appropriate', assessment: 'Editorial decision recorded.' });
    assert.equal((await lax.approve(ctx(), c3.id, { candidateDigest: d3, audience: 'public', destinationId: site.id, expiresAt: soon(), accountabilityDecisionId: y3.id })).state, 'valid');
  });
});

test('consent: deny blocks approval, release-time re-check blocks after withdrawal, participant review, use register', needsPg, async () => {
  const consent = new FakeConsent(); const uses: unknown[] = [];
  await withEngine(async (h) => {
    const { engine } = h;
    const build = (title: string) => engine.buildInvestigationReport(ctx(), { title, audience: 'legal_counsel', package: PKG, formats: ['html'], subjects: ['E11:participant:p-7', 'E05:evidence_version:doc-1@1'] });
    const dest = await engine.createDestination(ctx(), { name: 'portal', kind: 'local_directory', audiences: ['legal_counsel'], config: { root: 'portal' } });
    const c = await build('Report A'); const digest = await reviewed(engine, c.id);
    const input = { candidateDigest: digest, audience: 'legal_counsel', destinationId: dest.id, expiresAt: soon() };
    consent.denied.add('E11:participant:p-7');
    assert.equal(await code(engine.approve(ctx(), c.id, input)), 'consent_denied');
    consent.denied.clear();
    const approval = await engine.approve(ctx(), c.id, input);
    assert.deepEqual(consent.calls.at(-1), { subjects: ['E11:participant:p-7', 'E05:evidence_version:doc-1@1'], action: 'reproduce', purpose: 'test', audience: 'legal_counsel', destination: 'portal' });
    assert.equal(approval.rights[0]?.decision, 'allow'); assert.deepEqual(approval.rights[0]?.permissionRefs, ['E11:permission:perm-1@1']);
    // permission withdrawn after approval: release is blocked by the re-check and the approval is void
    consent.denied.add('E11:participant:p-7');
    assert.equal(await code(engine.release(ctx(), c.id, { approvalId: approval.id, audience: 'legal_counsel', destinationId: dest.id })), 'consent_denied');
    assert.equal((await engine.listApprovals(ctx(), c.id))[0]?.invalidReason, 'rights_changed');
    consent.denied.clear();
    assert.equal(await code(engine.release(ctx(), c.id, { approvalId: approval.id, audience: 'legal_counsel', destinationId: dest.id })), 'approval_invalid');
    assert.deepEqual(await engine.listReleases(ctx()), []);
    // a changed decision (different permission basis) also voids the approval
    const a2 = await engine.approve(ctx(), c.id, input);
    consent.permissionRefs = ['E11:permission:perm-2@1'];
    assert.equal(await code(engine.release(ctx(), c.id, { approvalId: a2.id, audience: 'legal_counsel', destinationId: dest.id })), 'approval_invalid');
    // renewed approval releases, and the use is registered with the consent engine
    const a3 = await engine.approve(ctx(), c.id, input);
    const rel = await engine.release(ctx(), c.id, { approvalId: a3.id, audience: 'legal_counsel', destinationId: dest.id });
    assert.equal(rel.state, 'delivered');
    assert.equal(uses.length, 1); assert.deepEqual({ ...(uses[0] as object), decisionRef: 'x', idempotencyKey: 'x' }, { decisionRef: 'x', idempotencyKey: 'x', subjects: ['E11:participant:p-7', 'E05:evidence_version:doc-1@1'], output: rel.ref, action: 'reproduce', audience: 'legal_counsel', destination: 'portal' });
    assert.match((uses[0] as { decisionRef: string }).decisionRef, /^E11:decision:/);
    // a consent restriction requires the participant's own review of the exact version
    consent.restrictions = ['participant_review'];
    const p = await build('Report B');
    assert.equal(await code(engine.submitForReview(ctx(), p.id, { reviewers: ['rev-1'] })), 'invalid_input');
    await engine.submitForReview(ctx(), p.id, { reviewers: ['rev-1'], participantReviewers: ['participant-7'] });
    assert.equal((await engine.recordReview(as('rev-1'), p.id, { candidateDigest: p.digest as string, outcome: 'accepted' })).state, 'in_review');
    assert.equal(await code(engine.approve(ctx(), p.id, { ...input, candidateDigest: p.digest as string })), 'invalid_state');
    assert.equal(await code(engine.recordParticipantReview(as('rev-1'), p.id, { candidateDigest: p.digest as string, outcome: 'accepted' })), 'forbidden');
    assert.equal(await code(engine.recordParticipantReview(ctx({ actor: { id: 'participant-7', kind: 'agent', roles: [] } }), p.id, { candidateDigest: p.digest as string, outcome: 'accepted' })), 'forbidden');
    assert.equal((await engine.recordParticipantReview(as('participant-7'), p.id, { candidateDigest: p.digest as string, outcome: 'accepted' })).state, 'reviewed');
    assert.equal((await engine.approve(ctx(), p.id, { ...input, candidateDigest: p.digest as string })).state, 'valid');
    // objection sends the candidate back and voids approvals
    const o = await build('Report C');
    await engine.submitForReview(ctx(), o.id, { reviewers: ['rev-1'], participantReviewers: ['participant-7'] });
    assert.equal((await engine.recordParticipantReview(as('participant-7'), o.id, { candidateDigest: o.digest as string, outcome: 'objected', note: 'Paragraph two identifies my workplace.' })).state, 'changes_requested');
    assert.equal(await code(engine.approve(ctx(), o.id, { ...input, candidateDigest: o.digest as string })), 'invalid_state');
    // 'review' is not 'allow'
    consent.restrictions = []; consent.decide = async () => ({ decision: 'review', reasons: ['needs a rights officer'], permissionRefs: [], restrictions: [], decidedAt: new Date().toISOString(), decisionRef: 'E11:decision:r' });
    assert.equal(await code(engine.approve(ctx(), c.id, input)), 'consent_denied');
    // standalone without a consent service: denied unless the deployment explicitly opts in
    const alone = h.make(h.baseConfig, {});
    assert.equal(await code(alone.approve(ctx(), c.id, input)), 'consent_denied');
    assert.equal((await h.make({ ...h.baseConfig, standaloneRights: 'allow_without_port' }, {}).approve(ctx(), c.id, input)).rights[0]?.evaluated, false);
  }, {}, { useDecision: consent, useRegister: { recordUse: async (_c, input) => { uses.push(input); return {}; } } });
});

test('invalidation: upstream changes, destination changes, correction and supersession with follow-up tracking', needsPg, async () => {
  await withEngine(async (h) => {
    const { engine } = h;
    const dest = await engine.createDestination(ctx(), { name: 'portal', kind: 'local_directory', audiences: ['legal_counsel'], config: { root: 'portal' } });
    const dl = await engine.createDestination(ctx(), { name: 'download', kind: 'signed_download', audiences: ['legal_counsel'], config: { ttlSeconds: 3600 } });
    const v1 = await engine.buildInvestigationReport(ctx(), { title: 'Harbour report', audience: 'legal_counsel', package: PKG, formats: ['html'] });
    const d1 = await reviewed(engine, v1.id);
    const a1 = await engine.approve(ctx(), v1.id, { candidateDigest: d1, audience: 'legal_counsel', destinationId: dest.id, expiresAt: soon() });
    const r1 = await engine.release(ctx(), v1.id, { approvalId: a1.id, audience: 'legal_counsel', destinationId: dest.id, recipients: ['Counsel A', 'Counsel B'] });
    const aDl = await engine.approve(ctx(), v1.id, { candidateDigest: d1, audience: 'legal_counsel', destinationId: dl.id, expiresAt: soon() });
    const rDl = await engine.release(ctx(), v1.id, { approvalId: aDl.id, audience: 'legal_counsel', destinationId: dl.id });
    const url = (rDl.receipt as { adapterResponse: { downloadUrl: string } }).adapterResponse.downloadUrl; const token = url.split('/').at(-1) as string;
    assert.equal((await engine.download(token)).sha256, (await engine.exportCandidateZip(ctx(), v1.id)).sha256);
    assert.equal(await code(engine.download(token, new Date(Date.now() + 3601 * 1000))), 'not_found', 'expired link');
    assert.equal(await code(engine.download(`${token.slice(0, -2)}xx`)), 'not_found'); assert.equal(await code(engine.download(token.replace(/\.\d+\./, '.99999999999.'))), 'not_found');
    const copy = await engine.recordDownstreamCopy(ctx(), (await engine.distributionHistory(ctx(), { candidateId: v1.id }))[0]?.id as string, { holder: 'Expert witness C' });
    // destination change voids approvals bound to the old revision
    const pending = await engine.approve(ctx(), v1.id, { candidateDigest: d1, audience: 'legal_counsel', destinationId: dest.id, expiresAt: soon() });
    assert.equal((await engine.updateDestination(ctx(), dest.id, { audiences: ['legal_counsel', 'authority_referral'] })).revision, 2);
    assert.equal(await code(engine.release(ctx(), v1.id, { approvalId: pending.id, audience: 'legal_counsel', destinationId: dest.id })), 'approval_invalid');
    assert.equal((await engine.listApprovals(ctx(), v1.id)).find((a) => a.id === pending.id)?.invalidReason, 'destination_changed');
    const pending2 = await engine.approve(ctx(), v1.id, { candidateDigest: d1, audience: 'legal_counsel', destinationId: dest.id, expiresAt: soon() });
    // unrelated upstream change touches nothing
    assert.deepEqual((await engine.applyUpstreamChange(ctx(), { eventId: 'ev-0', kind: 'source_corrected', refs: ['E05:evidence_version:unrelated@1'], reason: 'n/a' })).affected, []);
    assert.equal(await code(engine.applyUpstreamChange(ctx({ capabilities: ['release:read'] }), { eventId: 'ev-x', kind: 'source_corrected', refs: [], reason: '' })), 'forbidden');
    // a corrected source makes the candidate stale, voids the approval and flags every distribution
    const change = { eventId: 'ev-1', kind: 'source_corrected' as const, refs: ['E05:evidence_version:doc-1'], reason: 'The signature page was replaced by a corrected scan.' };
    const out = await engine.applyUpstreamChange(ctx({ capabilities: ['release:upstream'], actor: { id: 'pam-router', kind: 'service', roles: [] } }), change);
    assert.ok(out.affected.includes(v1.ref)); assert.ok(out.affected.includes(`E12:approval:${pending2.id}`)); assert.equal(out.affected.filter((a) => a.startsWith('E12:distribution:')).length, 4);
    assert.deepEqual((await engine.applyUpstreamChange(ctx(), change)).affected, out.affected, 'idempotent by eventId');
    const stale = await engine.getCandidate(ctx(), v1.id);
    assert.equal(stale.stale, true); assert.equal(stale.blocked, false); assert.equal((stale.staleReasons[0] as { cause: string }).cause, 'ev-1');
    const insp = await engine.inspect(ctx(), v1.ref); assert.equal(insp?.stale, true); assert.match(insp?.staleReasons[0] ?? '', /source_corrected/);
    assert.equal(await code(engine.release(ctx(), v1.id, { approvalId: pending2.id, audience: 'legal_counsel', destinationId: dest.id })), 'approval_invalid');
    assert.equal(await code(engine.approve(ctx(), v1.id, { candidateDigest: d1, audience: 'legal_counsel', destinationId: dest.id, expiresAt: soon() })), 'approval_invalid', 'stale candidate cannot be re-approved');
    const dists = await engine.distributionHistory(ctx(), { candidateId: v1.id });
    assert.equal(dists.length, 4); assert.ok(dists.every((d) => d.state === 'needs_follow_up' && d.followUpStatus === 'pending'));
    assert.equal((await engine.getRelease(ctx(), r1.id)).state, 'delivered', 'history is retained');
    const types = (await events(h)).map((e) => e.type);
    assert.equal(types.filter((t) => t === 'release.candidate_stale').length, 1); assert.equal(types.filter((t) => t === 'release.approval_invalidated').length, 2); assert.equal(types.filter((t) => t === 'release.distribution_needs_follow_up').length, 4);
    for (const kind of ['content_changed', 'render_changed', 'claim_changed', 'rights_changed', 'audience_changed'] as const) {
      const c = await engine.buildChronology(ctx(), { title: `Chronology ${kind}`, audience: 'legal_counsel', package: PKG, formats: ['html'] });
      const d = await reviewed(engine, c.id);
      const ap = await engine.approve(ctx(), c.id, { candidateDigest: d, audience: 'legal_counsel', destinationId: dest.id, expiresAt: soon() });
      const ref = kind === 'audience_changed' ? `E12:destination:${dest.id}` : kind === 'claim_changed' ? 'E07:claim:c-2' : kind === 'content_changed' ? 'E08:finding:f-1' : c.ref;
      const res = await engine.applyUpstreamChange(ctx(), { eventId: `ev-${kind}-${c.id}`, kind, refs: [ref], reason: kind });
      assert.ok(res.affected.includes(`E12:approval:${ap.id}`), kind);
      assert.equal(await code(engine.release(ctx(), c.id, { approvalId: ap.id, audience: 'legal_counsel', destinationId: dest.id })), 'approval_invalid', kind);
    }

    // correction: v2 supersedes v1; v1 is retained and marked; distributions are listed for follow-up
    const fixed = { ...PKG, findings: PKG.findings.map((f) => (f.id === 'F1' ? { ...f, statement: 'The harbour authority signed the dredging contract on 4 March 2025.', sources: [{ ref: 'E05:evidence_version:doc-1@2', locator: 'page 2' }] } : f)) };
    const v2 = await engine.buildInvestigationReport(ctx(), { title: 'Harbour report', audience: 'legal_counsel', package: fixed, formats: ['html'], supersedes: v1.id });
    assert.equal(v2.version, 2); assert.equal(v2.lineageId, v1.lineageId); assert.equal(v2.supersedes, v1.id); assert.notEqual(v2.digest, d1);
    const d2 = await reviewed(engine, v2.id);
    const early = await engine.approve(ctx(), v2.id, { candidateDigest: d2, audience: 'legal_counsel', destinationId: dest.id, expiresAt: soon() });
    assert.equal(await code(engine.issueCorrection(ctx({ actor: { id: 'bot', kind: 'agent', roles: [] } }), { priorCandidateId: v1.id, correctedCandidateId: v2.id, reason: 'x' })), 'forbidden');
    const unrelated = await engine.buildInvestigationReport(ctx(), { title: 'Other', audience: 'legal_counsel', package: PKG, formats: ['html'] });
    assert.equal(await code(engine.issueCorrection(ctx(), { priorCandidateId: v1.id, correctedCandidateId: unrelated.id, reason: 'x' })), 'invalid_state');
    const corr = await engine.issueCorrection(ctx(), { priorCandidateId: v1.id, correctedCandidateId: v2.id, reason: 'The signing date was 4 March, not 3 March.' });
    assert.match(corr.noticeText, /CORRECTION NOTICE/); assert.ok(corr.noticeText.includes(d1) && corr.noticeText.includes(d2)); assert.match(corr.noticeText, /Changed files: findings\.json, report\.html, report\.md/); assert.match(corr.noticeText, /4 March, not 3 March/);
    assert.equal(corr.followUps.length, 4); assert.ok(corr.followUps.some((f) => f.id === copy.id));
    const old = await engine.getCandidate(ctx(), v1.id);
    assert.equal(old.state, 'superseded'); assert.equal(old.supersededBy, v2.id); assert.equal(old.digest, d1);
    assert.equal((await engine.exportCandidateZip(ctx(), v1.id)).bytes.byteLength > 0, true, 'prior version bytes retained');
    assert.deepEqual((await engine.inspect(ctx(), v2.ref))?.versions.map((v) => [v.revision, v.summary]), [[1, 'superseded'], [2, 'reviewed']]);
    assert.equal(await code(engine.download(token)), 'ok', 'superseded copy stays downloadable until withdrawn; follow-up tracks it');
    // the notice is new outgoing content: an approval given before it existed is void; nothing is released unapproved
    assert.equal(await code(engine.release(ctx(), v2.id, { approvalId: early.id, audience: 'legal_counsel', destinationId: dest.id })), 'approval_invalid');
    assert.deepEqual(await engine.listReleases(ctx(), { candidateId: v2.id }), []);
    const a2 = await engine.approve(ctx(), v2.id, { candidateDigest: d2, audience: 'legal_counsel', destinationId: dest.id, expiresAt: soon() });
    const r2 = await engine.release(ctx(), v2.id, { approvalId: a2.id, audience: 'legal_counsel', destinationId: dest.id, recipients: ['Counsel A', 'Counsel B'] });
    const out2 = join(h.dir, 'portal', (r2.receipt as { adapterResponse: { location: string } }).adapterResponse.location);
    assert.equal(await readFile(join(out2, 'correction-notices', 'correction-v2.txt'), 'utf8'), corr.noticeText);
    assert.equal(existsSync(join(h.dir, 'portal', (r1.receipt as { adapterResponse: { location: string } }).adapterResponse.location, 'report.html')), true, 'prior delivery not deleted');
    // follow-up tracking
    const open = await engine.distributionHistory(ctx(), { lineageId: v1.lineageId, needsFollowUp: true });
    assert.equal(open.length, 4);
    assert.equal((await engine.updateFollowUp(ctx(), open[0]?.id as string, { status: 'notified', note: 'Notice sent with v2.' })).state, 'needs_follow_up');
    const ack = await engine.updateFollowUp(ctx(), open[0]?.id as string, { status: 'acknowledged' });
    assert.equal(ack.state, 'follow_up_done'); assert.equal(ack.followUpStatus, 'acknowledged'); assert.ok(ack.history.length >= 4);
    assert.equal((await engine.updateFollowUp(ctx(), copy.id, { status: 'unreachable', note: 'No contact details.' })).followUpStatus, 'unreachable');
    assert.equal((await engine.distributionHistory(ctx(), { lineageId: v1.lineageId, needsFollowUp: true })).length, 2);
    assert.equal((await engine.listCorrections(ctx(), v1.lineageId)).length, 1);
    const all = (await events(h)).map((e) => e.type);
    assert.ok(all.includes('release.correction_issued') && all.includes('release.superseded') && all.includes('release.follow_up_updated'));
    // permission withdrawn: blocked (not merely stale), download link revoked, nothing deleted
    const w = await engine.applyUpstreamChange(ctx(), { eventId: 'ev-9', kind: 'permission_withdrawn', refs: ['E05:evidence_version:doc-1@2'], reason: 'Source withdrew permission.' });
    assert.ok(w.affected.includes(v2.ref));
    const blocked = await engine.getCandidate(ctx(), v2.id); assert.equal(blocked.blocked, true);
    assert.equal((await engine.distributionHistory(ctx(), { candidateId: v2.id })).every((d) => d.state === 'needs_follow_up'), true);
    assert.equal((await engine.getRelease(ctx(), r2.id)).state, 'delivered');
  });
});
