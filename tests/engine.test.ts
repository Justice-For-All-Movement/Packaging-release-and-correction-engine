import test from 'node:test';
import assert from 'node:assert/strict';
import { readdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { zipRead } from '../src/engine/index.ts';
import { verifyAuditChain, listAudit } from '../src/service-kit.ts';
import { as, code, ctx, events, needsPg, PKG, reviewed, soon, tool, withEngine } from './helpers/engine.ts';

test('report candidate: openable files, deterministic manifest, review, exact approval, release receipt, idempotent retry, tenant isolation', needsPg, async () => {
  await withEngine(async (h) => {
    const { engine } = h;
    const c = await engine.buildInvestigationReport(ctx(), { title: 'Harbour contract report', audience: 'legal_counsel', package: PKG, formats: ['html', 'pdf', 'docx'] });
    assert.equal(c.state, 'built'); assert.match(c.digest ?? '', /^[a-f0-9]{64}$/);
    assert.deepEqual(c.components.map((x) => x.path), ['findings.json', 'report.docx', 'report.html', 'report.md', 'report.pdf']);
    const zip = await engine.exportCandidateZip(ctx(), c.id);
    const zipFile = join(h.dir, 'pkg.zip'); await writeFile(zipFile, zip.bytes);
    assert.match(await tool('unzip', ['-t', zipFile]), /No errors detected/);
    const entries = new Map(zipRead(zip.bytes).map((e) => [e.path, e.bytes]));
    const manifest = JSON.parse(new TextDecoder().decode(entries.get('manifest.json'))) as { components: { path: string; sha256: string; sources: string[] }[]; sources: string[]; basisLabels: unknown };
    const { createHash } = await import('node:crypto');
    assert.equal(createHash('sha256').update(entries.get('manifest.json') as Uint8Array).digest('hex'), c.digest);
    for (const m of manifest.components) assert.equal(createHash('sha256').update(entries.get(m.path) as Uint8Array).digest('hex'), m.sha256);
    assert.ok(manifest.sources.includes('E05:evidence_version:doc-1@1'));
    assert.deepEqual(manifest.basisLabels, { established: 1, disputed: 1, unknown: 1 });
    const pdfFile = join(h.dir, 'report.pdf'); await writeFile(pdfFile, entries.get('report.pdf') as Uint8Array);
    assert.match(await tool('pdfinfo', [pdfFile]), /Pages:\s+\d/);
    const text = await tool('pdftotext', [pdfFile, '-']);
    assert.match(text, /ESTABLISHED/); assert.match(text, /DISPUTED/); assert.match(text, /UNKNOWN/); assert.match(text, /E05:evidence_version:doc-1@1/); assert.match(text, /Only the signature page/);
    const docxFile = join(h.dir, 'report.docx'); await writeFile(docxFile, entries.get('report.docx') as Uint8Array);
    assert.match(await tool('unzip', ['-t', docxFile]), /No errors detected/);
    // an established finding without a source is refused rather than presented as established
    assert.equal(await code(engine.buildInvestigationReport(ctx(), { title: 'x', audience: 'legal_counsel', package: { ...PKG, findings: [{ id: 'F9', status: 'established', statement: 'Unsourced.' }], chronology: [] } })), 'invalid_input');
    // determinism for non-rendered formats
    const d1 = await engine.buildChronology(ctx(), { title: 'Chronology', audience: 'legal_counsel', package: PKG, formats: ['html', 'docx'] });
    const d2 = await engine.buildChronology(ctx(), { title: 'Chronology', audience: 'legal_counsel', package: PKG, formats: ['html', 'docx'] });
    assert.equal(d1.digest, d2.digest); assert.notEqual(d1.id, d2.id);
    assert.deepEqual((await engine.exportCandidateZip(ctx(), d1.id)).sha256, (await engine.exportCandidateZip(ctx(), d2.id)).sha256);
    const k1 = await engine.buildChronology(ctx(), { title: 'Chronology', audience: 'legal_counsel', package: PKG, formats: ['html'], idempotencyKey: 'k1' });
    assert.equal((await engine.buildChronology(ctx(), { title: 'Chronology', audience: 'legal_counsel', package: PKG, formats: ['html'], idempotencyKey: 'k1' })).id, k1.id);

    // review → approval → release
    const dest = await engine.createDestination(ctx(), { name: 'counsel portal', kind: 'local_directory', audiences: ['legal_counsel'], config: { root: 'portal' } });
    assert.equal(await code(engine.approve(ctx(), c.id, { candidateDigest: c.digest as string, audience: 'legal_counsel', destinationId: dest.id, expiresAt: soon() })), 'invalid_state', 'unreviewed');
    await engine.submitForReview(ctx(), c.id, { reviewers: ['rev-1', 'rev-2'] });
    await engine.addReviewComment(as('rev-2'), c.id, { body: 'Check the date in F1.', componentPath: 'report.md' });
    assert.equal(await code(engine.recordReview(as('stranger'), c.id, { candidateDigest: c.digest as string, outcome: 'accepted' })), 'forbidden');
    assert.equal(await code(engine.recordReview(as('rev-1'), c.id, { candidateDigest: 'f'.repeat(64), outcome: 'accepted' })), 'approval_invalid');
    assert.equal((await engine.recordReview(as('rev-1'), c.id, { candidateDigest: c.digest as string, outcome: 'accepted' })).state, 'in_review');
    assert.equal((await engine.recordReview(as('rev-2'), c.id, { candidateDigest: c.digest as string, outcome: 'accepted' })).state, 'reviewed');
    assert.equal((await engine.listReviewEvents(ctx(), c.id)).length, 4);
    // fail-closed authorization and human-only approval
    assert.equal(await code(engine.approve(ctx({ capabilities: ['release:*'] }), c.id, { candidateDigest: c.digest as string, audience: 'legal_counsel', destinationId: dest.id, expiresAt: soon() })), 'forbidden');
    for (const kind of ['agent', 'service'] as const) assert.equal(await code(engine.approve(ctx({ actor: { id: 'a1', kind, roles: ['owner'] } }), c.id, { candidateDigest: c.digest as string, audience: 'legal_counsel', destinationId: dest.id, expiresAt: soon() })), 'forbidden');
    assert.equal(await code(engine.approve(ctx(), c.id, { candidateDigest: 'f'.repeat(64), audience: 'legal_counsel', destinationId: dest.id, expiresAt: soon() })), 'approval_invalid');
    assert.equal(await code(engine.approve(ctx(), c.id, { candidateDigest: c.digest as string, audience: 'internal_review', destinationId: dest.id, expiresAt: soon() })), 'approval_invalid');
    assert.equal(await code(engine.approve(ctx(), c.id, { candidateDigest: c.digest as string, audience: 'legal_counsel', destinationId: dest.id, expiresAt: soon(86400 * 30) })), 'invalid_input');
    const approval = await engine.approve(ctx(), c.id, { candidateDigest: c.digest as string, audience: 'legal_counsel', destinationId: dest.id, expiresAt: soon(), idempotencyKey: 'ap1' });
    assert.equal((await engine.approve(ctx(), c.id, { candidateDigest: c.digest as string, audience: 'legal_counsel', destinationId: dest.id, expiresAt: approval.expiresAt, idempotencyKey: 'ap1' })).id, approval.id);
    // approval of one candidate never releases another (exact version)
    await reviewed(engine, d1.id);
    assert.equal(await code(engine.release(ctx(), d1.id, { approvalId: approval.id, audience: 'legal_counsel', destinationId: dest.id })), 'approval_invalid');
    assert.equal(await code(engine.release(ctx(), c.id, { approvalId: approval.id, audience: 'internal_review', destinationId: dest.id })), 'approval_invalid');
    assert.equal(await code(engine.release(ctx({ capabilities: ['release:read', 'release:write', 'release:approve'] }), c.id, { approvalId: approval.id, audience: 'legal_counsel', destinationId: dest.id })), 'forbidden');
    const rel = await engine.release(ctx(), c.id, { approvalId: approval.id, audience: 'legal_counsel', destinationId: dest.id, recipients: ['Counsel team A'] });
    assert.equal(rel.state, 'delivered'); assert.equal(rel.replayed, false);
    const receipt = rel.receipt as { candidateDigest: string; destination: { name: string }; releasedBy: string; receiptDigest: string; adapterResponse: { location: string }; zipSha256: string };
    assert.equal(receipt.candidateDigest, c.digest); assert.equal(receipt.destination.name, 'counsel portal'); assert.equal(receipt.releasedBy, 'owner-1'); assert.equal(receipt.zipSha256, zip.sha256);
    const outDir = join(h.dir, 'portal', receipt.adapterResponse.location);
    assert.deepEqual((await readdir(outDir)).sort(), ['findings.json', 'manifest.json', 'package.zip', 'report.docx', 'report.html', 'report.md', 'report.pdf']);
    assert.deepEqual(new Uint8Array(await readFile(join(outDir, 'package.zip'))), zip.bytes);
    // retry does not double-distribute
    const again = await engine.release(ctx(), c.id, { approvalId: approval.id, audience: 'legal_counsel', destinationId: dest.id, recipients: ['Counsel team A'] });
    assert.equal(again.id, rel.id); assert.equal(again.replayed, true);
    const history = await engine.distributionHistory(ctx(), { candidateId: c.id });
    assert.equal(history.length, 1); assert.equal(history[0]?.recipient, 'Counsel team A'); assert.equal(history[0]?.state, 'delivered');
    assert.equal((await engine.listApprovals(ctx(), c.id))[0]?.state, 'used');
    const copy = await engine.recordDownstreamCopy(ctx(), history[0]?.id as string, { holder: 'Outside expert B' });
    assert.equal(copy.kind, 'downstream_copy');

    // standard surface
    const insp = await engine.inspect(ctx(), c.ref);
    assert.equal(insp?.state, 'reviewed'); assert.ok(insp?.sources.includes('E05:evidence_version:doc-1@1')); assert.ok((insp?.dependents.length ?? 0) >= 3);
    assert.equal((await engine.search(ctx(), { q: 'dredging contract' })).some((s) => s.ref === c.ref), true);
    assert.deepEqual((await events(h)).map((e) => e.type).filter((t) => ['release.candidate_built', 'release.approved', 'release.released'].includes(t)).slice(-2), ['release.approved', 'release.released']);
    assert.ok(verifyAuditChain(await listAudit(h.sql, 'e12_release', ctx(), { allProjects: true, limit: 1000 })));
    assert.equal((await engine.health()).ok, true);

    // tenant / project isolation: nothing is visible or usable from another scope
    for (const other of [ctx({ tenantId: 't2' }), ctx({ projectId: 'p2' })]) {
      assert.equal(await code(engine.getCandidate(other, c.id)), 'not_found');
      assert.equal(await code(engine.getManifest(other, c.id)), 'not_found');
      assert.equal(await code(engine.getComponent(other, c.id, 'report.md')), 'not_found');
      assert.equal(await code(engine.exportCandidateZip(other, c.id)), 'not_found');
      assert.equal(await code(engine.getRelease(other, rel.id)), 'not_found');
      assert.equal(await code(engine.release(other, c.id, { approvalId: approval.id, audience: 'legal_counsel', destinationId: dest.id })), 'not_found');
      assert.equal(await code(engine.updateFollowUp(other, history[0]?.id as string, { status: 'notified' })), 'not_found');
      assert.equal(await code(engine.updateDestination(other, dest.id, { enabled: false })), 'not_found');
      assert.deepEqual(await engine.listCandidates(other), []); assert.deepEqual(await engine.listReleases(other), []); assert.deepEqual(await engine.listDestinations(other), []);
      assert.deepEqual(await engine.distributionHistory(other), []); assert.deepEqual(await engine.search(other, { q: 'dredging' }), []);
      assert.equal(await engine.inspect(other, c.ref), null); assert.equal(await engine.inspect(other, rel.ref), null);
      assert.deepEqual(await engine.audit(other), []);
      assert.deepEqual((await engine.applyUpstreamChange(other, { eventId: 'x1', kind: 'source_corrected', refs: ['E05:evidence_version:doc-1'], reason: 'r' })).affected, []);
    }
    assert.deepEqual(await engine.events(ctx({ tenantId: 't2' })), []);
    assert.ok((await h.objects.list('')).every((k) => k.startsWith('t1/p1/')));
    assert.equal((await engine.getCandidate(ctx(), c.id)).stale, false);
    // compartment-hidden candidates are indistinguishable from missing ones
    const hidden = await engine.buildChronology(ctx({ compartments: ['c-secret'] }), { title: 'Sealed chronology', audience: 'internal_review', package: PKG, formats: ['html'], compartment: 'c-secret' });
    assert.equal(await code(engine.getCandidate(ctx(), hidden.id)), 'not_found'); assert.equal(await engine.inspect(ctx(), hidden.ref), null);
    assert.equal((await engine.search(ctx(), { q: 'Sealed' })).length, 0); assert.equal((await engine.listCandidates(ctx())).some((x) => x.id === hidden.id), false);
    for (const cap of ['release:read', 'release:write', 'release:export', 'release:events'] as const) {
      const none = ctx({ capabilities: [] });
      assert.equal(await code(cap === 'release:read' ? engine.getCandidate(none, c.id) : cap === 'release:write' ? engine.buildChronology(none, { title: 'x', audience: 'legal_counsel', package: PKG }) : cap === 'release:export' ? engine.exportCandidateZip(none, c.id) : engine.events(none)), 'forbidden');
    }
  });
});
