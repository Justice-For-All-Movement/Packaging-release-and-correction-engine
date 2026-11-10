import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { DRAFT_STAMP, UNRESOLVED_AUTHORITY, validatePack, zipRead } from '../src/engine/index.ts';
import type { ReleaseEngine } from '../src/engine/index.ts';
import { as, b64, code, ctx, image, needsPg, pack, PKG, reviewed, tool, withEngine } from './helpers/engine.ts';

const files = async (engine: ReleaseEngine, id: string): Promise<Map<string, Uint8Array>> => new Map(zipRead((await engine.exportCandidateZip(ctx(), id)).bytes).map((e) => [e.path, e.bytes]));
const text = (m: Map<string, Uint8Array>, p: string): string => new TextDecoder().decode(m.get(p));
const plain = (s: string): string => s.replace(/\\(.)/g, '$1');

test('legal-support drafts: sourced facts, unresolved authorities, assumptions, draft stamp, professional review bound to the exact version', needsPg, async () => {
  await withEngine(async (h) => {
    const { engine } = h; const p = await pack();
    const input = { title: 'Complaint about the dredging contract', audience: 'legal_counsel', jurisdictionPackId: 'example-republic', documentType: 'oversight_complaint', package: PKG, values: { oversight_body: 'Harbour Oversight Board (fictional)' }, formats: ['html', 'pdf', 'docx'] as const };
    const c = await engine.buildLegalDraft(ctx(), input);
    assert.equal(c.state, 'built', JSON.stringify(c.leakReport));
    const f = await files(engine, c.id);
    const md = plain(text(f, 'draft.md'));
    // stamp on the title and on every section
    const sections = md.split(/^## /m).slice(1);
    assert.ok(sections.length >= 7); for (const s of sections) assert.ok(s.includes(DRAFT_STAMP), s.slice(0, 40));
    assert.ok(md.split(/^## /m)[0]?.includes(DRAFT_STAMP));
    const pdfFile = join(h.dir, 'draft.pdf'); await writeFile(pdfFile, f.get('draft.pdf') as Uint8Array);
    assert.match(await tool('pdfinfo', [pdfFile]), /Pages:\s+\d/);
    const pdfText = (await tool('pdftotext', [pdfFile, '-'])).replace(/\s+/g, ' ');
    assert.ok(pdfText.includes('not legal advice; not filed; not reviewed by a legal professional'));
    assert.match(await tool('pandoc', ['-f', 'docx', '-t', 'plain', join(h.dir, await (async () => { await writeFile(join(h.dir, 'draft.docx'), f.get('draft.docx') as Uint8Array); return 'draft.docx'; })())]), /DRAFT/);
    // facts come only from the findings, each with its numbered sources; statuses are kept
    assert.match(md, /1\. \(ESTABLISHED\) The harbour authority signed the dredging contract on 3 March 2025\. \[S1\]/);
    assert.match(md, /\(DISPUTED\) The contractor says/); assert.match(md, /\(UNKNOWN\) Who authorised the first payment is not known\. \(no source cited\)/);
    assert.match(md, /S1 — `E05:evidence_version:doc-1@1` — page 2/);
    // authorities: only those in the pack appear; the absent one is an explicit unresolved item
    assert.ok(md.includes('Public Conduct Code (Example Republic), rule 12'));
    assert.ok(md.includes(UNRESOLVED_AUTHORITY));
    const manifest = JSON.parse(text(f, 'manifest.json')) as { legal: { unresolved_authorities: { id: string; reason: string }[]; jurisdictional_assumptions: string[]; authorities_used: { id: string }[]; unresolved_placeholders: string[]; stamp: string; filed: boolean; professionalReview: unknown; contentDigest: string } };
    assert.deepEqual(manifest.legal.unresolved_authorities.map((u) => u.id), ['sanctions-provision']); assert.match(manifest.legal.unresolved_authorities[0]?.reason ?? '', /not present in the jurisdiction pack/);
    assert.deepEqual(manifest.legal.authorities_used.map((a) => a.id), ['public-conduct-code-r12']);
    assert.equal(manifest.legal.stamp, DRAFT_STAMP); assert.equal(manifest.legal.filed, false); assert.equal(manifest.legal.professionalReview, null);
    assert.ok(manifest.legal.jurisdictional_assumptions.length >= 4 && manifest.legal.jurisdictional_assumptions[0]?.includes('has not been verified'));
    assert.deepEqual(manifest.legal.unresolved_placeholders, ['complainant']); assert.ok(md.includes('[to be completed: complainant]'));
    assert.match(md, /## Unresolved authorities[\s\S]*sanctions-provision/); assert.match(md, /## Jurisdictional assumptions[\s\S]*fictional/);
    // no citation-like text exists beyond the pack: every "Act"/"Code"/"section"/"rule" mention is a pack citation
    const known = p.authorities.map((a) => a.citation);
    let residue = md; for (const k of known) residue = residue.replaceAll(k, '');
    assert.doesNotMatch(residue, /\b(Act \d{4}|Code \(|section \d|rule \d|§|v\. |\[\d{4}\])/);
    assert.ok(!md.includes('Open Records Act'), 'authorities not referenced by this template are not volunteered');
    // professional review: human with the exact capability, for the exact digest
    const review = { candidateDigest: c.digest as string, reviewerName: 'A. Example', reviewerRole: 'Advocate (fictional)', reviewedOn: '2026-11-01' };
    assert.equal(await code(engine.recordProfessionalReview(ctx({ actor: { id: 'bot', kind: 'agent', roles: [] } }), c.id, review)), 'forbidden');
    assert.equal(await code(engine.recordProfessionalReview(ctx({ capabilities: ['release:*'] }), c.id, review)), 'forbidden', 'wildcard is not enough');
    assert.equal(await code(engine.recordProfessionalReview(ctx(), c.id, { ...review, candidateDigest: 'b'.repeat(64) })), 'approval_invalid');
    assert.equal(await code(engine.recordProfessionalReview(ctx(), c.id, { ...review, reviewedOn: '2999-01-01' })), 'invalid_input');
    const rec = await engine.recordProfessionalReview(as('legal-admin'), c.id, review);
    assert.equal((await files(engine, c.id)).get('draft.md') !== undefined && plain(text(await files(engine, c.id), 'draft.md')).includes(DRAFT_STAMP), true, 'the reviewed candidate itself is immutable');
    const r2 = await engine.buildLegalDraft(ctx(), { ...input, formats: ['html'], supersedes: c.id, professionalReviewId: rec.id });
    const md2 = plain(text(await files(engine, r2.id), 'draft.md'));
    assert.ok(!md2.includes('not reviewed by a legal professional')); assert.ok(md2.includes('Professional review recorded for this exact content')); assert.ok(md2.includes('A. Example, Advocate (fictional), 2026-11-01')); assert.ok(md2.includes('not legal advice; not filed'));
    // the review does not transfer to different content
    assert.equal(await code(engine.buildLegalDraft(ctx(), { ...input, formats: ['html'], professionalReviewId: rec.id, values: { oversight_body: 'A different body' } })), 'approval_invalid');
    assert.equal(await code(engine.buildLegalDraft(ctx(), { ...input, formats: ['html'], professionalReviewId: rec.id, package: { ...PKG, findings: PKG.findings.slice(0, 1), chronology: [] } })), 'approval_invalid');
    assert.equal(await code(engine.buildLegalDraft(ctx(), { ...input, documentType: 'writ_of_something' })), 'invalid_input');
    assert.equal(await code(engine.buildLegalDraft(ctx(), { ...input, jurisdictionPackId: 'atlantis' })), 'invalid_input');
    assert.throws(() => validatePack({ ...p, documentTypes: { bad: { title: 'Bad', sections: [{ id: 's', heading: 'h', body: '{{invent_citation}}' }] } } }), /Unknown template token/);
    assert.deepEqual(engine.listJurisdictionPacks(ctx()).map((x) => x.id), ['example-republic']);

    // records request: legal basis only from the pack; unreviewed authority flagged; records derived from open questions
    const rr = await engine.buildRecordsRequest(ctx(), { title: 'Request for payment records', audience: 'records_holder', jurisdictionPackId: 'example-republic', package: PKG, recordsSought: ['The signed dredging contract'], values: { date: '10 November 2026' }, formats: ['html', 'pdf'],
      requester: { name: 'Example Newsroom', address: '1 Example Street', contact: 'records@example.org' }, recipient: { name: 'Records Officer', organization: 'Harbour Authority (fictional)' } });
    const rf = await files(engine, rr.id); const rmd = plain(text(rf, 'records-request.md'));
    assert.ok(rmd.includes('This request is made under Open Records Act 2001 (Example Republic), section 4.'));
    assert.ok(rmd.includes('Open Records Act 2001 (Example Republic), section 9 *(unreviewed authority — to be confirmed by a qualified reviewer)*'));
    assert.match(rmd, /1\. The signed dredging contract\n2\. Payment authorisation records for the dredging contract/); assert.ok(rmd.includes('Example Newsroom') && rmd.includes('records@example.org') && rmd.includes('Harbour Authority (fictional)'));
    assert.ok(rmd.includes(DRAFT_STAMP)); assert.ok(rmd.includes('[to be completed: date_range]'));
    const rl = (JSON.parse(text(rf, 'manifest.json')) as { legal: { unresolved_authorities: { id: string; reason: string }[] } }).legal;
    assert.deepEqual(rl.unresolved_authorities.map((u) => `${u.id}:${u.reason}`), ['open-records-act-s9:supplied by the deployment but marked unreviewed']);
    await writeFile(join(h.dir, 'rr.pdf'), rf.get('records-request.pdf') as Uint8Array); assert.match(await tool('pdftotext', [join(h.dir, 'rr.pdf'), '-']), /Records sought/);
    // a pack with no records-request template and no authorities yields no legal basis at all
    const bare = h.make({ ...h.baseConfig, jurisdictionPacks: [{ id: 'bare', name: 'Bare pack', version: 1, authorities: [], documentTypes: { memo: { title: 'Memo', sections: [{ id: 'a', heading: 'Authorities', body: '{{authorities}}' }, { id: 'f', heading: 'Facts', body: '{{facts:established}}' }] } } }] });
    const br = await bare.buildRecordsRequest(ctx(), { title: 'Request', audience: 'records_holder', jurisdictionPackId: 'bare', recordsSought: ['Tender file'], formats: ['html'], requester: { name: 'Example Newsroom' }, recipient: { name: 'Records Officer' } });
    const bmd = plain(text(await files(bare, br.id), 'records-request.md'));
    assert.ok(bmd.includes(`no legal basis is stated: ${UNRESOLVED_AUTHORITY}`)); assert.doesNotMatch(bmd, /Act|Code|section \d/);
    const memo = plain(text(await files(bare, (await bare.buildLegalDraft(ctx(), { title: 'Memo', audience: 'legal_counsel', jurisdictionPackId: 'bare', documentType: 'memo', package: PKG, formats: ['html'] })).id), 'draft.md'));
    assert.match(memo, /## Authorities[\s\S]*\[authority to be identified by a qualified reviewer\]/); assert.match(memo, /All authorities: the jurisdiction pack supplies no authorities/);
    assert.equal(await code(bare.buildRecordsRequest(ctx(), { title: 'Request', audience: 'records_holder', jurisdictionPackId: 'bare', formats: ['html'], requester: { name: 'x' }, recipient: { name: 'y' } })), 'invalid_input');
    // professional review cannot be recorded on non-legal packages
    const chron = await engine.buildChronology(ctx(), { title: 'Chronology', audience: 'legal_counsel', package: PKG, formats: ['html', 'pdf'] });
    assert.equal(await code(engine.recordProfessionalReview(ctx(), chron.id, { ...review, candidateDigest: chron.digest as string })), 'invalid_state');
    const cf = await files(engine, chron.id); const cmd = plain(text(cf, 'chronology.md'));
    assert.ok(cmd.indexOf('2025-02-01') < cmd.indexOf('2025-03-03'), 'sorted by date'); assert.match(cmd, /\| 2025-02-01 \| Tender said to have been advertised \| DISPUTED \| \[S1\] \|/);
    await writeFile(join(h.dir, 'ch.pdf'), cf.get('chronology.pdf') as Uint8Array); assert.match((await tool('pdftotext', ['-raw', join(h.dir, 'ch.pdf'), '-'])).replace(/\s+/g, ' '), /Dredging contract signed/);

    // referral package: recipient-configured cover, chronology, evidence index, contact
    const ref = await engine.buildReferralPackage(ctx(), { title: 'Referral: dredging contract', audience: 'authority_referral', formats: ['html', 'pdf'], package: PKG, coverSummary: 'We refer the attached findings about the dredging contract for your assessment.',
      recipient: { name: 'Intake Unit', organization: 'Harbour Oversight Board (fictional)' }, contact: { name: 'Example Newsroom legal desk', contact: 'legal@example.org' },
      items: [{ ref: 'E05:evidence_version:photo-1@2', label: 'Quay photograph', redacted: { filename: 'quay.png', mediaType: 'image/png', base64: b64(await image(h.dir, 'quay.png', 'gray')) }, custody: [{ at: '2026-01-02T10:00:00Z', actor: 'Analyst', action: 'received' }] }] });
    assert.equal(ref.state, 'built', JSON.stringify(ref.leakReport));
    const ff = await files(engine, ref.id);
    assert.deepEqual([...ff.keys()], ['chronology.html', 'chronology.md', 'chronology.pdf', 'cover.html', 'cover.md', 'cover.pdf', 'custody.json', 'evidence-index.html', 'evidence-index.md', 'evidence-index.pdf', 'evidence/001-quay.png', 'manifest.json', 'thumbnails/evidence_001-quay.png.jpg']);
    const cover = plain(text(ff, 'cover.md')); assert.ok(cover.includes('Harbour Oversight Board (fictional)') && cover.includes('legal@example.org') && cover.includes('not a determination of wrongdoing'));
    for (const n of ['cover.pdf', 'chronology.pdf', 'evidence-index.pdf']) { await writeFile(join(h.dir, n), ff.get(n) as Uint8Array); assert.match(await tool('pdfinfo', [join(h.dir, n)]), /Pages:/); }
    assert.match(text(ff, 'cover.html'), /<html/); await reviewed(engine, ref.id);
    // untrusted text cannot inject markup
    const inj = await engine.buildInvestigationReport(ctx(), { title: 'Report <script>alert(1)</script>', audience: 'legal_counsel', formats: ['html'], package: { ...PKG, summary: '<img src=x onerror=alert(1)> [link](javascript:alert(1)) ![i](http://tracker.example.org/p.png)' } });
    const html = text(await files(engine, inj.id), 'report.html');
    assert.doesNotMatch(html, /<script>alert|<img src=x|href="javascript:|<img[^>]+tracker/); assert.match(html, /Content-Security-Policy/);
  });
});
