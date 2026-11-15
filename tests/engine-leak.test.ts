import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFile, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { zipRead } from '../src/engine/index.ts';
import { as, b64, code, ctx, FakeConsent, image, needsPg, pdf, PKG, PROTECTED, reviewed, soon, tool, withEngine } from './helpers/engine.ts';
import { run } from '../src/engine/tools.ts';

const has = (bytes: Uint8Array, needle: string): boolean => Buffer.from(bytes).toString('latin1').toLowerCase().includes(needle.toLowerCase()) || Buffer.from(bytes).includes(Buffer.from(needle, 'utf16le'));

test('leak prevention: protected name in PDF metadata, EXIF and thumbnail source is removed; in caption, filename or text it blocks the candidate', needsPg, async () => {
  await withEngine(async (h) => {
    const { engine } = h;
    const dirtyPdf = await pdf(h.dir, 'statement', '# Redacted statement\n\nThe witness saw the delivery on the quay.\n', { Author: PROTECTED, Title: `Statement of ${PROTECTED}`, Keywords: PROTECTED });
    assert.ok(has(dirtyPdf, PROTECTED), 'fixture really carries the name');
    const dirtyJpg = await image(h.dir, 'photo.jpg', 'black', { Artist: PROTECTED, 'XMP-dc:Creator': PROTECTED, Copyright: PROTECTED, UserComment: PROTECTED, GPSLatitude: '12.5', GPSLatitudeRef: 'N' });
    assert.ok(has(dirtyJpg, PROTECTED));
    const originalThumb = await image(h.dir, 'thumb.jpg', 'red', { Artist: PROTECTED }); // made from the unredacted original
    const items = [
      { ref: 'E05:evidence_version:stmt-1@2', label: 'Redacted witness statement', custody: [{ at: '2026-01-02T10:00:00Z', actor: 'Records officer', action: 'received' }, { at: '2026-01-03T10:00:00Z', actor: 'Analyst', action: 'redacted' }], redacted: { filename: 'statement-redacted.pdf', mediaType: 'application/pdf', base64: b64(dirtyPdf) } },
      { ref: 'E05:evidence_version:photo-1@2', label: 'Quay photograph (faces obscured)', altText: 'A dark photograph of the quay', redacted: { filename: 'quay.jpg', mediaType: 'image/jpeg', base64: b64(dirtyJpg) }, thumbnail: { filename: 'thumb.jpg', mediaType: 'image/jpeg', base64: b64(originalThumb) } },
    ];
    const c = await engine.buildEvidenceBundle(ctx(), { title: 'Quay evidence bundle', audience: 'legal_counsel', items, protectedTerms: [PROTECTED], formats: ['html', 'pdf'] });
    assert.equal(c.state, 'built', JSON.stringify(c.leakReport));
    const zip = await engine.exportCandidateZip(ctx(), c.id);
    const entries = zipRead(zip.bytes);
    for (const e of entries) assert.ok(!has(e.bytes, PROTECTED) && !has(e.bytes, 'Quenby'), `${e.path} is clean`);
    const get = (p: string): Uint8Array => entries.find((e) => e.path === p)?.bytes as Uint8Array;
    assert.deepEqual(entries.map((e) => e.path), ['custody.json', 'evidence/001-statement-redacted.pdf', 'evidence/002-quay.jpg', 'index.html', 'index.md', 'index.pdf', 'manifest.json', 'thumbnails/evidence_002-quay.jpg.jpg']);
    // metadata really gone when re-read by an independent exiftool run
    const outPdf = join(h.dir, 'out.pdf'), outJpg = join(h.dir, 'out.jpg'), outThumb = join(h.dir, 'out-thumb.jpg');
    await writeFile(outPdf, get('evidence/001-statement-redacted.pdf')); await writeFile(outJpg, get('evidence/002-quay.jpg')); await writeFile(outThumb, get('thumbnails/evidence_002-quay.jpg.jpg'));
    const pdfTags = await tool('exiftool', ['-a', '-G1', outPdf]); assert.doesNotMatch(pdfTags, /Author|Title|Keywords|Quenby/);
    assert.match(await tool('pdftotext', [outPdf, '-']), /witness saw the delivery/);
    const jpgTags = await tool('exiftool', ['-a', '-G1', outJpg]); assert.doesNotMatch(jpgTags, /Artist|Creator|Copyright|GPS|UserComment|Quenby/);
    // the released thumbnail is regenerated from the redacted (black) image, not the supplied one made from the original (red)
    const mean = (await run('convert', [outThumb, '-format', '%[fx:mean.r]', 'info:'])).stdout.toString('utf8');
    assert.ok(Number(mean) < 0.1, `thumbnail red channel ${mean}`);
    assert.doesNotMatch(await tool('exiftool', ['-a', '-G1', outThumb]), /Artist|Quenby/);
    const manifest = JSON.parse(new TextDecoder().decode(get('manifest.json'))) as { redactionManifest: { path: string; action: string }[]; leakScan: { protectedTermCount: number }; components: { path: string; sha256: string }[] };
    const actions = manifest.redactionManifest.map((r) => `${r.action}:${r.path}`);
    for (const a of ['pdf_rewritten:evidence/001-statement-redacted.pdf', 'metadata_stripped:evidence/002-quay.jpg', 'supplied_thumbnail_discarded:supplied-thumbnails/002-thumb.jpg', 'thumbnail_regenerated:thumbnails/evidence_002-quay.jpg.jpg']) assert.ok(actions.includes(a), a);
    assert.equal(manifest.leakScan.protectedTermCount, 1);
    // the index lists the digest of the bytes actually released
    const index = new TextDecoder().decode(get('index.md'));
    for (const m of manifest.components.filter((x) => x.path.startsWith('evidence/'))) assert.ok(index.includes(m.sha256));
    assert.match(index, /2 event\(s\); first/);
    // the term is stored only as a salted hash, and never reaches search or audit
    const row = (await h.sql.query(`select term_hashes, term_salt, leak_report::text as lr, index_text, manifest::text as m from e12_release.candidates where id=$1`, [c.id]))[0] as Record<string, string>;
    assert.equal(row.term_hashes?.length, 1); assert.doesNotMatch(JSON.stringify(row), /Quenby/i);
    assert.deepEqual(await engine.search(ctx(), { q: 'Quenby' }), []);
    assert.doesNotMatch(JSON.stringify(await engine.audit(ctx())), /Quenby/i);

    // each text surface blocks, with a located finding that does not repeat the term
    const blocked = async (label: string, p: Promise<{ id: string; state: string; leakReport: unknown; components: unknown[] }>, expect: { code: string; field?: string; path?: string; line?: number }): Promise<void> => {
      const b = await p;
      assert.equal(b.state, 'leak_blocked', label); assert.equal(b.components.length, 0);
      const findings = (b.leakReport as { findings: { code: string; field: string; path: string; line?: number }[] }).findings;
      assert.ok(findings.some((f) => f.code === expect.code && (expect.field === undefined || f.field === expect.field) && (expect.path === undefined || f.path === expect.path) && (expect.line === undefined || f.line === expect.line)), `${label}: ${JSON.stringify(findings)}`);
      assert.doesNotMatch(JSON.stringify(b.leakReport), /Quenby/i);
      assert.equal(await code(engine.exportCandidateZip(ctx(), b.id)), 'invalid_state');
      assert.equal(await code(engine.submitForReview(ctx(), b.id, { reviewers: ['rev-1'] })), 'invalid_state');
      assert.deepEqual(await h.objects.list(`t1/p1/candidates/${b.id}`), [], 'nothing stored for a blocked candidate');
    };
    const cleanJpg = await image(h.dir, 'clean.jpg', 'black');
    const mp4 = join(h.dir, 'clip.mp4');
    await run('ffmpeg', ['-v', 'error', '-f', 'lavfi', '-i', 'testsrc=d=1:s=160x120:r=10', '-metadata', `title=${PROTECTED}`, '-metadata', `artist=${PROTECTED}`, '-y', mp4]);
    const clip = new Uint8Array(await readFile(mp4)); assert.ok(has(clip, PROTECTED));
    const render = { ref: 'E10:render:r-1@1', label: 'Explainer clip', file: { filename: 'clip.mp4', mediaType: 'video/mp4', base64: b64(clip) }, manifest: { renderer: 'e10', scenes: 1 }, altText: 'Test pattern video' };
    await blocked('caption', engine.buildMediaPackage(ctx(), { title: 'Media', audience: 'internal_review', protectedTerms: [PROTECTED], formats: ['html'], renders: [{ ...render, captions: [{ language: 'en', format: 'vtt', text: `WEBVTT\n\n00:00.000 --> 00:01.000\nThe harbour at dawn.\n\n00:01.000 --> 00:02.000\nFilmed by ${PROTECTED.toUpperCase()}.\n` }] }] }), { code: 'protected_term_in_text', path: 'captions/001.en.vtt', line: 7 });
    await blocked('filename', engine.buildEvidenceBundle(ctx(), { title: 'Bundle', audience: 'legal_counsel', protectedTerms: [PROTECTED], formats: ['html'], items: [{ ref: 'E05:evidence_version:photo-1@2', label: 'Photo', redacted: { filename: 'Marisol_Quenby-quay.jpg', mediaType: 'image/jpeg', base64: b64(cleanJpg) } }] }), { code: 'protected_term_in_filename', field: 'supplied_filename', path: '[withheld: contains a protected term]' });
    await blocked('camel filename', engine.buildEvidenceBundle(ctx(), { title: 'Bundle', audience: 'legal_counsel', protectedTerms: [PROTECTED], formats: ['html'], items: [{ ref: 'E05:evidence_version:photo-1@2', label: 'Photo', redacted: { filename: 'MarisolQuenby.jpg', mediaType: 'image/jpeg', base64: b64(cleanJpg) } }] }), { code: 'protected_term_in_filename' });
    await blocked('alt text', engine.buildEvidenceBundle(ctx(), { title: 'Bundle', audience: 'legal_counsel', protectedTerms: [PROTECTED], formats: ['html'], items: [{ ref: 'E05:evidence_version:photo-1@2', label: 'Photo', altText: `Portrait of ${PROTECTED}`, redacted: { filename: 'q.jpg', mediaType: 'image/jpeg', base64: b64(cleanJpg) } }] }), { code: 'protected_term_in_alt_text' });
    await blocked('manifest title', engine.buildChronology(ctx(), { title: `Chronology for ${PROTECTED}`, audience: 'legal_counsel', protectedTerms: [PROTECTED], formats: ['html'], package: PKG }), { code: 'protected_term_in_manifest', field: 'title' });
    await blocked('document text', engine.buildInvestigationReport(ctx(), { title: 'Report', audience: 'legal_counsel', protectedTerms: [PROTECTED], formats: ['html', 'pdf'], package: { ...PKG, findings: [...PKG.findings, { id: 'F4', status: 'unknown', statement: `It is not known whether Marisol   QUENBY was present.` }] } }), { code: 'protected_term_in_text', path: 'report.pdf' });
    const visiblePdf = await pdf(h.dir, 'named', `# Statement\n\nGiven by ${PROTECTED} on the quay.\n`);
    await blocked('pdf body', engine.buildEvidenceBundle(ctx(), { title: 'Bundle', audience: 'legal_counsel', protectedTerms: [PROTECTED], formats: ['html'], items: [{ ref: 'E05:evidence_version:stmt-1@2', label: 'Statement', redacted: { filename: 's.pdf', mediaType: 'application/pdf', base64: b64(visiblePdf) } }] }), { code: 'protected_term_in_text', path: 'evidence/001-s.pdf' });
    await blocked('disguised type', engine.buildEvidenceBundle(ctx(), { title: 'Bundle', audience: 'legal_counsel', formats: ['html'], items: [{ ref: 'E05:evidence_version:stmt-1@2', label: 'Statement', redacted: { filename: 's.jpg', mediaType: 'image/jpeg', base64: b64(visiblePdf) } }] }), { code: 'unsupported_component_type' });
    // originals are never released by default
    await blocked('original', engine.buildEvidenceBundle(ctx(), { title: 'Bundle', audience: 'legal_counsel', formats: ['html'], items: [{ ref: 'E05:evidence_version:photo-1@1', label: 'Photo', includeOriginal: true, original: { filename: 'o.jpg', mediaType: 'image/jpeg', base64: b64(cleanJpg) } }] }), { code: 'original_not_permitted' });
    const fallback = await engine.buildEvidenceBundle(ctx(), { title: 'Bundle', audience: 'legal_counsel', formats: ['html'], items: [{ ref: 'E05:evidence_version:photo-1@1', label: 'Photo', includeOriginal: true, original: { filename: 'o.jpg', mediaType: 'image/jpeg', base64: b64(await image(h.dir, 'orig.jpg', 'red')) }, redacted: { filename: 'r.jpg', mediaType: 'image/jpeg', base64: b64(cleanJpg) } }] });
    assert.equal(fallback.components.find((x) => x.path.startsWith('evidence/'))?.class, 'redacted_derivative'); assert.equal(fallback.components.find((x) => x.path.startsWith('evidence/'))?.path, 'evidence/001-r.jpg');
    const consent = new FakeConsent();
    const permissive = h.make({ ...h.baseConfig, audiences: { legal_counsel: { class: 'restricted', allowOriginals: true } } }, { useDecision: consent });
    const item = { ref: 'E05:evidence_version:photo-1@1', label: 'Photo', includeOriginal: true, original: { filename: 'o.jpg', mediaType: 'image/jpeg', base64: b64(await image(h.dir, 'orig2.jpg', 'red', { Artist: 'Someone' })) }, redacted: { filename: 'r.jpg', mediaType: 'image/jpeg', base64: b64(cleanJpg) } };
    const withOriginal = await permissive.buildEvidenceBundle(ctx(), { title: 'Bundle', audience: 'legal_counsel', formats: ['html'], items: [item] });
    assert.equal(withOriginal.components.find((x) => x.path.startsWith('evidence/'))?.class, 'original');
    consent.denied.add('E05:evidence_version:photo-1@1');
    assert.equal((await permissive.buildEvidenceBundle(ctx(), { title: 'Bundle', audience: 'legal_counsel', formats: ['html'], items: [item] })).components.find((x) => x.path.startsWith('evidence/'))?.class, 'redacted_derivative');

    // media package: container metadata removed, captions kept, files open
    const media = await engine.buildMediaPackage(ctx(), { title: 'Harbour explainer', audience: 'internal_review', protectedTerms: [PROTECTED], formats: ['html'], renders: [{ ...render, captions: [{ language: 'en', format: 'vtt', text: 'WEBVTT\n\n00:00.000 --> 00:01.000\nThe harbour at dawn.\n' }] }], credits: [{ role: 'Editor', name: 'Example Newsroom' }], disclosures: ['Contains a reconstruction.'], rightsSummary: [{ subject: 'E10:asset:music-1', holder: 'Example Library', license: 'Example licence 1.0' }] });
    assert.equal(media.state, 'built', JSON.stringify(media.leakReport));
    const mz = zipRead((await engine.exportCandidateZip(ctx(), media.id)).bytes);
    assert.deepEqual(mz.map((e) => e.path), ['captions/001.en.vtt', 'credits.json', 'index.html', 'index.md', 'manifest.json', 'media/001-clip.mp4', 'render-manifests/001.json', 'rights-summary.json', 'thumbnails/media_001-clip.mp4.jpg']);
    for (const e of mz) assert.ok(!has(e.bytes, 'Quenby'), e.path);
    const outMp4 = join(h.dir, 'out.mp4'); await writeFile(outMp4, mz.find((e) => e.path === 'media/001-clip.mp4')?.bytes as Uint8Array);
    assert.match(await tool('ffprobe', ['-v', 'error', '-show_entries', 'format=duration:format_tags', '-of', 'json', outMp4]), /"duration": "1\.0/);
    assert.doesNotMatch(await tool('ffprobe', ['-v', 'error', '-show_entries', 'format_tags', '-of', 'json', outMp4]), /title|artist/i);
    const mi = new TextDecoder().decode(mz.find((e) => e.path === 'index.md')?.bytes); assert.match(mi, /Example Newsroom/); assert.match(mi, /Contains a reconstruction/); assert.match(mi, /Example licence/);

    const eng = h.make(h.baseConfig, { useDecision: new FakeConsent() });
    // release-time re-check: terms must be supplied again, and a changed byte blocks the release and voids the approval
    const dest = await eng.createDestination(ctx(), { name: 'portal', kind: 'local_directory', audiences: ['legal_counsel'], config: { root: 'portal' } });
    const digest = await reviewed(eng, c.id);
    assert.equal(await code(engine.approve(ctx(), c.id, { candidateDigest: digest, audience: 'legal_counsel', destinationId: dest.id, expiresAt: soon() })), 'consent_denied', 'no consent service: fail closed');
    const approval = await eng.approve(ctx(), c.id, { candidateDigest: digest, audience: 'legal_counsel', destinationId: dest.id, expiresAt: soon() });
    assert.equal(await code(eng.release(ctx(), c.id, { approvalId: approval.id, audience: 'legal_counsel', destinationId: dest.id })), 'invalid_state', 'terms not supplied');
    assert.equal(await code(eng.release(ctx(), c.id, { approvalId: approval.id, audience: 'legal_counsel', destinationId: dest.id, protectedTerms: ['Somebody Else'] })), 'invalid_state');
    assert.equal(await code(eng.release(ctx(), c.id, { approvalId: approval.id, audience: 'legal_counsel', destinationId: dest.id, protectedTerms: [PROTECTED], recipients: [`Desk of ${PROTECTED}`] })), 'invalid_input');
    const key = `t1/p1/candidates/${c.id}/files/index.md`;
    const original = await h.objects.get(key); const tampered = Uint8Array.from(original); tampered[10] = (tampered[10] as number) ^ 1;
    await h.objects.delete(key); await h.objects.put(key, tampered);
    assert.equal(await code(eng.release(ctx(), c.id, { approvalId: approval.id, audience: 'legal_counsel', destinationId: dest.id, protectedTerms: [PROTECTED] })), 'approval_invalid');
    assert.equal((await eng.listApprovals(ctx(), c.id))[0]?.state, 'invalid'); assert.equal((await eng.listApprovals(ctx(), c.id))[0]?.invalidReason, 'content_changed');
    const after = await eng.getCandidate(ctx(), c.id); assert.equal(after.blocked, true);
    assert.deepEqual(await eng.listReleases(ctx(), { candidateId: c.id }), []);
    assert.equal(await code(eng.approve(as('owner-2'), c.id, { candidateDigest: digest, audience: 'legal_counsel', destinationId: dest.id, expiresAt: soon() })), 'approval_invalid');
  });
});
