import test from'node:test';import assert from'node:assert/strict';import{createReleaseState,propose,approve,checkRelease,setReleasePolicy,preparePrivateExport,beginDispatch,recordDelivery,invalidate,recordWithdrawal}from'../src/index.ts';import type{Artifact,CurrentInputs}from'../src/index.ts';import type{Context}from'../src/contracts.ts';
const c:Context={tenantId:'alpha',projectId:'study',actor:{id:'owner',kind:'human',roles:['owner']},purpose:'education',requestId:'r',now:'2026-01-01T00:00:00Z'};const bind=(id:string)=>({ref:{tenantId:'alpha',projectId:'study',kind:'artifact',id,revision:1},sha256:'a'.repeat(64)});const artifact:Artifact={...bind('film'),label:'Fictional short',sourceBindings:[bind('source')],visibility:'private',rightsDecision:bind('rights'),consentDecision:bind('consent'),editorialDecision:bind('review')};const inputs:CurrentInputs={artifacts:[artifact],rightsAllowed:true,consentAllowed:true,editorialApproved:true,policyRevision:1};const setup=(external=false)=>propose(c,createReleaseState(c,['owner']),{id:'package',artifacts:[artifact],audience:external?'public':'private-review',destination:external?'publisher':'private-archive',external});
test('private package requires exact human authorization and retains original proposal',()=>{const s=setup();assert.throws(()=>preparePrivateExport(c,s,'package',inputs));const n=approve(c,s,'package',inputs,'2026-01-01T00:10:00Z');assert.equal(n.manifests.length,2);assert.equal(s.manifests[0]!.approval,null);assert.ok(preparePrivateExport(c,n,'package',inputs));assert.throws(()=>approve({...c,actor:{...c.actor,kind:'agent'}},s,'package',inputs,'2026-01-01T00:10:00Z'));});
test('external publication fails closed by default and exact destination must be enabled',()=>{const s=setup(true);assert.throws(()=>approve(c,s,'package',inputs,'2026-01-01T00:10:00Z'),{code:'publisher_disabled'});const enabled=setReleasePolicy(c,s,{expectedRevision:1,externalEnabled:true,allowedDestinations:['other'],reason:'Fictional test'});assert.throws(()=>approve(c,enabled,'package',{...inputs,policyRevision:2},'2026-01-01T00:10:00Z'));});
test('changed bytes source rights consent policy expiry or adverse decisions invalidate release',()=>{const n=approve(c,setup(),'package',inputs,'2026-01-01T00:10:00Z');for(const next of[{...inputs,rightsAllowed:false},{...inputs,consentAllowed:false},{...inputs,editorialApproved:false},{...inputs,artifacts:[{...artifact,sha256:'b'.repeat(64)}]},{...inputs,artifacts:[{...artifact,sourceBindings:[{...bind('source'),ref:{...bind('source').ref,revision:2}}]}]}])assert.throws(()=>checkRelease(c,n,'package',next));assert.throws(()=>checkRelease({...c,now:'2026-01-01T00:10:00Z'},n,'package',inputs));const changed=setReleasePolicy(c,n,{expectedRevision:1,externalEnabled:false,allowedDestinations:[],reason:'Policy changed'});assert.throws(()=>checkRelease(c,changed,'package',{...inputs,policyRevision:2}));});
test('uncertain external delivery is fenced against blind retry and corrected content is withdrawn',()=>{let s=setReleasePolicy(c,setup(true),{expectedRevision:1,externalEnabled:true,allowedDestinations:['publisher'],reason:'Fictional test approval'});const now={...inputs,policyRevision:2};s=approve(c,s,'package',now,'2026-01-01T00:10:00Z');s=beginDispatch(c,s,'package',now,'handoff');s=recordDelivery(c,s,'package','handoff',null);assert.throws(()=>beginDispatch(c,s,'package',now,'retry'));s=recordDelivery(c,s,'package','handoff',bind('receipt'));s=invalidate(c,s,bind('source'),'Source correction');assert.equal(s.manifests.at(-1)!.state,'withdrawal-required');s=recordWithdrawal(c,s,'package',bind('withdrawal-receipt'));assert.equal(s.manifests.at(-1)!.state,'withdrawn');assert.equal(s.manifests[0]!.state,'proposed');});
test('cross-scope source and mixed artifact editions cannot enter a package',()=>{assert.throws(()=>propose(c,createReleaseState(c,['owner']),{id:'bad',artifacts:[{...artifact,sourceBindings:[{...bind('source'),ref:{...bind('source').ref,tenantId:'beta'}}]}],audience:'private',destination:'archive',external:false}));assert.throws(()=>propose(c,createReleaseState(c,['owner']),{id:'bad',artifacts:[artifact,artifact],audience:'private',destination:'archive',external:false}));});

test('a viewer cannot operate the external gateway',()=>{const viewer={...c,actor:{...c.actor,roles:['viewer']}};assert.throws(()=>recordDelivery(viewer,setup(),'package','fake',null),{code:'gateway_required'});});

test('proposal binds the same artifact snapshot that passed scope validation',()=>{
 let reads=0;
 const supplied={...artifact,get ref(){return ++reads<=4?artifact.ref:{...artifact.ref,tenantId:'beta'};}};
 const state=propose(c,createReleaseState(c,['owner']),{id:'snapshot',artifacts:[supplied],audience:'private-review',destination:'archive',external:false});
 assert.equal(reads,1);assert.deepEqual(state.manifests[0]!.artifacts[0]!.ref,artifact.ref);
});

test('proposal identity and destination fields are read once before validation',()=>{
 let idReads=0,destinationReads=0,externalReads=0;
 const proposal={get id(){return ++idReads<=2?'new':'package';},artifacts:[artifact],audience:'private-review',
  get destination(){return ++destinationReads===1?'archive':'';},get external(){return ++externalReads===1?false:true;}};
 const state=propose(c,setup(),proposal);
 assert.equal(idReads,1);assert.equal(destinationReads,1);assert.equal(externalReads,1);
 assert.equal(state.manifests.at(-1)!.id,'new');assert.equal(state.manifests.at(-1)!.destination,'archive');assert.equal(state.manifests.at(-1)!.external,false);
});

test('nested cross-scope decisions are rejected from the captured proposal and caller buffers remain detached',()=>{
 const proposal={id:'snapshot',artifacts:[structuredClone(artifact)],audience:'review',destination:'archive',external:false};
 const state=propose(c,createReleaseState(c,['owner']),proposal);
 proposal.artifacts[0]!.label='changed';proposal.artifacts[0]!.sourceBindings[0]!.ref.id='changed';
 assert.equal(state.manifests[0]!.artifacts[0]!.label,artifact.label);
 assert.equal(state.manifests[0]!.artifacts[0]!.sourceBindings[0]!.ref.id,'source');
 const bad={...artifact,rightsDecision:{...bind('rights'),ref:{...bind('rights').ref,projectId:'other'}}};
 assert.throws(()=>propose(c,createReleaseState(c,['owner']),{...proposal,artifacts:[bad]}),{code:'scope_denied'});
});
