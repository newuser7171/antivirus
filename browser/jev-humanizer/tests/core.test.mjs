import test from 'node:test';import assert from 'node:assert/strict';
import {makeDrafts,MAX_CHARS,countWords} from '../src/engine.js';
import {buildRequest,parseResponse,evaluate} from '../src/jev.js';
const source='We are ready to utilize this tool in order to save 12 hours.';
const drafts=makeDrafts(source,'casual');
function answer(choice='plain',confidence=.9,meaning=.98){const probabilities={};for(const d of drafts)probabilities[d.id]=d.id===choice?1:0;const answers={best:{type:'choice',choice,confidence,probabilities}};for(const d of drafts)if(d.id!=='original')answers['meaning_'+d.id]={type:'noul',noul:meaning};return {model:'fixture',answers};}
test('local edits improve a verbose sentence',()=>assert.equal(drafts.at(-1).text,"We're ready to use this tool to save 12 hours."));
test('original is retained exactly',()=>assert.equal(drafts[0].text,source));
test('quoted text, links, code and email are preserved',()=>{
 const s='"utilize in order to" `utilize` https://example.org/utilize?a=utilize utilize@example.com We utilize it.';
 const result=makeDrafts(s).at(-1).text;assert.ok(result.startsWith('"utilize in order to" `utilize` https://example.org/utilize?a=utilize utilize@example.com'));assert.ok(result.endsWith('We use it.'));
});
test('negation and numbers are retained',()=>assert.equal(makeDrafts('We do not utilize 3.5 kg before 12:30.','casual').at(-1).text,"We don't use 3.5 kg before 12:30."));
test('word boundaries prevent replacements inside identifiers',()=>assert.equal(makeDrafts('preutilized utilized_name Xutilize utilizer')[0].text,'preutilized utilized_name Xutilize utilizer'));
test('nonmatching and non-English text stay unchanged',()=>{assert.equal(makeDrafts('Përshëndetje, si je?').length,1);assert.equal(makeDrafts('Hello.').length,1);});
test('empty and oversized source rejected',()=>{assert.throws(()=>makeDrafts(' '));assert.throws(()=>makeDrafts('x'.repeat(MAX_CHARS+1)));});
test('case handling preserves upper case',()=>assert.equal(makeDrafts('UTILIZE this.').at(-1).text,'USE this.'));
test('formal tone expands supported contractions',()=>assert.equal(makeDrafts("We don't do that.",'formal').at(-1).text,'We do not do that.'));
test('request excludes credentials and webpage details',()=>{const r=buildRequest(source,'casual',drafts);assert.deepEqual(Object.keys(r.state),['source','tone','candidates']);assert.equal(r.model,'jev-latest');assert.equal(Object.keys(r.questions).length,drafts.length);});
test('duplicate, unknown and oversized candidates rejected',()=>{assert.throws(()=>buildRequest(source,'casual',[drafts[0],drafts[0]]));assert.throws(()=>buildRequest(source,'casual',[drafts[0],{id:'alien',text:'x'}]));assert.throws(()=>buildRequest(source,'casual',[drafts[0],{id:'plain',text:'x'.repeat(12001)}]));});
test('good recommendation is eligible for user preview',()=>assert.equal(parseResponse(answer(),drafts).sufficient,true));
test('poor meaning preservation is not recommended',()=>assert.equal(parseResponse(answer('plain',.9,.6),drafts).sufficient,false));
test('uncertain choice is not recommended',()=>assert.equal(parseResponse(answer('plain',.4,.98),drafts).sufficient,false));
test('original can be preferred without edits',()=>assert.equal(parseResponse(answer('original'),drafts).choice,'original'));
test('missing judgments are rejected rather than defaulted',()=>{const r=answer();delete r.answers.meaning_plain;assert.throws(()=>parseResponse(r,drafts));});
test('numeric strings and out-of-range values rejected',()=>{const r=answer();r.answers.meaning_plain.noul='0.99';assert.throws(()=>parseResponse(r,drafts));assert.throws(()=>parseResponse(answer('plain',1.1),drafts));});
test('invalid distribution rejected',()=>{const r=answer();r.answers.best.probabilities.original=1;assert.throws(()=>parseResponse(r,drafts));});
test('choice must have highest probability',()=>{const r=answer();r.answers.best.choice='light';assert.throws(()=>parseResponse(r,drafts));});
test('network request goes only to TypeSafe',async()=>{
 let call;const result=await evaluate(source,'casual',drafts,'test-key',undefined,async(url,options)=>{call={url,options};return new Response(JSON.stringify(answer()),{status:200});});
 assert.equal(call.url,'https://api.typesafe.ai/v1/systemone');assert.equal(call.options.headers.Authorization,'Bearer test-key');assert.equal(call.options.redirect,'error');assert.equal(call.options.credentials,'omit');assert.ok(!call.options.body.includes('test-key'));assert.equal(result.choice,'plain');
});
test('authentication and malformed response failures are visible',async()=>{
 await assert.rejects(()=>evaluate(source,'casual',drafts,'test-key',undefined,async()=>new Response('secret body',{status:401})),/rejected the key/);
 await assert.rejects(()=>evaluate(source,'casual',drafts,'test-key',undefined,async()=>new Response('not JSON',{status:200})),/unreadable/);
 await assert.rejects(()=>evaluate(source,'casual',drafts,'test-key',undefined,async()=>new Response('x'.repeat(65537),{status:200})),/size limit/);
});
test('empty keys do not send requests',async()=>{let called=false;await assert.rejects(()=>evaluate(source,'casual',drafts,'',undefined,async()=>{called=true;}));assert.equal(called,false);});
test('word counting handles whitespace',()=>{assert.equal(countWords('  one\n two '),2);assert.equal(countWords(''),0);});
