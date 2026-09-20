export const MAX_CHARS = 6000;
const lightRules = [
 ['in order to','to'],['due to the fact that','because'],['at this point in time','now'],
 ['in the event that','if'],['in spite of the fact that','although'],['with regard to','about'],
 ['with regards to','about'],['in regard to','about'],['on a daily basis','every day'],
 ['on a regular basis','regularly'],['for the purpose of','for'],['a large number of','many'],
 ['a small number of','a few'],['has the ability to','can'],['have the ability to','can'],
 ['it is possible that','perhaps'],['at the present time','now'],['in the near future','soon']
];
const plainRules = [
 ['utilize','use'],['utilizes','uses'],['utilized','used'],['utilizing','using'],
 ['commence','start'],['commences','starts'],['commenced','started'],
 ['subsequently','later'],['approximately','about'],['prior to','before'],
 ['in addition to','as well as'],['numerous','many'],['endeavor to','try to'],
 ['in close proximity to','near'],['in a timely manner','promptly']
];
const casualRules = [['we are',"we're"],['you are',"you're"],['they are',"they're"],
 ['it is',"it's"],['that is',"that's"],['do not',"don't"],['does not',"doesn't"],
 ['cannot',"can't"],['will not',"won't"],['we have',"we've"],['I am',"I'm"]];
const formalRules = [["don't",'do not'],["doesn't",'does not'],["can't",'cannot'],
 ["won't",'will not'],["we're",'we are'],["you're",'you are'],["they're",'they are']];
const escape = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
function casing(source, replacement) {
 if (source === source.toUpperCase()) return replacement.toUpperCase();
 if (source[0] === source[0].toUpperCase()) return replacement[0].toUpperCase()+replacement.slice(1);
 return replacement;
}
function protect(text, edit) {
 // Do not alter quoted passages, URLs, email addresses or inline/fenced code.
 const protectedParts = /(```[\s\S]*?```|`[^`\n]*`|"[^"\n]*"|“[^”]*”|https?:\/\/[^\s]+|\b[^\s@]+@[^\s@]+\b)/g;
 return text.split(protectedParts).map((part, i)=>i%2 ? part : edit(part)).join('');
}
function rewrite(text, rules) {
 const changes=[];
 const value=protect(text,part=>{
  for(const [from,to] of rules) {
   const re=new RegExp('(?<![\\p{L}\\p{N}_])'+escape(from)+'(?![\\p{L}\\p{N}_])','giu');
   part=part.replace(re, match=>{const replacement=casing(match,to);changes.push({from:match,to:replacement});return replacement;});
  }
  return part;
 });
 return {text:value,changes};
}
export function makeDrafts(source,tone='natural') {
 if(typeof source!=='string'||!source.trim())throw new Error('Paste some text first.');
 if(source.length>MAX_CHARS)throw new Error(`Use at most ${MAX_CHARS.toLocaleString()} characters at a time.`);
 if(!['natural','casual','formal'].includes(tone))throw new Error('Choose a supported tone.');
 const toneRules=tone==='casual'?casualRules:tone==='formal'?formalRules:[];
 const drafts=[{id:'original',label:'Original',text:source,changes:[]}];
 const specs=[['light','Light edit',[...lightRules,...toneRules]],['plain','Plain language',[...lightRules,...plainRules,...toneRules]]];
 for(const [id,label,rules] of specs){const draft=rewrite(source,rules);if(!drafts.some(d=>d.text===draft.text))drafts.push({id,label,...draft});}
 return drafts;
}
export function countWords(text){return text.trim()?text.trim().split(/\s+/u).length:0;}
