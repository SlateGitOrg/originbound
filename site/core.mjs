
const n=(value,fallback=0)=>Number.isFinite(Number(value))?Number(value):fallback;
const clamp=(value,low,high)=>Math.min(high,Math.max(low,value));
const round=(value,digits=2)=>Number(value.toFixed(digits));
const mean=values=>values.length?values.reduce((sum,value)=>sum+value,0)/values.length:0;
const parseJSON=(value,fallback=[])=>{try{return JSON.parse(value)}catch{return fallback}};
const valuesFrom=value=>String(value).split(/[\s,]+/).map(Number).filter(Number.isFinite);
const result=(status,summary,metrics,rows,detail='')=>({status,summary,metrics,rows,detail});
const erf=x=>{const sign=x<0?-1:1,a=Math.abs(x),t=1/(1+0.3275911*a);const y=1-(((((1.061405429*t-1.453152027)*t)+1.421413741)*t-0.284496736)*t+0.254829592)*t*Math.exp(-a*a);return sign*y};
const normalCdf=z=>0.5*(1+erf(z/Math.sqrt(2)));
const wilson=(successes,total)=>{if(!total)return[0,0];const z=1.96,p=successes/total,d=1+z*z/total,c=(p+z*z/(2*total))/d,h=z*Math.sqrt((p*(1-p)+z*z/(4*total))/total)/d;return[clamp(c-h,0,1),clamp(c+h,0,1)]};
const sha256=async value=>{const bytes=new TextEncoder().encode(String(value));const digest=await crypto.subtle.digest('SHA-256',bytes);return[...new Uint8Array(digest)].map(byte=>byte.toString(16).padStart(2,'0')).join('')};
const tag=(xml,name)=>xml.match(new RegExp('<'+name+'[^>]*>([\\s\\S]*?)<\\/'+name+'>','i'))?.[1]?.trim()??'';
const similarity=(a,b)=>{const x=String(a).toLowerCase(),y=String(b).toLowerCase();if(x===y)return 1;const A=new Set(x.split(/\W+/).filter(Boolean)),B=new Set(y.split(/\W+/).filter(Boolean));const inter=[...A].filter(v=>B.has(v)).length;return inter/Math.max(1,new Set([...A,...B]).size)};

export const meta={"slug":"originbound","name":"Origin Bound","eyebrow":"Authentication relay lab","description":"Run the same relay against TOTP and WebAuthn to expose the protocol field that changes the result.","fields":[{"name":"method","label":"Authentication method","type":"select","options":["TOTP","WebAuthn"],"help":""},{"name":"origin","label":"Browser origin","type":"select","options":["https://bank.example","https://bank.example.evil","https://login.bank.example"],"help":""},{"name":"rpId","label":"Relying-party ID","type":"textarea","rows":2,"help":""},{"name":"timeStep","label":"TOTP time step","type":"number","min":1,"max":999999,"step":1,"help":""}]};
export const initialState={"method":"WebAuthn","origin":"https://bank.example.evil","rpId":"bank.example","timeStep":123456};
export const alternateState={"method":"TOTP","origin":"https://bank.example.evil","rpId":"bank.example","timeStep":123456};
export async function compute(i){const host=(()=>{try{return new URL(i.origin).hostname}catch{return''}})(),rp=String(i.rpId).toLowerCase(),originBound=host===rp||host.endsWith(`.${rp}`),webauthn=i.method==='WebAuthn',success=webauthn?originBound:true,status=success?'Authentication accepted':'Relay blocked';return result(status,webauthn?(originBound?'WebAuthn assertion is bound to the legitimate RP ID.':'WebAuthn rejects the attacker origin before the assertion is accepted.'):'TOTP supplies a transferable code, so the relay succeeds.',[{label:'Method',value:i.method},{label:'Origin host',value:host||'Invalid'},{label:'RP ID match',value:originBound?'Yes':'No'},{label:'Relay outcome',value:success?'Succeeds':'Blocked'}],[{protocol:'TOTP',originChecked:'No',relay:'Succeeds'},{protocol:'WebAuthn',originChecked:'Yes',relay:originBound?'Legitimate request':'Blocked'}],`TOTP step ${n(i.timeStep)} has no origin binding.`)}
