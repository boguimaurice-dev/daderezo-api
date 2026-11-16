const {JSDOM,VirtualConsole}=require('jsdom');
const fs=require('fs'); const assert=require('assert');
let errors=[], googleCallback, submitted=[], disabledGoogle=false;
const vc=new VirtualConsole(); vc.on('jsdomError', e=> { if(!e.message.includes('navigation')) errors.push(e.message); });
const dom=new JSDOM(fs.readFileSync('DADEREZO.html','utf8'),{
 url:'https://daderezo.test/ui',runScripts:'dangerously',virtualConsole:vc,
 beforeParse(w){
  w.matchMedia=()=>({matches:false,addEventListener(){},addListener(){}});
  w.setInterval=()=>0; w.alert=()=>{}; w.confirm=()=>true;
  w.HTMLCanvasElement.prototype.getContext=()=>new Proxy({createLinearGradient:()=>({addColorStop(){}})}, {get:(o,p)=>o[p]||(()=>{})});
  w.fetch=async(url,opts={})=>{
   const path=new URL(url,w.location.href).pathname;
   let data={};
   if(path==='/auth/me')data={authenticated:false};
   if(path==='/auth/google/config')data={enabled:!disabledGoogle,client_id:'test.apps.googleusercontent.com',nonce:'test-nonce',message:'Google non configuré'};
   if(path==='/auth/google'){submitted.push(JSON.parse(opts.body));data={status:'2fa_required',temp_token:'temp-test'};}
   if(path==='/auth/2fa/setup')data={secret:'TESTSECRET',enrollment_token:'signed-enroll',formatted_secret:'TEST SECRET',qr_code_data_uri:'data:image/svg+xml;base64,PHN2Zy8+'};
   if(path==='/agents')data={agents:[]};
   return {ok:true,status:200,json:async()=>data};
  };
  const append=w.HTMLHeadElement.prototype.appendChild;
  w.HTMLHeadElement.prototype.appendChild=function(node){
   if(node.src?.includes('accounts.google.com/gsi/client')){
    w.google={accounts:{id:{initialize(config){googleCallback=config.callback;assert.equal(config.nonce,'test-nonce')},renderButton(el){el.textContent='Continuer avec Google';}}}};
    setTimeout(()=>node.onload(),0);return node;
   }
   return append.call(this,node);
  };
 }
});
const w=dom.window; const wait=()=>new Promise(r=>setTimeout(r,60));
(async()=>{
 await wait();
 w.document.getElementById('authAccountBtn').click();await wait();
 assert.equal(typeof googleCallback,'function');
 await googleCallback({credential:'real-credential-from-gis'});
 assert.equal(submitted[0].id_token,'real-credential-from-gis');assert(!submitted[0].user_info);
 assert(!w.document.getElementById('auth2faBox').classList.contains('hidden'));
 w.document.getElementById('cancel2faBtn').click();
 w.eval("applyAuthUserUI({email:'user@example.org',org_name:'Org',org_slug:'org',probe_api_key:'key',totp_enabled:false,auth_provider:'local'})");
 w.document.getElementById('authAccountBtn').click();
 w.document.getElementById('startTotpSetupBtn').click();await wait();
 assert(w.document.getElementById('totpQrCode').src.startsWith('data:image/svg+xml;base64,'));
 w.document.getElementById('closeTotpSetupBtn').click();
 assert(!w.document.getElementById('totpQrCode').hasAttribute('src'));
 w.eval('applyWorkspaceChrome()');
 assert.equal(w.document.body.getAttribute('data-workspace'),'work');
 for(const id of ['homePageLink','homePageTopLink']){const a=w.document.getElementById(id);assert.equal(a.getAttribute('href'),'/');assert(!a.hasAttribute('data-sim-only'));}
 assert.deepEqual(errors,[]);
 console.log('DOM checks passed: GIS credential + 2FA challenge, local QR + cleanup, home links in work mode, no JS initialization errors.');
 dom.window.close();
})().catch(e=>{console.error(e);dom.window.close();process.exitCode=1;});
