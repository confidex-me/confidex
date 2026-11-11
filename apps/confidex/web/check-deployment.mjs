import assert from 'node:assert/strict';
import {mkdir, writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
import {runBrowser} from '../../../tools/browser-run.mjs';
const [chrome, remoteUrl, shots='/tmp/confidex-deployment-screens'] = process.argv.slice(2);
assert.equal(new URL(remoteUrl).protocol, 'https:');
await mkdir(shots, {recursive:true});
const results=[];
for(const [width, languages, expected] of [[1180,['ru-RU','en-US'],'ru'],[390,['en-GB'],'en-US'],[390,['zz-ZZ'],'en-US']]) {
  results.push(await runBrowser(chrome,{},async({command,evaluate})=>{
    const rpc=async(method,params={})=>{const r=await command(method,params);assert(!r.error,JSON.stringify(r));return r.result;};
    await rpc('Page.enable');
    await rpc('Page.addScriptToEvaluateOnNewDocument',{source:`
      Object.defineProperty(Navigator.prototype,'languages',{get:()=>${JSON.stringify(languages)}});
      window.languageFixture=${JSON.stringify(languages)}.join(',');
      window.cspFailures=[];window.scriptFailures=[];
      addEventListener('securitypolicyviolation',e=>cspFailures.push(e.violatedDirective));
      addEventListener('error',e=>scriptFailures.push(e.message));
    `});
    await rpc('Page.reload',{ignoreCache:true});
    const until=async predicate=>{const end=Date.now()+40000;for(;;){let s;try{s=await evaluate(`window.languageFixture===${JSON.stringify(languages.join(','))}?window.confidex?.snapshot():null`);}catch{}if(s&&predicate(s))return s;assert(Date.now()<end,JSON.stringify(s));await delay(50);}};
    let s=await until(s=>s.screen==='catalog'&&!s.busy);
    assert.equal(s.locale,expected);
    assert.equal(s.defaultSyncServer,'https://sync.confidex.me/');
    const click=async id=>{s=await until(s=>s.hits[id]);const[x,y]=s.hits[id];for(const type of ['mousePressed','mouseReleased'])await rpc('Input.dispatchMouseEvent',{type,x,y,button:'left',clickCount:1});await delay(100);};
    await click('create');await until(s=>s.screen==='create');
    const frame=await rpc('Page.captureScreenshot',{format:'png'});
    await writeFile(join(shots,`${width}-${expected}.png`),Buffer.from(frame.data,'base64'));
    await click('settings');await click('language');
    const index=expected==='ru'?0:1;
    const [x,y]=(await until(s=>s.hits['language-menu'])).hits['language-menu'];
    await rpc('Input.dispatchMouseEvent',{type:'mouseMoved',x,y});
    await rpc('Input.dispatchMouseEvent',{type:'mouseWheel',x,y,deltaX:0,deltaY:-5000});
    await delay(200);
    for(let attempt=0;!(await evaluate('window.confidex.snapshot()')).hits[`language-${index}`];attempt++){
      assert(attempt<12,'language option did not become visible');
      await rpc('Input.dispatchMouseEvent',{type:'mouseWheel',x,y,deltaX:0,deltaY:160});
      await delay(200);
    }
    await click(`language-${index}`);
    const manual=(await until(s=>s.locale!==expected)).locale;
    for(const type of ['keyDown','keyUp'])await rpc('Input.dispatchKeyEvent',{type,key:'Escape',code:'Escape',windowsVirtualKeyCode:27});
    await delay(250);assert.equal((await until(s=>s.screen==='create')).locale,manual);
    await evaluate('navigator.serviceWorker.ready.then(()=>true)');
    const end=Date.now()+30000;
    while(!await evaluate('Boolean(navigator.serviceWorker.controller)')){assert(Date.now()<end);await delay(50);}
    await rpc('Network.enable');
    await rpc('Network.emulateNetworkConditions',{offline:true,latency:0,downloadThroughput:0,uploadThroughput:0});
    await rpc('Page.reload',{ignoreCache:true});
    s=await until(s=>s.screen==='catalog'&&!s.busy);
    assert.equal(s.locale,expected);
    assert.equal(await evaluate('navigator.onLine'),false);
    assert.deepEqual(await evaluate('[window.cspFailures,window.scriptFailures]'),[[],[]]);
    const origins=await evaluate('[...new Set(performance.getEntriesByType("resource").map(e=>new URL(e.name).origin))]');
    assert(origins.every(origin=>origin===new URL(remoteUrl).origin),JSON.stringify(origins));
    return {width,languages,locale:s.locale,manualLocale:manual,offlineReload:true,cspFailures:0};
  },{windowSize:[width,1000],viewport:[width,1000],remoteUrl}));
}
console.log(JSON.stringify(results,null,2));
