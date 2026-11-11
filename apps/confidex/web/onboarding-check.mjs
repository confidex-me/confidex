import assert from 'node:assert/strict';
import {mkdir, writeFile} from 'node:fs/promises';
import {setTimeout as delay} from 'node:timers/promises';
import {runBrowser} from '../../../tools/browser-run.mjs';
import {assets} from './assets.mjs';

const [chrome, bundle, server, screenshots, remoteUrl] = process.argv.slice(2);
assert(chrome && bundle && server, 'Usage: onboarding-check.mjs CHROME BUNDLE DISPOSABLE_SYNC_SERVER [SCREENSHOTS] [APP_URL]');
if (screenshots) await mkdir(screenshots, {recursive:true});
const files = await assets(bundle);
const password = 'public-onboarding-password-fixture';
const results = [];
for (const width of [1180,390]) {
  results.push(await runBrowser(chrome, files, async ({evaluate,command}) => {
    const rpc = async (method, params={}) => {
      const reply = await command(method,params); assert(!reply.error,JSON.stringify(reply.error)); return reply.result;
    };
    const state = () => evaluate('window.confidex?.snapshot()');
    const until = async predicate => {
      for(let i=0;i<500;i++) {
        let s; try { s=await state(); } catch {}
        if(s && predicate(s)) return s;
        await delay(50);
      }
      throw Error('Onboarding timed out: '+JSON.stringify(await state()));
    };
    const click = async id => {
      for(let i=0;i<30;i++) {
        const s=await until(s=>s.hits[id]),[x,y]=s.hits[id];
        const viewport=s.bounds['preferences-viewport'];
        const top=viewport?.[1]??0,bottom=viewport?.[3]??1100;
        if(y>=top+2 && y<=bottom-2) {
          for(const type of ['mousePressed','mouseReleased']) await rpc('Input.dispatchMouseEvent',{type,x,y,button:'left',clickCount:1});
          await delay(100); return;
        }
        const point={x:viewport?viewport[0]+5:width-20,y:(top+bottom)/2};
        await rpc('Input.dispatchMouseEvent',{type:'mouseMoved',...point});
        await rpc('Input.dispatchMouseEvent',{type:'mouseWheel',...point,deltaX:0,deltaY:y<top?-180:180});
        await delay(100);
      }
      throw Error('Could not scroll to '+id);
    };
    const text = async (id,value) => {
      await click(id);
      for(const type of ['rawKeyDown','keyUp']) await rpc('Input.dispatchKeyEvent',{type,key:'a',code:'KeyA',windowsVirtualKeyCode:65,modifiers:4});
      await rpc('Input.dispatchKeyEvent',{type:'keyUp',key:'Meta',code:'MetaLeft',modifiers:0});
      await rpc('Input.insertText',{text:value}); await delay(100);
    };
    const escape = async () => {
      for(const type of ['keyDown','keyUp']) await rpc('Input.dispatchKeyEvent',{type,key:'Escape',code:'Escape',windowsVirtualKeyCode:27});
      await delay(100);
    };
    const capture = async name => {
      if(!screenshots) return;
      await delay(250);
      await writeFile(`${screenshots}/${width}-${name}.png`,Buffer.from((await rpc('Page.captureScreenshot',{format:'png'})).data,'base64'));
    };
    await until(s=>s.screen==='catalog'&&!s.busy);
    await click('create');
    await until(s=>s.screen==='create'&&s.hits['create-sync']);
    assert((await state()).hits['create-sync-server'],'new vault sync is not enabled by default');
    await capture('create-default');
    await click('cancel');await until(s=>s.screen==='catalog'&&!s.busy);
    await click('settings');
    await text('default-sync-server',server);
    if(width===1180) await click('default-sync-enabled');
    await capture('defaults');await escape();
    await evaluate('window.__beforeOnboardingReload=true');
    await rpc('Page.reload',{});
    for(let i=0;i<500;i++) {
      try { if(await evaluate('document.readyState==="complete"&&!window.__beforeOnboardingReload')) break; } catch {}
      await delay(50);
    }
    await until(s=>s.screen==='catalog'&&!s.busy);
    await click('create');
    await until(s=>s.screen==='create'&&s.hits['create-sync']);
    assert.equal(Boolean((await state()).hits['create-sync-server']),width!==1180,'saved enabled default was lost');
    if(width===1180) await click('create-sync');
    await click('create-sync-server');await until(s=>s.hits['sync-server']);
    await capture('server-expanded');
    if(width===390) await click('create-sync');
    await text('name','Public onboarding fixture');
    await text('password',password);await text('repeat',password);
    await click('submit');await until(s=>s.screen==='key'&&!s.busy);
    await capture('backup-key');
    const modulePath=Object.keys(files).find(path=>path.endsWith('/web/storage.js'));
    const inspect = () => evaluate(`(async()=>{
      const {dbCall}=await import(${JSON.stringify(modulePath)});
      const vault=(await dbCall('vaults',[]))[0];
      const id=vault.id.map(n=>n.toString(16).padStart(2,'0')).join('');
      const sync=await dbCall('sync-state',[id]);
      const persisted=(await dbCall('load-key',[id]))!==null;
      return {persisted,sync:sync?JSON.parse(new TextDecoder().decode(Uint8Array.from(sync))):null};
    })()`);
    const before=await inspect();
    assert.equal(before.persisted,false,'canceled passkey enrollment saved a secret key');
    assert.equal(before.sync,null,'sync started before backup confirmation');
    await click('key-saved');await click('continue');
    await until(s=>s.screen==='open'&&!s.busy);
    const after=await inspect();
    if(width===1180) { assert.equal(after.sync?.enabled,true);assert.equal(after.sync.server,server); }
    else assert.equal(after.sync,null,'disabled creation synchronized');
    assert.equal((await state()).error,null);
    assert(await evaluate(`!Object.keys(localStorage).some(k=>k.includes('egui'))`),'egui memory was persisted');
    await capture('vault');
    return {width,remembered:false,defaultsPersisted:true,syncEnabled:width===1180,backupBeforeSync:true};
  },{viewport:[width,1100],remoteUrl}));
}
console.log(JSON.stringify(results));
