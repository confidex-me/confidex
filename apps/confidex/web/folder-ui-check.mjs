import assert from 'node:assert/strict';
import {mkdir,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
import {assets} from './assets.mjs';
import {runBrowser} from '../../../tools/browser-run.mjs';
const [chrome,bundle,output]=process.argv.slice(2);
assert(chrome&&bundle&&output,'usage: folder-ui-check.mjs CHROME BUNDLE RESULTS');
await mkdir(output,{recursive:true});
const base=await assets(bundle),results=[];
for(const [width,locale] of [[1320,'ru'],[390,'ru'],[1320,'de'],[390,'de']]) {
  const files={...base,'/boot.js':Buffer.from(`import init,{WebHandle} from '/app.js';await init();const app=new WebHandle();await app.start_folder_check(document.getElementById('app'),${JSON.stringify(locale)});window.confidex=app;document.getElementById('loading').remove();`)};
  results.push(await runBrowser(chrome,files,async({command,evaluate})=>{
    const rpc=async(method,params={})=>{const response=await command(method,params);assert(!response.error,JSON.stringify(response));return response.result;};
    const state=()=>evaluate('window.confidex?.snapshot()');
    const capture=async name=>{await delay(150);await writeFile(join(output,`${width}-${locale}-${name}.png`),Buffer.from((await rpc('Page.captureScreenshot',{format:'png'})).data,'base64'));};
    const until=async predicate=>{const deadline=Date.now()+30000;for(;;){const s=await state();if(s&&predicate(s))return s;if(Date.now()>deadline){await capture('failure');assert.fail(JSON.stringify(s));}await delay(40);}};
    const click=async id=>{
      for(let attempt=0;attempt<30;attempt++) {
        const s=await until(s=>s.hits[id]),[x,y]=s.hits[id];
        if(y>5&&y<990&&x>0&&x<width) {
          await rpc('Input.dispatchMouseEvent',{type:'mouseMoved',x,y});await delay(40);
          const fresh=(await state()).hits[id];if(!fresh||Math.abs(fresh[1]-y)>1)continue;
          for(const type of ['mousePressed','mouseReleased'])await rpc('Input.dispatchMouseEvent',{type,x,y,button:'left',clickCount:1});
          await delay(100);return;
        }
        const r=s.bounds['preferences-viewport']??s.bounds['preferences-window']??[0,0,width,1000];
        await rpc('Input.dispatchMouseEvent',{type:'mouseWheel',x:Math.min(width-20,(r[0]+r[2])/2+60),y:Math.max(30,Math.min(800,(r[1]+r[3])/2)),deltaX:0,deltaY:y<5?-180:180});await delay(100);
      }
      assert.fail(`unreachable ${id}`);
    };
    const text=async(id,value,replace=false)=>{
      await click(id);
      if(replace) for(const type of ['keyDown','keyUp'])await rpc('Input.dispatchKeyEvent',{type,key:'a',code:'KeyA',windowsVirtualKeyCode:65,modifiers:4});
      await rpc('Input.insertText',{text:value});await delay(60);
    };
    await until(s=>s.screen==='catalog'&&!s.busy);
    await capture('catalog');await click('folder-open');
    await until(s=>s.screen==='import'&&!s.busy);
    assert(!(await state()).hits['sync-server']);await capture('import');
    await text('name','Public folder fixture');await text('secret-key','public-fixture-key');await text('password','incorrect');await click('submit');
    await until(s=>!s.busy&&s.error==='vault-error-auth');assert(!(await state()).bounds['folder-error']);
    await text('password','public-password',true);await click('submit');
    await until(s=>s.screen==='open'&&!s.busy&&s.folderPending===2);
    assert.equal((await state()).error,null);await capture('pending');
    await click('settings');if((await state()).hits['preferences-sections'])await click('preferences-sections');await click('preferences-section-1');
    await until(s=>s.bounds['preferences-folder']&&s.hits['folder-disconnect']);
    await capture('settings');
    const configured=await state();assert(configured.folderPath.endsWith('Confidex shared vault'));assert(configured.bounds['preferences-folder'][0]>=0&&configured.bounds['preferences-folder'][2]<=width);
    await click('folder-disconnect');await until(s=>s.folderPath===null&&!s.busy);
    await click('folder-choose');await until(s=>s.folderPath!==null&&!s.busy);
    await capture('reconnected');
    await click('preferences-close');await until(s=>!s.bounds['preferences-window']);
    await click('sync');await until(s=>s.folderRunning&&s.hits['folder-cancel']);await capture('working');
    await click('folder-cancel');await until(s=>!s.busy&&!s.folderRunning);assert.equal((await state()).error,null);
    await click('sync');await until(s=>s.folderRunning);await click('lock');
    await until(s=>s.screen==='unlock'&&!s.busy);assert.equal((await state()).folderPath,null);
    await delay(2200);assert.equal((await state()).screen,'unlock');await capture('locked');
    return {width,locale,bootstrap:true,wrongPassword:true,configure:true,disconnect:true,pending:true,cancel:true,lock:true};
  },{viewport:[width,1000],windowSize:[width,1000]}));
}
console.log(JSON.stringify(results));
