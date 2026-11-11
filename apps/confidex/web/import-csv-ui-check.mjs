import assert from 'node:assert/strict';
import {mkdir,writeFile} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {setTimeout as delay} from 'node:timers/promises';
import {runBrowser} from '../../../tools/browser-run.mjs';
import {assets} from './assets.mjs';
const [chrome,bundle,output]=process.argv.slice(2);
await mkdir(output,{recursive:true});
const fixture=name=>fileURLToPath(new URL(`../../../crates/confidex-app/tests/import_fixtures/csv/${name}`,import.meta.url));
const malformed=resolve(output,'public-malformed.csv'),delimiter=resolve(output,'public-semicolon.csv'),noHeader=resolve(output,'public-no-header.csv'),empty=resolve(output,'public-header-only.csv'),encoding=resolve(output,'public-utf16.csv');
await writeFile(malformed,'name,password\n"unterminated,public-only-secret\n');
await writeFile(delimiter,'title;username;password\nPublic semicolon;public-user;public-only-secret\n');
await writeFile(noHeader,'Public title,https://example.invalid,public-user,CSV_FIRST_ROW_PRIVATE\n');
await writeFile(empty,'name,url,username,password\n');
await writeFile(encoding,Buffer.from([255,254,110,0,97,0,109,0,101,0,10,0]));
const files=await assets(bundle),storagePath=Object.keys(files).find(path=>path.endsWith('/web/storage.js'));
for(const width of [1320,820,390]) {
  await runBrowser(chrome,files,async({command,evaluate})=>{
    const rpc=async(method,params={})=>{const r=await command(method,params);assert(!r.error,JSON.stringify(r));return r.result;};
    const state=()=>evaluate('window.confidex?.snapshot()');
    const until=async predicate=>{for(let i=0;i<900;i++){const s=await state();if(s&&predicate(s))return s;await delay(40);}throw Error('CSV UI timeout: '+JSON.stringify(await state()));};
    const click=async id=>{
      for(let attempt=0;attempt<60;attempt++) {
        const s=await state();if(!s){await delay(40);continue;}
        const row=/^import-csv-(?:name|target)-(\d+)$/.exec(id),menu=/^import-csv-role-(\d+)-/.exec(id);
        let v=menu?s.bounds[`import-csv-target-${menu[1]}-options`]:row?s.bounds['import-csv-columns']:s.bounds['import-window-body']??s.bounds['preferences-viewport'];
        if(/^preferences-section|^settings$|^import-close$/.test(id))v=null;
        const point=s.hits[id];
        if(point&&(!v||point[1]>=v[1]+1&&point[1]<=v[3]-1)) {
          const [x,y]=point;await rpc('Input.dispatchMouseEvent',{type:'mouseMoved',x,y});await delay(40);
          const fresh=(await state())?.hits[id];if(!fresh||Math.abs(fresh[0]-x)>0.5||Math.abs(fresh[1]-y)>0.5)continue;
          for(const type of ['mousePressed','mouseReleased'])await rpc('Input.dispatchMouseEvent',{type,x,y,button:'left',clickCount:1});await delay(120);return;
        }
        if(v&&(row||menu||point)) {
          const target={x:menu&&point?point[0]:(v[0]+v[2])/2,y:(v[1]+v[3])/2};
          const first=Math.min(...Object.keys(s.hits).flatMap(key=>/^import-csv-target-(\d+)$/.exec(key)?.slice(1).map(Number)??[]));
          const up=point?point[1]<v[1]:row&&Number(row[1])<first;
          await rpc('Input.dispatchMouseEvent',{type:'mouseMoved',...target});
          await rpc('Input.dispatchMouseEvent',{type:'mouseWheel',...target,deltaX:0,deltaY:up?-130:130});await delay(300);
        } else await delay(50);
      }
      await writeFile(join(output,`${width}-failure.png`),Buffer.from((await rpc('Page.captureScreenshot',{format:'png'})).data,'base64'));
      throw Error('Cannot reach '+id+': '+JSON.stringify(await state()));
    };
    const text=async(id,text)=>{
      await click(id);
      for(const type of ['rawKeyDown','keyUp'])await rpc('Input.dispatchKeyEvent',{type,key:'a',code:'KeyA',windowsVirtualKeyCode:65,modifiers:4});
      await rpc('Input.dispatchKeyEvent',{type:'keyUp',key:'Meta',code:'MetaLeft',modifiers:0});
      await rpc('Input.insertText',{text});await delay(60);
    };
    const shot=async name=>{await delay(180);await writeFile(join(output,`${width}-${name}.png`),Buffer.from((await rpc('Page.captureScreenshot',{format:'png'})).data,'base64'));};
    await until(s=>s.screen==='catalog'&&!s.busy);await delay(200);await click('create');await click('create-sync');
    await text('name','Public CSV destination');await text('password','public-browser-csv-password');await text('repeat','public-browser-csv-password');
    await click('submit');await until(s=>s.screen==='key'&&!s.busy);await click('key-saved');await click('continue');await until(s=>s.screen==='open'&&!s.busy);
    await evaluate(`(async()=>{window.csvDb=(await import(${JSON.stringify(storagePath)})).dbCall;window.csvVault=(await csvDb('vaults',[]))[0].id.map(n=>n.toString(16).padStart(2,'0')).join('');})()`);
    const objects=()=>evaluate(`csvDb('snapshot',[csvVault]).then(s=>s.objects.length)`);
    const open=async(path,mapping=true)=>{
      await click('settings');if((await state()).hits['preferences-sections'])await click('preferences-sections');await click('preferences-section-1');await click('import-records');
      await text('import-account','public-csv-source');
      await rpc('Page.enable');await rpc('Page.setInterceptFileChooserDialog',{enabled:true});await click('import-choose-file');
      const {root}=await rpc('DOM.getDocument'),{nodeId}=await rpc('DOM.querySelector',{nodeId:root.nodeId,selector:'input[type=file]'});assert(nodeId);
      await rpc('DOM.setFileInputFiles',{nodeId,files:[path]});await delay(150);await click('import-review');
      if(mapping)await until(s=>s.hits['import-csv-header']);else await until(s=>s.hits['import-choose-file']&&!s.hits['import-review']&&!s.hits['vault-cancel']);
    };
    const close=async()=>{await click('import-close');await until(s=>!s.bounds['import-window']);};
    const profile=async id=>{await click('import-csv-profile');await click(`import-csv-profile-${id}`);};
    const role=async(index,target)=>{await click(`import-csv-target-${index}`);await shot(`role-${index}-menu`);await click(`import-csv-role-${index}-${target}`);};
    const preview=async()=>{await click('import-review');await until(s=>s.hits['import-row-0']||s.bounds['import-preview']);if((await state()).hits['import-row-0'])await click('import-row-0');await until(s=>s.bounds['import-preview']);};
    const apply=async added=>{
      const before=await objects(),rows=(await state()).rows;
      if((await state()).hits['import-container-ack'])await click('import-container-ack');if((await state()).hits['import-item-ack'])await click('import-item-ack');
      await click('import-apply');await until(s=>s.hits['import-done']);assert.equal(await objects(),before+added);
      await click('import-done');await until(s=>!s.bounds['import-window']&&s.rows===rows+added);
    };
    await open(noHeader);await shot('private-before-header');assert.equal(await objects(),0);await close();
    await open(fixture('chromium-100.csv'));await click('import-csv-header');await until(s=>s.hits['import-csv-profile']);await profile('chromium');await shot('profile');
    await click('import-csv-reset');await until(s=>s.hits['import-csv-header']);await shot('reset');await profile('chromium');
    await text('import-csv-name-2','Public renamed username');await preview();await shot('preview');assert.equal(await objects(),0);
    await click('import-csv-edit');await until(s=>s.hits['import-csv-header']);await shot('edit-again');await preview();await apply(1);
    await open(fixture('chromium-100.csv'));await click('import-csv-header');await until(s=>s.hits['import-csv-profile']);await profile('chromium');await text('import-csv-name-2','Public renamed username');await preview();await shot('duplicate');assert(!(await state()).hits['import-apply']);assert.equal(await objects(),1);await close();
    if(width===1320)for(const [file,id,added] of [['firefox.csv','firefox',2],['apple-passwords-upstream.csv','apple-passwords',1]]) {
      const before=await objects();await open(fixture(file));await click('import-csv-header');await until(s=>s.hits['import-csv-profile']);await profile(id);await shot(id);await preview();assert.equal(await objects(),before);await apply(added);
    }
    const before=await objects();await open(fixture('generic.csv'));await click('import-csv-header');await until(s=>s.hits['import-csv-profile']);
    for(const [index,target] of ['title','url/v1','username/v1','password/v1','secure-note/v1','text/v1','secret/v1','text/v1','totp/v1'].entries())await role(index,target);
    await text('import-csv-name-5','Public extra field');await text('import-csv-name-6','Hidden extra field');await shot('manual');await preview();await shot('manual-preview');assert.equal(await objects(),before);await apply(2);
    await open(delimiter);await click('import-csv-delimiter');await click('import-csv-delimiter-semicolon');await until(s=>s.hits['import-csv-header']);await click('import-csv-header');await until(s=>s.hits['import-csv-target-0']);
    for(const [index,target] of ['title','username/v1','password/v1'].entries())await role(index,target);
    await preview();await shot('semicolon-preview');await apply(1);
    const saved=await objects();await open(malformed);await click('import-review');await until(s=>s.hits['import-csv-reset']);await shot('error');assert.equal(await objects(),saved);await close();
    await open(empty);await click('import-csv-header');await until(s=>s.hits['import-csv-profile']);await profile('chromium');await click('import-review');await until(s=>s.hits['import-csv-edit']);await shot('header-only');assert(!(await state()).hits['import-apply']);assert.equal(await objects(),saved);await close();
    await open(encoding,false);await shot('encoding-error');assert.equal(await objects(),saved);await close();
    console.log(JSON.stringify({width,previewWrites:0,objects:await objects(),profiles:width===1320?3:1}));
  },{viewport:[width,1000],windowSize:[width,1000]});
}
