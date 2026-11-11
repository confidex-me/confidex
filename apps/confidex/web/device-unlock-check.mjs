import assert from 'node:assert/strict';
import {mkdir,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
import {runBrowser} from '../../../tools/browser-run.mjs';
import {assets} from './assets.mjs';

const [chrome, bundle, server, evidence] = process.argv.slice(2);
const width=Number(process.env.CONFIDEX_UI_WIDTH??1180);
assert(chrome && bundle && server, 'Usage: device-unlock-check.mjs CHROME BUNDLE DISPOSABLE_SYNC_SERVER');
const files = await assets(bundle);
const storage = Object.keys(files).find(path => path.endsWith('/web/storage.js'));
assert(storage);
files['/worker.js'] = Buffer.concat([Buffer.from(`
  addEventListener('message', event => {
    if (!Number.isSafeInteger(event.data?.testClock)) return;
    event.stopImmediatePropagation();
    Date.now = () => event.data.testClock;
  });
`), files['/worker.js']]);

const interval = 36 * 60 * 60 * 1000;
const password = 'public device unlock password';
if(evidence)await mkdir(evidence,{recursive:true});

await runBrowser(chrome, files, async ({command, evaluate}) => {
  const rpc = async (method, params = {}) => {
    const reply = await command(method, params);
    assert(!reply.error, JSON.stringify(reply.error));
    return reply.result;
  };
  await rpc('Page.enable');
  await rpc('WebAuthn.enable');
  await rpc('WebAuthn.addVirtualAuthenticator', {options: {
    protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal',
    hasResidentKey: true, hasUserVerification: true, hasPrf: true,
    automaticPresenceSimulation: true, isUserVerified: true,
  }});
  await rpc('Page.addScriptToEvaluateOnNewDocument', {source: `
    Object.defineProperty(navigator,'languages',{get:()=>['en-US']});
    window.NativeWorker=Worker;
    window.Worker=class extends NativeWorker {
      constructor(...args) {
        super(...args);
        if (args[0]==='/worker.js' && !window.appWorker) window.appWorker=this;
      }
    };
    window.passkeyCalls=[];
    for (const method of ['create','get']) {
      const original=navigator.credentials[method].bind(navigator.credentials);
      navigator.credentials[method]=options=>{passkeyCalls.push(method);return original(options);};
    }
    window.confirmations=[];
    window.confirm=message=>{confirmations.push(message);return true;};
  `});
  const snapshot = () => evaluate('window.confidex?.snapshot()');
  const until = async predicate => {
    const deadline = Date.now() + 40000;
    for (;;) {
      let state;
      try { state = await snapshot(); } catch {}
      if (state && predicate(state)) return state;
      assert(Date.now() < deadline, JSON.stringify(state));
      await delay(60);
    }
  };
  const reload = async () => {
    const time = await evaluate('performance.timeOrigin');
    await rpc('Page.reload', {ignoreCache: true});
    await until(s => s.screen === 'catalog' && !s.busy);
    assert.notEqual(await evaluate('performance.timeOrigin'), time);
  };
  const click = async id => {
    const [x,y] = (await until(s => s.hits[id])).hits[id];
    for (const type of ['mousePressed','mouseReleased']) {
      await rpc('Input.dispatchMouseEvent',{type,x,y,button:'left',clickCount:1});
    }
    await delay(100);
  };
  const text = async (id,value) => {
    await click(id);
    for (const type of ['rawKeyDown','keyUp']) {
      await rpc('Input.dispatchKeyEvent',{type,key:'a',code:'KeyA',windowsVirtualKeyCode:65,modifiers:4});
    }
    await rpc('Input.dispatchKeyEvent',{type:'keyUp',key:'Meta',code:'MetaLeft',modifiers:0});
    await rpc('Input.insertText',{text:value});
    await delay(80);
  };
  const shot=async name=>{
    if(evidence)await writeFile(join(evidence,`${width}-${name}.png`),Buffer.from((await rpc('Page.captureScreenshot',{format:'png'})).data,'base64'));
  };
  await reload();
  const fixture = await evaluate(`(async()=>{
    const worker=new NativeWorker('/worker.js',{type:'module'});
    await new Promise((resolve,reject)=>{
      worker.onmessage=({data})=>{if(data==='ready')resolve();};
      worker.onerror=reject;
    });
    const execute=command=>new Promise((resolve,reject)=>{
      worker.onmessage=({data})=>{
        try {
          const reply=JSON.parse(new TextDecoder().decode(data)).result;
          if(reply.Err)reject(Error(JSON.stringify(reply.Err)));
          else resolve(reply.Ok);
        }catch(error){reject(error);}
      };
      worker.postMessage(new TextEncoder().encode(JSON.stringify({generation:1,command})));
    });
    try {
      const {Created:created}=await execute({Create:{name:'Public device unlock fixture',password:${JSON.stringify(password)},remember:false}});
      await execute({Save:{draft:{record:Array(16).fill(1),revision:null,title:'Public record',tags:[],fields:[]},epoch:1}});
      const server=${JSON.stringify(server)};
      await execute({SyncConfig:{server}});
      for(let i=0;i<16;i++){
        const {Synced:report}=await execute({Sync:{server}});
        if(!report.more)break;
        if(i===15)throw Error('Fixture did not sync');
      }
      const vault=created.info.id.map(n=>n.toString(16).padStart(2,'0')).join('');
      const {dbCall}=await import(${JSON.stringify(storage)});
      await dbCall('remove',[vault]);
      return {vault,key:created.key};
    } finally {worker.terminate();}
  })()`);
  const saved = () => evaluate(`(async()=>{
    const {dbCall}=await import(${JSON.stringify(storage)});
    const vault=${JSON.stringify(fixture.vault)};
    const local=await dbCall('load-device-unlock',[vault]);
    const ordinary=await dbCall('load-key',[vault]);
    const snapshot=await dbCall('snapshot',[vault]);
    return {verifiedAt:local?.verifiedAt??null,encrypted:local?.entry instanceof Uint8Array,
      cleartext:typeof ordinary==='string',isolated:!('deviceUnlock' in snapshot.vault||'rememberedKey' in snapshot.vault)};
  })()`);
  const importVault = async usePasskey => {
    await click('import');
    await until(s => s.screen === 'import' && s.hits['device-unlock']);
    await text('name','Public device unlock fixture');
    await text('sync-server',server);
    await text('secret-key',fixture.key);
    await text('password',password);
    if (usePasskey) await click('device-unlock');
    await click('submit');
    await until(s => s.screen === 'open' && !s.busy);
  };
  const lock = async () => {
    await click('lock');
    return until(s => s.screen === 'unlock' && !s.busy);
  };
  const open = () => until(s => s.screen === 'open' && !s.busy);
  const advance = at => evaluate(`Date.now=()=>${at};appWorker.postMessage({testClock:${at}});true`);

  const before = Date.now();
  await importVault(true);
  const initial = await saved();
  assert(initial.encrypted && !initial.cleartext && initial.isolated);
  assert(initial.verifiedAt >= before && initial.verifiedAt <= Date.now());
  const deadline = initial.verifiedAt + interval;
  assert.deepEqual(await evaluate('passkeyCalls'),['create','get']);

  await reload();
  await click('vault-0');
  const beforeExpiry = await until(s => s.screen === 'unlock' && !s.busy);
  assert(!beforeExpiry.hits.password && !beforeExpiry.hits['secret-key']);
  await advance(deadline - 1);
  await click('submit');
  await open();
  assert.equal((await saved()).verifiedAt,initial.verifiedAt);
  assert.deepEqual(await evaluate('passkeyCalls'),['get']);

  await advance(deadline);
  const expired = await lock();
  assert(expired.hits.password && !expired.hits['secret-key']);
  await text('password','wrong public password');
  await click('submit');
  await until(s => s.error === 'vault-error-auth' && !s.busy);
  assert.equal((await saved()).verifiedAt,initial.verifiedAt);
  await text('password',password);
  await click('submit');
  await open();
  assert.equal((await saved()).verifiedAt,deadline);
  assert.deepEqual(await evaluate('passkeyCalls'),['get','get','get']);

  await click('settings');
  await click('device-unlock-delay');
  await until(s => (width<600?[5]:[5,30,60,360,720,1440,2160]).every(value => s.hits['device-unlock-delay-'+value]));
  await click('device-unlock-delay-5');
  assert.equal(await evaluate("localStorage.getItem('device-unlock-minutes')"),'5');
  await reload();
  await advance(deadline + 5 * 60 * 1000);
  await click('vault-0');
  const shortened = await until(s => s.screen === 'unlock' && !s.busy);
  assert(shortened.hits.password && !shortened.hits['secret-key']);
  assert.equal((await saved()).verifiedAt,deadline);
  await click('vaults');
  await until(s => s.screen === 'catalog' && !s.busy);
  const calls = await evaluate('passkeyCalls.slice()');
  await importVault(false);
  assert.deepEqual(await saved(),{verifiedAt:null,encrypted:false,cleartext:true,isolated:true});
  assert((await evaluate('confirmations.at(-1)')).includes('without encryption'));
  assert.deepEqual(await evaluate('passkeyCalls'),calls);
  assert((await lock()).hits.password);
  await text('password',password);
  await click('submit');
  await open();
  assert.deepEqual(await evaluate('passkeyCalls'),calls);
  await click('settings');
  if ((await snapshot()).hits['preferences-sections']) await click('preferences-sections');
  await click('preferences-section-1');
  const setting = async id => {
    for (let attempt=0;attempt<30;attempt++) {
      const state=await until(s=>s.hits[id]);
      const [x,y]=state.hits[id],bounds=state.bounds['preferences-viewport'];
      if (!bounds || y>=bounds[1]&&y<=bounds[3]) {await click(id);return;}
      const point={x:(bounds[0]+bounds[2])/2,y:(bounds[1]+bounds[3])/2};
      await rpc('Input.dispatchMouseEvent',{type:'mouseMoved',...point});
      await rpc('Input.dispatchMouseEvent',{type:'mouseWheel',...point,deltaX:0,deltaY:y<bounds[1]?-200:200});
      await delay(100);
    }
    await shot('setting-failure');
    throw Error('Setting is outside the viewport: '+id+': '+JSON.stringify((await snapshot()).bounds));
  };
  await setting('auto-lock');
  await click('auto-lock-15');
  const preferences=await evaluate("localStorage.getItem('vault-auto-lock-minutes')");
  assert(preferences.includes('15'));
  await shot('auto-lock');
  await setting('vault-device-unlock');
  await setting('device-unlock-password');
  await text('device-unlock-password','wrong public password');
  await setting('device-unlock-apply');
  await until(s=>!s.busy);
  assert(!(await saved()).encrypted);
  await shot('device-unlock-wrong-password');
  await text('device-unlock-password',password);
  await setting('device-unlock-apply');
  await until(s=>!s.busy&&!s.hits['device-unlock-password']);
  const protectedKey=await saved();
  assert(protectedKey.encrypted&&!protectedKey.cleartext);
  await shot('device-unlock-enabled');
  await evaluate('window.confirm=()=>false');
  await setting('vault-device-unlock');await until(s=>!s.busy);
  assert.deepEqual(await saved(),protectedKey,'cancel changed the existing capability');
  await evaluate('window.confirm=message=>{confirmations.push(message);return true;}');
  await setting('vault-device-unlock');await until(s=>!s.busy);
  assert(!(await saved()).encrypted&&(await saved()).cleartext);
  await click('preferences-close');
  const disabled=await lock();
  assert(disabled.hits.password);
  await reload();
  assert.equal(await evaluate("localStorage.getItem('vault-auto-lock-minutes')"),preferences);
  await click('vault-0');await until(s=>s.screen==='unlock'&&!s.busy);
  await text('password',password);await click('submit');await open();
  await advance((await evaluate('Date.now()'))+5*60*1000+1);
  await rpc('Input.dispatchMouseEvent',{type:'mouseMoved',x:3,y:3});
  await delay(200);
  assert((await snapshot()).screen==='open','the saved 15 minute interval was not restored');
  await click('new-record');await click('template-login');
  await text('record-title','Public deferred auto-lock draft');
  const activeAt=await evaluate('Date.now()');
  await advance(activeAt+15*60*1000+1);
  await rpc('Input.dispatchMouseEvent',{type:'mouseMoved',x:4,y:4});
  await delay(200);
  assert((await snapshot()).editing&&(await snapshot()).screen==='open','auto-lock discarded the editor');
  await click('save');await until(s=>!s.busy&&!s.editing);
  await advance(activeAt+30*60*1000+2);
  await rpc('Input.dispatchMouseEvent',{type:'mouseMoved',x:5,y:5});
  await until(s=>s.screen==='unlock'&&!s.busy);
}, {passkeys:true, viewport:[width,1000]});
console.log('Device unlock, expiration, renewal, reversible settings, canceled revocation, and per-vault auto-lock persistence: pass');
