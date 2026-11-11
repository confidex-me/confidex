import assert from 'node:assert/strict';
import {readFile,readdir,rename,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {createRequire} from 'node:module';
import {setTimeout as delay} from 'node:timers/promises';

// Installed only by the public-fixture CDP runner; record metadata, never values.
export function observeExportWorker() {
  const Original=window.Worker,decoder=new TextDecoder();
  window.exportTraffic={events:[],progress:{},sequence:0};
  const header=data=>{
    if(!ArrayBuffer.isView(data)&&!(data instanceof ArrayBuffer))return null;
    const bytes=data instanceof ArrayBuffer?new Uint8Array(data):new Uint8Array(data.buffer,data.byteOffset,data.byteLength);
    try {if(bytes[0]===123)return JSON.parse(decoder.decode(bytes));}catch{}
    if(bytes.length<4)return null;
    const length=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength).getUint32(0,true);
    if(length>bytes.length-4)return null;
    try{return JSON.parse(decoder.decode(bytes.subarray(4,4+length)));}catch{return null;}
  };
  const log=event=>{const trace=window.exportTraffic;trace.events.push({...event,sequence:++trace.sequence});};
  window.Worker=class extends Original {
    constructor(...args) {
      super(...args);this.exportOperation=null;
      this.addEventListener('message',({data})=>{
        const value=header(data)?.result?.Ok?.VendorExport;
        if(!value)return;
        const ok=value.Ok;
        if(ok?.Progress) {
          const {operation,progress}=ok.Progress,trace=window.exportTraffic;
          const previous=trace.progress[operation]??{phases:[],positiveWrite:false};
          const phase=String(progress.phase).toLowerCase();
          trace.progress[operation]={phase,current:progress.current,total:progress.total,
            phases:[...new Set([...previous.phases,phase])],
            positiveWrite:previous.positiveWrite||(phase==='write'&&progress.current>0)};
        } else if(value.Err)log({direction:'reply',kind:value.Err?.Export==='Canceled'?'Canceled':'Error',operation:this.exportOperation});
        else if(ok?.Ready)log({direction:'reply',kind:'Ready',operation:ok.Ready.operation,bytes:ok.Ready.ready.bytes});
        else if(ok?.Reviewed)log({direction:'reply',kind:'Reviewed',operation:ok.Reviewed.operation,records:ok.Reviewed.review.records});
        else if(ok==='Canceled')log({direction:'reply',kind:'CanceledAck',operation:this.exportOperation});
      });
    }
    postMessage(data,...rest) {
      if(data&&Number.isInteger(data.cancelExport))log({direction:'control',kind:'Cancel',operation:data.cancelExport,progress:window.exportTraffic.progress[data.cancelExport]});
      const command=header(data)?.command,request=command?.VendorExport;
      if(request) {
        const kind=typeof request==='string'?request:Object.keys(request)[0],operation=request[kind]?.operation;
        if(Number.isInteger(operation)&&['Prepare','Generate'].includes(kind))this.exportOperation=operation;
        log({direction:'request',kind,operation});
      } else if(command==='Lock')log({direction:'request',kind:'Lock',operation:this.exportOperation});
      return super.postMessage(data,...rest);
    }
  };
}

export async function cancelLoadUi({width,locale,directory,rpc,evaluate,snapshot,until,capture,click,text,open,seed}) {
  const trace=()=>evaluate('window.exportTraffic');
  const reset=()=>evaluate('window.exportTraffic={events:[],progress:{},sequence:0};true');
  const waitTrace=async(predicate)=>{
    const deadline=Date.now()+45000;
    for(;;){const state=await trace();if(predicate(state))return state;if(Date.now()>deadline){await capture('traffic-failure');assert.fail(JSON.stringify(state));}await delay(30);}
  };
  const fastClick=async id=>{
    const state=await snapshot(),point=state.hits[id];assert(point,id);
    const [x,y]=point;assert(x>=0&&x<width&&y>=0&&y<1000);
    await rpc('Input.dispatchMouseEvent',{type:'mouseMoved',x,y});
    for(const type of ['mousePressed','mouseReleased'])await rpc('Input.dispatchMouseEvent',{type,x,y,button:'left',clickCount:1});
  };
  const noDownload=async()=>assert.equal((await readdir(directory)).filter(name=>!name.endsWith('.png')&&!name.endsWith('-traffic.json')).length,0,'canceled export published a file');
  const working=async()=>{
    const state=await snapshot();
    assert(state.bounds['export-window']&&state.hits['export-cancel']&&!state.hits['export-save']&&!state.hits['export-restart']&&!state.hits['export-allow-losses']);
  };
  const configure=async(index)=>{
    await open();
    if(index){await click('export-format');await click('export-format-'+index);await text('export-password','PUBLIC-live-cancel-password');}
    await until(state=>state.hits['export-review']);
  };
  const reviewed=async(index)=>{
    await configure(index);await click('export-review');
    await until(state=>state.hits[index?'export-allow-losses':'export-plaintext-ack']);
    assert(!(await snapshot()).hits['export-generate']);
    if(!index)await click('export-plaintext-ack');
    await click('export-allow-losses');await until(state=>state.hits['export-generate']);
  };
  const canceled=async(operation,kind)=>{
    let state=await waitTrace(trace=>trace.events.some(event=>event.kind==='Canceled'&&event.operation===operation));
    assert(state.events.some(event=>event.direction==='control'&&event.kind==='Cancel'&&event.operation===operation),kind+': UI sent no cancel control');
    assert(!state.events.some(event=>event.direction==='reply'&&event.kind==='Ready'&&event.operation===operation),kind+': canceled operation returned Ready');
    await until(state=>!state.bounds['export-window']);
    await noDownload();
    await delay(250);
    assert(!(await snapshot()).bounds['export-window'],'late reply restored the closed form');
    state=await trace();
    assert(!state.events.some(event=>event.direction==='reply'&&event.kind==='Ready'&&event.operation===operation),'late Ready survived cancellation');
    await writeFile(join(directory,kind+'-traffic.json'),JSON.stringify(state,null,2));
    await capture(kind+'-canceled');
    return state;
  };
  await evaluate('window.exportCancelBeats=0;window.exportCancelTimer=setInterval(()=>exportCancelBeats++,10);true');
  const checks=[];
  await configure(0);await reset();await click('export-review');
  let state=await waitTrace(trace=>trace.events.some(event=>event.direction==='request'&&event.kind==='Prepare')&&Object.values(trace.progress).some(progress=>progress.phase==='read'&&progress.current>0&&progress.current<10000));
  const prepare=state.events.find(event=>event.direction==='request'&&event.kind==='Prepare').operation;
  await working();await capture('preparing',0);await fastClick('export-cancel');
  state=await canceled(prepare,'prepare');
  assert(state.events.find(event=>event.direction==='control'&&event.operation===prepare).progress.current>0);
  checks.push({stage:'prepare',operation:prepare,canceled:true});

  for(const lock of [false,true]) {
    await reviewed(1);await reset();await click('export-generate');
    state=await waitTrace(trace=>trace.events.some(event=>event.direction==='request'&&event.kind==='Generate')&&Object.values(trace.progress).some(progress=>progress.positiveWrite));
    const operation=state.events.find(event=>event.direction==='request'&&event.kind==='Generate').operation;
    await working();await capture(lock?'generating-before-lock':'generating-before-cancel',0);
    if(lock) {
      for(const type of ['keyDown','keyUp'])await rpc('Input.dispatchKeyEvent',{type,key:'L',code:'KeyL',windowsVirtualKeyCode:76,modifiers:type==='keyDown'?10:0});
    } else await fastClick('export-cancel');
    state=await canceled(operation,lock?'generate-lock':'generate');
    assert(state.events.find(event=>event.direction==='control'&&event.operation===operation).progress.positiveWrite);
    checks.push({stage:lock?'generate-lock':'generate',operation,canceled:true});
    if(lock) {
      assert(state.events.some(event=>event.direction==='request'&&event.kind==='Lock'));
      await until(state=>state.screen==='unlock'&&!state.busy);
      if((await snapshot()).hits['secret-key'])await text('secret-key',seed.key);
      await text('password','public-export-contract-password');await click('submit');
      await until(state=>state.screen==='open'&&!state.busy&&state.rows>0);
    }
  }
  await reviewed(0);await click('export-generate');await until(state=>state.hits['export-save']);await noDownload();
  await capture('recovered-ready');await click('export-save');await until(state=>state.hits['export-restart']);
  const filename=join(directory,'bitwarden-personal.json');
  for(let attempt=0;;attempt++){try{await readFile(filename);break;}catch{assert(attempt<100,'recovery download missing');await delay(80);}}
  const Importer=createRequire(import.meta.url)('../../../crates/confidex-app/tests/export_fixtures/bitwarden_json/reader.cjs').loadImporter(process.env.CONFIDEX_BITWARDEN_SOURCE);
  const parsed=await new Importer().parse(await readFile(filename,'utf8'));
  assert(parsed.success);assert.equal(parsed.errors.length,0);assert.equal(parsed.ciphers.length,10000);
  const seen=new Set();
  for(const item of parsed.ciphers) {
    const index=Number(item.name.replace(/^Public /,''));assert(Number.isInteger(index)&&index>=0&&index<10000&&!seen.has(index));seen.add(index);
    assert.equal(item.name,'Public '+index);assert.equal(item.login.username,'public-user-'+index);
    assert.equal(item.login.password,'PUBLIC-current-'+index);
    assert.deepEqual(Array.from(item.login.uris,uri=>uri.uri),['https://example.invalid/'+index]);
    assert.equal(item.notes,'Public note '+index);
  }
  await rename(filename,join(directory,'10000-recovered.json'));await capture('recovered-complete');
  const heartbeat=await evaluate('clearInterval(exportCancelTimer);exportCancelBeats');assert(heartbeat>100);
  return {width,locale,records:10000,checks,recoveryDownload:true,independentReader:true,heartbeat};
}
