import assert from 'node:assert/strict';
import {mkdir, writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
import {runBrowser} from '../../../tools/browser-run.mjs';
import {assets} from './assets.mjs';

const [chrome,bundle,shots] = process.argv.slice(2);
assert(chrome && bundle, 'provide Chrome and WASM bundle paths');
if(shots) await mkdir(shots,{recursive:true});
const files=await assets(bundle);
const results=[];
for(const viewport of [[1320,900],[390,900]]) {
  results.push(await runBrowser(chrome,files,async({command,evaluate})=>{
    const rpc=async(method,params={})=>{
      const r=await command(method,params);assert(!r.error,JSON.stringify(r));return r.result;
    };
    const snapshot=()=>evaluate('window.confidex?.snapshot()');
    const until=async predicate=>{
      const deadline=Date.now()+60_000;
      for(;;){let s;try{s=await snapshot();}catch{}if(s&&predicate(s))return s;
        assert(Date.now()<deadline,`UI timed out: ${JSON.stringify(s)}`);await delay(30);}
    };
    const capture=async name=>{
      if(!shots)return;
      const r=await rpc('Page.captureScreenshot',{format:'png'});
      await writeFile(join(shots,`${viewport[0]}-${name}.png`),Buffer.from(r.data,'base64'));
    };
    const click=async id=>{
      let s=await until(s=>s.hits[id]);
      const [x,y]=s.hits[id];
      await rpc('Input.dispatchMouseEvent',{type:'mouseMoved',x,y});await delay(80);
      s=await until(s=>s.hits[id]);
      const [px,py]=s.hits[id];
      assert(px>=0&&px<=viewport[0]&&py>=0&&py<=viewport[1],`outside viewport: ${id}`);
      for(const type of ['mousePressed','mouseReleased'])await rpc('Input.dispatchMouseEvent',{type,x:px,y:py,button:'left',clickCount:1});
      await delay(60);
    };
    const text=async(id,value)=>{
      await click(id);
      for(const type of ['rawKeyDown','keyUp'])await rpc('Input.dispatchKeyEvent',{type,key:'a',code:'KeyA',windowsVirtualKeyCode:65,modifiers:4});
      await rpc('Input.dispatchKeyEvent',{type:'keyUp',key:'Meta',code:'MetaLeft',modifiers:0});
      await rpc('Input.insertText',{text:value});await delay(60);
    };
    const connect=()=>evaluate(`(async()=>{
      const worker=new Worker('/worker.js',{type:'module'});
      await new Promise((resolve,reject)=>{worker.onmessage=e=>{if(e.data==='ready')resolve();};worker.onerror=()=>reject(Error('fixture worker'));});
      window.backend=command=>new Promise((resolve,reject)=>{
        worker.onmessage=({data})=>{
          if(!(data instanceof Uint8Array)||!data.length){reject(Error('empty reply'));return;}
          const r=JSON.parse(new TextDecoder().decode(data));data.fill(0);
          if('Err'in r.result)reject(Error(JSON.stringify(r.result.Err)));else resolve(r.result.Ok);
        };
        const bytes=new TextEncoder().encode(JSON.stringify({generation:1,command}));worker.postMessage(bytes,[bytes.buffer]);
      });
      window.searchAll=async(query,after=null,tag=null,refresh=false)=>{
        for(let steps=0;steps<100;steps++){
          const r=await backend({Search:{query,after,tag,refresh}});refresh=false;
          if(r==='Indexing')continue;
          if(!r.Rows)throw Error('invalid search output');return {...r.Rows,steps};
        }throw Error('index did not finish');
      };
    })()`);
    await until(s=>s.screen==='catalog'&&!s.busy);
    await connect();
    const {transferCode,...proof}=await evaluate(`(async()=>{
      const {Created:created}=await backend({Create:{name:'Search fixture',password:'public-search-fixture',remember:false}});
      window.fixtureVault=created.info.id;
      for(let i=0;i<150;i++){
        await backend({Save:{epoch:1,draft:{record:Array(16).fill(i+1),revision:null,title:'Public account '+i,tags:['work'],fields:[
          {source:null,name:'Login',type_name:'login/v1',values:{url:'https://code.example.test/project'+String(i).padStart(4,'0'),password:'passwordonlymarker'},opaque:0,protected:false},
          {source:null,name:'Note',type_name:'note/v1',values:{text:i===149?'noteonlytail':'ordinary public note'},opaque:0,protected:false},
          {source:null,name:'Protected note',type_name:'secure-note/v1',values:{text:'protectedonlymarker'},opaque:0,protected:false}
        ]}}});
      }
      const tail=await searchAll('NOTEONLYTA');
      if(tail.rows.length!==1||tail.rows[0].head.record[0]!==150||tail.steps<1)throw Error('search missed unloaded record');
      for(const q of ['passwordonlymarker','protectedonlymarker','missingmarker','---'])if((await searchAll(q)).rows.length)throw Error('unexpected hit: '+q);
      const first=await searchAll('public');const last=await searchAll('public',first.next);
      if(first.rows.length!==128||!first.more||last.rows.length!==22||last.more)throw Error('search pagination');
      if((await searchAll('project0149')).rows.length!==1)throw Error('URL search');
      let invalid=false;try{await searchAll('x'.repeat(4097));}catch(e){invalid=String(e).includes('Input');}
      if(!invalid||(await searchAll('project0149')).steps!==0)throw Error('invalid query discarded the index');
      if((await searchAll('',null,'missing')).rows.length)throw Error('tag filter');
      const {Draft:draft}=await backend({Open:{record:Array(16).fill(150)}});
      draft.fields.find(f=>f.type_name==='note/v1').protected=true;await backend({Save:{draft,epoch:2}});
      const protectedResult=await searchAll('noteonlytail');
      if(protectedResult.rows.length||protectedResult.steps!==0)throw Error('protected transition rebuilt or retained the note');
      const {Draft:restored}=await backend({Open:{record:Array(16).fill(150)}});
      const note=restored.fields.find(f=>f.values.text==='noteonlytail');note.type_name='note/v1';note.protected=false;await backend({Save:{draft:restored,epoch:3}});
      if((await searchAll('noteonlytail')).rows.length!==1)throw Error('unprotect transition');
      await backend('Lock');
      let locked=false;try{await searchAll('noteonlytail');}catch(e){locked=String(e).includes('Locked');}
      if(!locked)throw Error('search while locked');
      return {transferCode:created.key,records:150,steps:tail.steps,fullPagination:true,privateValuesExcluded:true,protectionUpdated:true,locked:true};
    })()`);
    await rpc('Page.reload');
    await until(s=>s.screen==='catalog'&&!s.busy&&s.vaults===1);
    await click('vault-0');
    await until(s=>s.screen==='unlock'&&!s.busy);
    await text('secret-key',transferCode);
    await text('password','public-search-fixture');await click('submit');
    await until(s=>s.screen==='open'&&!s.busy&&s.rows===128);
    await text('search','noteonlyta');
    await until(s=>!s.busy&&s.rows===1);
    await capture('note-result');
    await text('search','project0149');
    await until(s=>!s.busy&&s.rows===1);
    await capture('url-result');
    await text('search','protectedonlymarker');
    await until(s=>!s.busy&&s.rows===0);
    await capture('protected-excluded');
    await text('search','#work');
    await until(s=>!s.busy&&s.rows===128);
    await text('search','noteonlyta');
    await until(s=>!s.busy&&s.rows===1);
    await rpc('Input.dispatchKeyEvent',{type:'keyDown',key:'L',code:'KeyL',windowsVirtualKeyCode:76,modifiers:10});
    await rpc('Input.dispatchKeyEvent',{type:'keyUp',key:'L',code:'KeyL',windowsVirtualKeyCode:76,modifiers:0});
    await until(s=>s.screen==='unlock'&&!s.busy&&s.rows===0);
    await capture('locked');
    return {viewport,...proof,uiSearch:true,uiTagFilter:true,uiLock:true};
  },{viewport}));
}
console.log(JSON.stringify(results,null,2));
