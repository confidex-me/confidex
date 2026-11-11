import assert from 'node:assert/strict';
import {mkdir,writeFile} from 'node:fs/promises';
import {setTimeout as delay} from 'node:timers/promises';
import {runBrowser} from '../../../tools/browser-run.mjs';
import {assets} from './assets.mjs';

const [chrome,bundle,output='/tmp/confidex-select-shots']=process.argv.slice(2);
assert(chrome&&bundle,'Usage: select-check.mjs CHROME BUNDLE [SCREENSHOTS]');
const files=await assets(bundle);
await mkdir(output,{recursive:true});
const results=[];
for(const [width,height] of [[1180,650],[390,640]]) {
 results.push(await runBrowser(chrome,files,async({command,evaluate})=>{
  const rpc=async(method,params={})=>{const r=await command(method,params);assert(!r.error,JSON.stringify(r));return r.result;};
  const state=()=>evaluate('window.confidex?.snapshot()');
  const until=async pred=>{
    for(let i=0;i<600;i++){let s;try{s=await state();}catch{}if(s&&pred(s))return s;await delay(50);}
    throw Error('Select timeout: '+JSON.stringify(await state()));
  };
  const pointer=async(x,y)=>{for(const type of ['mousePressed','mouseReleased'])await rpc('Input.dispatchMouseEvent',{type,x,y,button:'left',clickCount:1});await delay(120);};
  const click=async id=>{
    for(let i=0;i<30;i++) {
      const s=await until(s=>s.hits[id]);const [x,y]=s.hits[id];
      const v=s.bounds['preferences-viewport'];
      if(!v||id==='settings'||(y>v[1]+2&&y<v[3]-2)){await pointer(x,y);return;}
      const point={x:v[2]+4,y:(v[1]+v[3])/2};
      await rpc('Input.dispatchMouseEvent',{type:'mouseMoved',...point});
      await rpc('Input.dispatchMouseEvent',{type:'mouseWheel',...point,deltaX:0,deltaY:y<v[1]?-150:150});await delay(120);
    }
    throw Error('Cannot scroll to '+id);
  };
  const options=(s,prefix)=>Object.entries(s.hits).filter(([key])=>new RegExp(`^${prefix}-[0-9]+$`).test(key));
  const aligned=(s,control,prefix)=>{
    const anchor=s.hits[control],items=options(s,prefix);assert(items.length,'no visible options');
    for(const [id,[x,y]] of items){
      assert(Math.abs(x-anchor[0])<24*s.zoom,`${id} opened beside ${control}: ${x} / ${anchor[0]}`);
      assert(x>=0&&x<=width&&y>=0&&y<=height,`${id} outside viewport`);
    }
    return items;
  };
  const open=async(control,prefix)=>{
    await click(control);await until(s=>options(s,prefix).length>0);await delay(250);
    return aligned(await state(),control,prefix);
  };
  const choose=async(control,prefix,id)=>{
    for(let i=0;i<40;i++){
      const s=await state(),items=aligned(s,control,prefix);
      if(s.hits[id]){await pointer(...s.hits[id]);return;}
      const point={x:items[0][1][0],y:items.reduce((sum,item)=>sum+item[1][1],0)/items.length};
      const before=s.hits[control];
      await rpc('Input.dispatchMouseEvent',{type:'mouseMoved',...point});
      await rpc('Input.dispatchMouseEvent',{type:'mouseWheel',...point,deltaX:0,deltaY:100});await delay(120);
      const after=(await state()).hits[control];
      assert(Math.abs(before[1]-after[1])<2,'menu scrolling moved the form');
    }
    throw Error('Could not select '+id);
  };
  const escape=async()=>{for(const type of ['keyDown','keyUp'])await rpc('Input.dispatchKeyEvent',{type,key:'Escape',code:'Escape',windowsVirtualKeyCode:27});await delay(150);};
  const shot=async name=>writeFile(`${output}/${width}-${name}.png`,Buffer.from((await rpc('Page.captureScreenshot',{format:'png'})).data,'base64'));
  await until(s=>s.screen==='catalog'&&!s.busy);
  await click('settings');
  await open('language','language');await shot('language');
  await escape();assert((await state()).bounds['preferences-window'],'Escape closed settings with the menu');
  await open('theme','theme');await choose('theme','theme','theme-1');await until(s=>s.theme===1);await delay(150);
  await open('language','language');await choose('language','language','language-7');await until(s=>s.locale==='fr');
  await open('scale','scale');await choose('scale','scale','scale-125');await until(s=>Math.abs(s.zoom-1.25)<0.01);await delay(250);
  await open('language','language');await shot('language-scaled');
  await escape();assert.equal((await state()).locale,'fr');
  return {width,height,anchored:true,selection:true,scrollContained:true,scale:1.25};
 },{viewport:[width,height]}));
}
console.log(JSON.stringify(results));
