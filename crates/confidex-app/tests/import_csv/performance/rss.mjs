import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';

export function treeRss(text, root) {
  const rows = text.trim().split('\n').map(line=>line.trim().split(/\s+/).map(Number));
  assert(rows.every(row=>row.length===3 && row.every(Number.isFinite)));
  const members = new Set([root]);
  for(let changed=true;changed;) {
    changed=false;
    for(const [pid,parent] of rows) {
      if(members.has(parent)&&!members.has(pid)) {members.add(pid);changed=true;}
    }
  }
  const selected=rows.filter(([pid])=>members.has(pid));
  assert(selected.some(([pid])=>pid===root),'Chrome root process is missing');
  return {bytes:selected.reduce((sum,[,,rss])=>sum+rss*1024,0),processes:selected.length};
}

assert.deepEqual(treeRss('3 2 30\n9 1 90\n1 0 10\n2 1 20',2),{bytes:50*1024,processes:2});

export function sampleRss(pid) {
  assert(Number.isInteger(pid)&&pid>0);
  assert(process.platform!=='win32','RSS sampling requires a POSIX ps command');
  let baseline,peak=0,processes=0,samples=0,failure;
  function sample() {
    try {
      const result=treeRss(execFileSync('/bin/ps',['-axo','pid=,ppid=,rss='],{
        encoding:'utf8',timeout:5000,maxBuffer:2*1024*1024,
      }),pid);
      baseline??=result.bytes;
      peak=Math.max(peak,result.bytes);
      processes=Math.max(processes,result.processes);
      samples++;
    } catch(error) {failure??=error;}
  }
  sample();
  if(failure)throw failure;
  const timer=setInterval(sample,100);
  return {
    stop(){clearInterval(timer);},
    result(){
      sample();
      if(failure)throw failure;
      assert(samples>1&&peak>0);
      return {baselineBytes:baseline,peakBytes:peak,maxProcesses:processes,samples,intervalMs:100};
    },
  };
}
