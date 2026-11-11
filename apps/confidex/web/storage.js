let opened;
const keyWarnings = new WeakMap();
export function attachKeyFallback(worker) {
  worker.addEventListener('message', event => {
    if (event.data !== 'confidex-confirm-plaintext') return;
    event.stopImmediatePropagation();
    const port = event.ports[0];
    if (!port) return;
    const message = keyWarnings.get(worker);
    keyWarnings.delete(worker);
    port.postMessage(Boolean(message && window.confirm(message)));
    port.close();
  }, {capture: true});
}
export function setKeyStorageWarning(worker, message) {
  keyWarnings.set(worker, message);
}
export function confirmPlaintextKey() {
  if (typeof document !== 'undefined') return Promise.resolve(false);
  return new Promise(resolve => {
    const channel = new MessageChannel();
    channel.port1.onmessage = ({data}) => {
      channel.port1.close();
      resolve(data === true);
    };
    postMessage('confidex-confirm-plaintext', [channel.port2]);
  });
}
export async function syncFetch(url, method, contentType, body) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), method === 'HEAD' ? 3000 : 30000);
  try {
    const response = await fetch(url, {
      method, headers: contentType ? {'Content-Type':contentType} : {},
      body: method === 'GET' || method === 'HEAD' ? undefined : body,
      mode:'cors', credentials:'omit', redirect:'error', cache:'no-store',
      referrerPolicy:'no-referrer', signal:controller.signal,
    });
    const reader = response.body?.getReader(), chunks = [];
    let length = 0;
    if (reader) for (;;) {
      const {value, done} = await reader.read();
      if (done) break;
      length += value.length;
      if (length > 8000000) { await reader.cancel(); throw 'Limit'; }
      chunks.push(value);
    }
    const bytes = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk,offset); offset += chunk.length; }
    const limit = response.headers.get('Sync-Max-Body-Bytes');
    return {status:response.status, content_type:response.headers.get('Content-Type')??'',
      etag:response.headers.get('ETag'), cursor:response.headers.get('Sync-Cursor'),
      max_body:limit == null ? null : Number(limit), body:bytes};
  } finally { clearTimeout(timer); }
}
const MAX = 4065668;
const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
const bytes = (text, length) => {
  if (typeof text !== 'string' || text.length !== length * 2 || !/^[a-f0-9]+$/.test(text)) throw 'Invalid';
  return Array.from(text.match(/../g), b => Number.parseInt(b, 16));
};
const key = (value, size) => {
  if (!(Array.isArray(value) || value instanceof Uint8Array) || value.length !== size || !value.every(b => Number.isInteger(b) && b >= 0 && b <= 255)) throw 'Invalid';
  return hex(value);
};
function database() {
  return opened ??= new Promise((resolve, reject) => {
    const request = indexedDB.open('confidex', 5);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains('vaults')) db.createObjectStore('vaults', { keyPath: 'id' });
      if (!db.objectStoreNames.contains('heads')) db.createObjectStore('heads', { keyPath: ['vault', 'record', 'revision'] });
      else if (request.transaction.objectStore('heads').keyPath.length === 2) {
        const next = db.createObjectStore('branch-heads', {keyPath:['vault','record','revision']});
        const copy = request.transaction.objectStore('heads').openCursor();
        copy.onsuccess = () => {
          try {
            const cursor = copy.result;
            if (cursor) { next.add(cursor.value); cursor.continue(); }
            else { db.deleteObjectStore('heads'); next.name = 'heads'; }
          } catch { request.transaction.abort(); }
        };
      }
      if (!db.objectStoreNames.contains('objects')) db.createObjectStore('objects', { keyPath: ['vault', 'revision'] });
      if (!db.objectStoreNames.contains('sync-state')) db.createObjectStore('sync-state');
      if (!db.objectStoreNames.contains('record-tags')) {
        const tags = db.createObjectStore('record-tags', {keyPath:['vault','revision','tag']});
        tags.createIndex('lookup', ['vault','tag','record','revision']);
      }
    };
    request.onerror = () => { opened = undefined; reject(request.error?.name === 'VersionError' ? 'Version' : 'Storage'); };
    request.onblocked = () => reject('Storage');
    request.onsuccess = () => {
      request.result.onversionchange = () => { request.result.close(); opened = undefined; };
      resolve(request.result);
    };
  });
}
const asHead = row => row ? { record: bytes(row.record, 16), revision: bytes(row.revision, 32) } : null;
const asVault = row => {
  if (!row || typeof row.info?.name !== 'string' || row.info.name.length > 128 || row.lock?.length > 344) throw 'Invalid';
  return { info: { id: bytes(row.id, 16), name: row.info.name }, lock: row.lock };
};
export async function dbCall(operation, args) {
  const db = await database();
  const writing = ['create', 'rename', 'append', 'save-key', 'remove-key', 'save-device-unlock', 'set-unprotected-key', 'remove', 'clear-records', 'sync-commit', 'publish-branches', 'record-batch', 'restore'].includes(operation);
  return new Promise((resolve, reject) => {
    const tx = db.transaction(['vaults', 'heads', 'objects', 'sync-state', 'record-tags'], writing ? 'readwrite' : 'readonly');
    const vaults = tx.objectStore('vaults'), heads = tx.objectStore('heads'), objects = tx.objectStore('objects');
    let output = null, failure;
    tx.oncomplete = () => resolve(output);
    tx.onabort = () => reject(failure ?? (tx.error?.name === 'QuotaExceededError' ? 'Quota' : 'Storage'));
    tx.onerror = event => {
      if (event.target.error?.name === 'ConstraintError') failure = 'Conflict';
      if (event.target.error?.name === 'QuotaExceededError') failure = 'Quota';
    };
    const abort = reason => { failure = reason; tx.abort(); };
    const read = (request, callback) => {
      request.onsuccess = () => { try { callback(request.result); } catch (error) { abort(error?.name === 'QuotaExceededError' ? 'Quota' : typeof error === 'string' ? error : 'Storage'); } };
    };
    const addTags = (vault, record, revision, tags) => {
      if (!Array.isArray(tags) || tags.length > 256 || new Set(tags).size !== tags.length || tags.some(tag => typeof tag !== 'string' || new TextEncoder().encode(tag).length > 256)) throw 'Invalid';
      for (const tag of tags) tx.objectStore('record-tags').put({vault,record,revision,tag});
    };
    const oneHead = (vault, record, callback) => {
      read(heads.getAll(IDBKeyRange.bound([vault,record,''],[vault,record,'\uffff']),2), rows => {
        if (rows.length > 1) { abort('Conflict'); return; }
        callback(rows[0]);
      });
    };
    const run = () => { try {
      if (operation === 'remove' || operation === 'clear-records') {
        const vault = args[0], range = IDBKeyRange.bound([vault,''],[vault,'\uffff']);
        if (operation === 'clear-records') read(vaults.get(vault), row => { if (row) vaults.put({...row,removing:true}); });
        for (const name of ['record-tags','heads','objects']) {
          const request = tx.objectStore(name).openCursor(range);
          read(request, cursor => { if (cursor) { cursor.delete(); cursor.continue(); } });
        }
        tx.objectStore('sync-state').delete(vault);
        if (operation === 'remove') vaults.delete(vault);
      } else if (operation === 'rename') {
        const [vault, expected, name] = args;
        if (typeof name !== 'string' || !name || new TextEncoder().encode(name).length > 128 || typeof expected !== 'string' || new TextEncoder().encode(expected).length > 128) { abort('Invalid'); return; }
        read(vaults.get(vault), row => {
          if (!row) { abort('NotFound'); return; }
          if (row.removing) { abort('Removing'); return; }
          if (row.info.name !== expected) { abort('Conflict'); return; }
          vaults.put({...row,info:{...row.info,name}});
        });
      } else if (['load-key', 'save-key', 'remove-key', 'load-device-unlock', 'save-device-unlock', 'key-opt-out', 'set-unprotected-key'].includes(operation)) {
        const [vault, key, verifiedAt, expected] = args;
        const validText = value => typeof value === 'string' && value.length > 0 && value.length <= 128;
        const validEntry = value => value instanceof Uint8Array && value.length > 0 && value.length <= 16384;
        const validTimestamp = value => Number.isSafeInteger(value) && value > 0;
        read(vaults.get(vault), row => {
          if (operation === 'remove-key') {
            if (row) {
              delete row.rememberedKey;
              delete row.deviceUnlock;
              delete row.noPasskey;
              vaults.put(row);
            }
          } else if (!row) abort('NotFound');
          else if (row.removing) abort('Removing');
          else if (operation === 'key-opt-out') output = row.noPasskey === true;
          else if (operation === 'set-unprotected-key') {
            if (key !== null && !validText(key)) { abort('Invalid'); return; }
            delete row.deviceUnlock;
            delete row.rememberedKey;
            row.noPasskey = true;
            if (key !== null) row.rememberedKey = key;
            vaults.put(row);
          } else if (operation === 'save-device-unlock') {
            if (!validEntry(key) || !validTimestamp(verifiedAt)) { abort('Invalid'); return; }
            if (expected !== null) {
              const current = row.deviceUnlock?.entry;
              if (!validEntry(expected) || !validEntry(current) || expected.length !== current.length
                  || !expected.every((byte, index) => byte === current[index])) { abort('Conflict'); return; }
            }
            delete row.rememberedKey;
            delete row.noPasskey;
            row.deviceUnlock = {entry:key, verifiedAt};
            vaults.put(row);
          } else if (operation === 'load-device-unlock') {
            const saved = row.deviceUnlock;
            if (validEntry(saved?.entry) && validTimestamp(saved.verifiedAt)) output = saved;
          } else if (operation === 'save-key') {
            if (!validText(key) && !validEntry(key)) { abort('Invalid'); return; }
            vaults.put({...row, rememberedKey:key});
          } else {
            const saved = row.rememberedKey;
            output = validText(saved) || validEntry(saved) ? saved : null;
          }
        });
      } else if (operation === 'snapshot') {
        const vault = args[0], result = {vault:null,objects:[],heads:[]};
        let size = 0;
        read(vaults.get(vault), row => {
          if (!row) { abort('NotFound'); return; }
          if (row.removing) { abort('Removing'); return; }
          result.vault = asVault(row);
        });
        const range = IDBKeyRange.bound([vault,''],[vault,'\uffff']);
        const request = objects.openCursor(range);
        read(request, cursor => {
          if (!cursor) return;
          const row = cursor.value;
          size += row.wire.length;
          if (!row.wire.length || row.wire.length > MAX || size > 48*1024*1024 || result.objects.length === 10000) { abort('Limit'); return; }
          result.objects.push({head:{record:bytes(row.record,16),revision:bytes(row.revision,32)},wire:row.wire,tags:[]});
          cursor.continue();
        });
        const headRequest = heads.openCursor(range);
        read(headRequest, cursor => {
          if (!cursor) return;
          if (result.heads.length === 10000) { abort('Limit'); return; }
          result.heads.push(asHead(cursor.value)); cursor.continue();
        });
        output = result;
      } else if (operation === 'record-batch') {
        const [vault, commit] = args;
        if (!Array.isArray(commit?.previous) || !Array.isArray(commit?.objects) || !Array.isArray(commit?.heads)) { abort('Invalid'); return; }
        if (commit.previous.length > 100000 || commit.objects.length > 10000 || commit.heads.length > 10000) { abort('Limit'); return; }
        if (commit.objects.length !== commit.heads.length) { abort('Invalid'); return; }
        const base = new Set(), records = new Set(), objectsByRevision = new Map(), changed = new Set(), targets = new Set();
        let last = '', size = 0;
        for (const head of commit.previous) {
          const record = key(head?.record, 16), revision = key(head?.revision, 32);
          const id = record + revision;
          if (id <= last) { abort('Invalid'); return; }
          base.add(id); records.add(record); last = id;
        }
        const encoder = new TextEncoder();
        const less = (a, b) => {
          for (let i=0;i<Math.min(a.length,b.length);i++) if (a[i] !== b[i]) return a[i] < b[i];
          return a.length < b.length;
        };
        for (const object of commit.objects) {
          const record = key(object?.head?.record, 16), revision = key(object?.head?.revision, 32);
          if (!Array.isArray(object.tags) || object.tags.length > 256) { abort('Limit'); return; }
          let previousTag;
          for (const tag of object.tags) {
            if (typeof tag !== 'string') { abort('Limit'); return; }
            const encoded = encoder.encode(tag);
            if (encoded.length > 256 || (previousTag && !less(previousTag,encoded))) { abort('Limit'); return; }
            previousTag = encoded;
          }
          if (!(object.wire instanceof Uint8Array)) { abort('Invalid'); return; }
          size += object.wire.length;
          if (!object.wire.length || object.wire.length > MAX || size > 32*1024*1024) { abort('Limit'); return; }
          if (objectsByRevision.has(revision)) { abort('Invalid'); return; }
          objectsByRevision.set(revision, record);
        }
        for (const change of commit.heads) {
          const record = key(change?.head?.record, 16), revision = key(change?.head?.revision, 32);
          const expected = change.expected == null ? null : key(change.expected, 32);
          const source = `${record}:${expected}`, target = record + revision;
          if (changed.has(source) || targets.has(target) || (expected == null ? records.has(record) : !base.has(record + expected)) || objectsByRevision.get(revision) !== record) { abort('Invalid'); return; }
          changed.add(source); targets.add(target);
        }
        read(vaults.get(vault), row => {
          if (!row) { abort('NotFound'); return; }
          if (row.removing) { abort('Removing'); return; }
          const range = IDBKeyRange.bound([vault,''], [vault,'\uffff']);
          read(heads.getAll(range, 100001), current => {
            if (current.length > 100000) { abort('Limit'); return; }
            if (current.length !== base.size || current.some(head => !base.has(head.record + head.revision))) { abort('Conflict'); return; }
            for (const object of commit.objects) {
              const record = hex(object.head.record), revision = hex(object.head.revision), wire = object.wire;
              read(objects.get([vault,revision]), stored => {
                if (stored) {
                  if (stored.record !== record || stored.wire.length !== wire.length || !wire.every((b,i) => stored.wire[i] === b)) { abort('Conflict'); return; }
                } else objects.add({vault,record,revision,wire});
                addTags(vault,record,revision,object.tags);
              });
            }
            for (const change of commit.heads) {
              const record = hex(change.head.record);
              if (change.expected != null) heads.delete([vault,record,hex(change.expected)]);
              heads.put({vault,record,revision:hex(change.head.revision)});
            }
          });
        });
      } else if (operation === 'restore') {
        const snapshot = args[0], vault = hex(snapshot.vault.info.id);
        if (snapshot.objects.length > 10000 || snapshot.heads.length > 10000 || snapshot.objects.reduce((n,o)=>n+o.wire.length,0) > 48*1024*1024) { abort('Limit'); return; }
        read(vaults.get(vault), exists => {
          if (exists) { abort('Conflict'); return; }
          vaults.add({id:vault,info:snapshot.vault.info,lock:snapshot.vault.lock});
          for (const object of snapshot.objects) {
            const record = hex(object.head.record), revision = hex(object.head.revision);
            if (!object.wire.length || object.wire.length > MAX) { abort('Limit'); return; }
            objects.add({vault,record,revision,wire:Uint8Array.from(object.wire)});
            addTags(vault,record,revision,object.tags);
          }
          for (const head of snapshot.heads) heads.add({vault,record:hex(head.record),revision:hex(head.revision)});
        });
      } else if (operation === 'sync-state') {
        read(tx.objectStore('sync-state').get(args[0]), row => {
          if (row?.length > 8000000) { abort('Limit'); return; }
          output = row ?? null;
        });
      } else if (operation === 'sync-commit' || operation === 'publish-branches') {
        const [vault, commit] = args;
        const branched = operation === 'publish-branches';
        if (branched) {
          const binary = value => (Array.isArray(value) || value instanceof Uint8Array) && value.every(b => Number.isInteger(b) && b >= 0 && b <= 255);
          if (!binary(commit?.current) || (commit.previous != null && !binary(commit.previous)) || !Array.isArray(commit.objects) || !Array.isArray(commit.heads)) { abort('Invalid'); return; }
          if (commit.previous?.length > 8000000) { abort('Limit'); return; }
          if (commit.objects.some(o => !binary(o.wire))) { abort('Invalid'); return; }
        }
        if (commit.current.length > 8000000 || commit.objects.length > 256 || commit.heads.length > 256 || commit.objects.reduce((n, o) => n + o.wire.length, 0) > 8000000) { abort('Limit'); return; }
        if (!branched && new Set(commit.heads.map(c => key(c?.head?.record,16))).size !== commit.heads.length) { abort('Invalid'); return; }
        const equal = (a, b) => a == null || b == null ? a == null && b == null : a.length === b.length && a.every((value, i) => value === b[i]);
        read(vaults.get(vault), exists => {
          if (!exists) { abort('NotFound'); return; }
          if (exists.removing) { abort('Removing'); return; }
          read(tx.objectStore('sync-state').get(vault), previous => {
            if (!equal(previous, commit.previous)) { abort('Conflict'); return; }
            for (const object of commit.objects) {
              const record = branched ? key(object?.head?.record,16) : hex(object.head.record);
              const revision = branched ? key(object?.head?.revision,32) : hex(object.head.revision);
              const wire = Uint8Array.from(object.wire);
              if (!wire.length || wire.length > MAX) { abort('Limit'); return; }
              read(objects.get([vault, revision]), stored => {
                if (stored) { if (stored.record !== record || !equal(stored.wire, wire)) { abort('Conflict'); return; } }
                else objects.add({vault, record, revision, wire});
                addTags(vault,record,revision,object.tags);
              });
            }
            if (branched) {
              const actions = new Set(), consumed = new Set();
              const changes = commit.heads.map(change => {
                const record = key(change?.head?.record,16), revision = key(change?.head?.revision,32);
                const expected = change.expected == null ? null : key(change.expected,32);
                const action = `${record}:${revision}:${expected}`, old = `${record}:${expected}`;
                if (actions.has(action) || (expected != null && consumed.has(old))) throw 'Invalid';
                actions.add(action); if (expected != null) consumed.add(old);
                return {record,revision,expected};
              });
              let pending = changes.length;
              for (const change of changes) {
                read(heads.get([vault,change.record,change.expected ?? change.revision]), current => {
                  if (change.expected != null && !current) { abort('Conflict'); return; }
                  read(objects.get([vault,change.revision]), object => {
                    if (!object || object.record !== change.record) { abort('NotFound'); return; }
                    if (--pending !== 0) return;
                    for (const c of changes) if (c.expected != null) heads.delete([vault,c.record,c.expected]);
                    for (const c of changes) heads.put({vault,record:c.record,revision:c.revision});
                  });
                });
              }
            } else for (const change of commit.heads) {
              const record = hex(change.head.record), revision = hex(change.head.revision);
              oneHead(vault, record, current => {
                if ((current?.revision ?? null) !== (change.expected == null ? null : hex(change.expected))) { abort('Conflict'); return; }
                read(objects.get([vault, revision]), object => {
                  if (!object || object.record !== record) { abort('NotFound'); return; }
                  if (current) heads.delete([vault,record,current.revision]);
                  heads.put({vault, record, revision});
                });
              });
            }
            tx.objectStore('sync-state').put(commit.current, vault);
          });
        });
      } else if (operation === 'vaults') {
        const rows = [];
        const request = vaults.openCursor();
        read(request, cursor => {
          if (!cursor) { output = rows; return; }
          rows.push(asVault(cursor.value).info);
          if (rows.length > 128) { abort('Limit'); return; }
          cursor.continue();
        });
      } else if (operation === 'vault') {
        read(vaults.get(args[0]), row => { if (!row) abort('NotFound'); else if (row.removing) abort('Removing'); else output = asVault(row); });
      } else if (operation === 'create') {
        const row = args[0];
        if (row.lock.length > 344 || !row.info.name || new TextEncoder().encode(row.info.name).length > 128) { abort('Invalid'); return; }
        vaults.add({ id: hex(row.info.id), info: row.info, lock: row.lock });
      } else if (operation === 'branch-heads') {
        const [vault, after, tag] = args;
        if (tag != null && (typeof tag !== 'string' || new TextEncoder().encode(tag).length > 256)) { abort('Limit'); return; }
        const record = after == null ? '' : key(after.record,16), revision = after == null ? '' : key(after.revision,32);
        const low = tag == null ? [vault,record,revision] : [vault,tag,record,revision];
        const high = tag == null ? [vault,'\uffff'] : [vault,tag,'\uffff','\uffff'];
        const source = tag == null ? heads : tx.objectStore('record-tags').index('lookup');
        const request = source.openCursor(IDBKeyRange.bound(low,high,after != null));
        const rows = [];
        read(request, cursor => {
          if (!cursor || rows.length === 128) { output = rows; return; }
          if (tag == null) { rows.push(asHead(cursor.value)); cursor.continue(); }
          else {
            const row = cursor.value;
            read(heads.get([vault,row.record,row.revision]), head => {
              if (head) rows.push(asHead(head));
              cursor.continue();
            });
          }
        });
      } else if (operation === 'heads') {
        const [vault, after] = args;
        const range = IDBKeyRange.bound(after == null ? [vault,''] : [vault,after,'\uffff'], [vault, '\uffff'], after != null);
        const rows = [], request = heads.openCursor(range);
        read(request, cursor => {
          if (!cursor || rows.length === 128) { output = rows; return; }
          rows.push(asHead(cursor.value)); cursor.continue();
        });
      } else if (operation === 'tagged-heads') {
        const [vault, tag, after] = args;
        if (typeof tag !== 'string' || new TextEncoder().encode(tag).length > 256) { abort('Limit'); return; }
        const low = after == null ? [vault,tag,'',''] : [vault,tag,after,'\uffff'];
        const range = IDBKeyRange.bound(low,[vault,tag,'\uffff','\uffff'],after != null);
        const rows = [], request = tx.objectStore('record-tags').index('lookup').openCursor(range);
        read(request, cursor => {
          if (!cursor || rows.length === 128) { output = rows; return; }
          const row = cursor.value;
          read(heads.get([vault,row.record,row.revision]), head => {
            if (head?.revision === row.revision) rows.push(asHead(head));
            cursor.continue();
          });
        });
      } else if (operation === 'head') {
        oneHead(args[0], args[1], row => { output = asHead(row); });
      } else if (operation === 'object') {
        read(objects.get([args[0], args[1]]), row => {
          if (!row) { abort('NotFound'); return; }
          if (!(row.wire instanceof Uint8Array) || row.wire.length > MAX) { abort('Limit'); return; }
          output = row.wire;
        });
      } else if (operation === 'append') {
        const [vault, record, revision, expected, wire, tags] = args;
        if (!wire.length || wire.length > MAX) { abort('Limit'); return; }
        read(vaults.get(vault), exists => {
          if (!exists) { abort('NotFound'); return; }
          if (exists.removing) { abort('Removing'); return; }
          oneHead(vault, record, current => {
            if (current?.revision === revision) {
              read(objects.get([vault, revision]), previous => {
                if (!previous || previous.record !== record || previous.wire.length !== wire.length || !wire.every((b, i) => b === previous.wire[i])) abort('Conflict');
              });
            } else if ((current?.revision ?? null) !== expected) abort('Conflict');
            else {
              objects.add({ vault, record, revision, wire });
              addTags(vault,record,revision,tags);
              if (current) heads.delete([vault,record,current.revision]);
              heads.put({ vault, record, revision });
            }
          });
        });
      } else abort('Invalid');
    } catch (error) { abort(error?.name === 'QuotaExceededError' ? 'Quota' : typeof error === 'string' ? error : 'Storage'); } };
    if (['heads','head','tagged-heads','append','sync-commit'].includes(operation)) {
      const request = heads.openCursor(IDBKeyRange.bound([args[0],''],[args[0],'\uffff']));
      let previous;
      read(request, cursor => {
        if (!cursor) { run(); return; }
        if (cursor.value.record === previous) { abort('Conflict'); return; }
        previous = cursor.value.record; cursor.continue();
      });
    } else run();
  });
}
export function requestPersistence() {
  navigator.storage?.persist?.().catch(() => {});
}
export function offlineShell() { return globalThis.confidexOfflineShell ?? 0; }
